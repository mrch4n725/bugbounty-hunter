import threading
import queue
import socket
import time
import hashlib
import re
from urllib.parse import urljoin, urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor
from bs4 import BeautifulSoup

from modules.utils import make_session, safe_get, same_domain, log, Colors, url_in_scope, finding


JS_SECRET_PATTERNS = {
    "AWS Access Key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "Generic API Key": re.compile(r'["\']([a-zA-Z0-9_\-]{32,45})["\']'),
    "Bearer Token": re.compile(r"(?i)bearer\s+([a-zA-Z0-9\-_.]{20,})"),
    "Internal Endpoint": re.compile(r'["\']/(?:internal|admin|debug|private)/[^"\']{3,}["\']'),
    "nr-data Endpoint": re.compile(r"https?://[a-z0-9\-]+\.nr-data\.net[^\s\"']*"),
    "Hardcoded Password": re.compile(r"(?i)password\s*[:=]\s*[\"']([^\"']{8,})[\"']"),
    "Private IP": re.compile(r"(?:10\.|172\.1[6-9]\.|172\.2[0-9]\.|192\.168\.)\d+\.\d+"),
}


class Recon:
    """
    Reconnaissance module for discovering URLs, subdomains, forms, and parameters.
    Performs multithreaded web crawling, subdomain enumeration, and form discovery.
    """
    
    EXCLUDED_EXTENSIONS = (
        ".jpg", ".jpeg", ".png", ".gif", ".svg", ".webp", ".ico",
        ".css", ".js", ".woff", ".woff2", ".ttf", ".eot", ".mp4",
        ".mp3", ".pdf", ".zip", ".gz", ".tar", ".rar",
    )

    COMMON_SUBDOMAINS = [
        'www', 'mail', 'ftp', 'dev', 'staging', 'test', 'api', 'admin',
        'beta', 'blog', 'shop', 'git', 'jenkins', 'vpn', 'remote', 'internal',
        'secure', 'server', 'host', 'cloud', 'cdn', 'web', 'app', 'service',
        'email', 'smtp', 'pop', 'ns', 'mx', 'dns', 'db', 'database'
    ]
    
    def __init__(self, config):
        """
        Initialize the Recon module.
        """
        self.config = config
        self.target = config.get('target')
        self.threads = config.get('threads', 5)
        self.timeout = config.get('timeout', 10)
        self.verbose = config.get('verbose', False)
        self.crawl_depth = config.get('crawl_depth', 2)
        self.request_delay = config.get('delay', 0.0)
        self.max_urls = config.get('max_urls', 250)
        
        self.session = make_session(config)
        self.urls = set()
        self.js_urls = set()
        self.forms = []
        self.params = set()
        self.subdomains = set()
        self.is_spa = False
        self.spa_shell_size = 0
        self.spa_shell_hash = ""
        self.authenticated = False
        
        parsed = urlparse(self.target if '://' in self.target else f'https://{self.target}')
        self.base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        # Thread-safe locks
        self.urls_lock = threading.Lock()
        self.forms_lock = threading.Lock()
        self.params_lock = threading.Lock()
        self.js_urls_lock = threading.Lock()
        self.subdomains_lock = threading.Lock()
        self.crawl_lock = threading.Lock()  # Shared lock for visited and depth data
        self._fingerprint_shell()
        self._validate_auth()
        
    def run(self):
        """
        Execute the reconnaissance process.
        """
        log(f"Starting reconnaissance on {self.target}", Colors.CYAN, self.verbose)
        
        # Start with subdomain enumeration and discover additional endpoints
        self._enumerate_subdomains()
        self._discover_robots()
        self._discover_sitemap()
        
        # Crawl the target
        self._crawl()
        
        return {
            'urls': sorted(list(self.urls)),
            'forms': self.forms,
            'params': sorted(list(self.params)),
            'subdomains': sorted(list(self.subdomains)),
            'js_urls': sorted(list(self.js_urls)),
            'authenticated': self.authenticated,
        }

    def _fingerprint_shell(self):
        """Identify SPA shells so the crawler can ignore route fallback pages."""
        try:
            r = self.session.get(self.target, timeout=self.timeout)
        except Exception:
            return
        content = r.text.lower()
        spa_signals = [
            '<div id="root"', '<div id="app"', 'bundle.js',
            'chunk.js', '__next', 'ng-version', 'react', 'vue.js',
            'ember', 'backbone', '__webpack'
        ]
        score = sum(1 for signal in spa_signals if signal in content)
        if score >= 2:
            self.is_spa = True
            self.spa_shell_size = len(r.text)
            self.spa_shell_hash = hashlib.md5(r.text.encode()).hexdigest()

    def _is_real_page(self, response):
        """Return False for identical or near-identical SPA shell responses."""
        if not self.is_spa:
            return True
        size_diff = abs(len(response.text) - self.spa_shell_size)
        content_hash = hashlib.md5(response.text.encode()).hexdigest()
        if content_hash == self.spa_shell_hash:
            return False
        if size_diff < 512:
            return False
        return True

    def _validate_auth(self):
        """Best-effort check that supplied cookies or Authorization still work."""
        if not self.session.cookies and not self.session.headers.get("Authorization"):
            self.authenticated = False
            return
        probe_paths = ["/api/v1/user", "/api/v1/me", "/graphql", "/api/graphql"]
        for path in probe_paths:
            try:
                r = self.session.get(urljoin(self.base_url, path), timeout=self.timeout)
                if r.status_code in (200, 403) and r.status_code != 401:
                    self.authenticated = True
                    return
            except Exception:
                continue
        self.authenticated = False
        print("[!] WARNING: Session appears unauthenticated or expired.")

    def _add_discovered_url(self, url, response=None):
        """Add a crawled page only after SPA-shell filtering has accepted it."""
        if self.max_urls and len(self.urls) >= self.max_urls:
            return False
        if urlparse(url).path.lower().endswith(".js"):
            with self.js_urls_lock:
                self.js_urls.add(url)
            return False
        if response is None:
            response = safe_get(self.session, url, self.timeout, raise_for_status=False)
        if response is None or not self._is_real_page(response):
            return False
        self.urls.add(url)
        return True

    def _extract_scripts(self, url, soup):
        """Collect linked JavaScript bundles for passive endpoint/secret mining."""
        for script in soup.find_all("script", src=True):
            js_url = urljoin(url, script["src"]).split("#")[0]
            if url_in_scope(js_url, self.config) and same_domain(self.base_url, js_url):
                with self.js_urls_lock:
                    self.js_urls.add(js_url)
    
    def _crawl(self):
        """
        Perform multithreaded crawling to discover URLs.
        Respects max_depth and only follows same-domain links.
        """
        visited = set()
        to_visit = queue.Queue()
        depth_map = {}
        
        start_url = self.target
        to_visit.put(start_url)
        depth_map[start_url] = 0
        visited.add(start_url)
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {}
            
            while True:
                # 1. Feed the pool up to capacity limits
                while len(futures) < self.threads:
                    try:
                        url = to_visit.get_nowait()
                    except queue.Empty:
                        break
                    
                    with self.crawl_lock:
                        current_depth = depth_map.get(url, 0)
                    
                    if current_depth <= self.crawl_depth:
                        future = executor.submit(
                            self._process_url,
                            url,
                            current_depth,
                            to_visit,
                            depth_map,
                            visited
                        )
                        futures[future] = url
                
                # 2. Break out entirely if there's no work queued and no background tasks running
                if not futures and to_visit.empty():
                    break
                
                # 3. Clean up any completed futures dynamically
                completed_futures = [f for f in futures.keys() if f.done()]
                for future in completed_futures:
                    futures.pop(future, None)
                    try:
                        future.result()
                    except Exception as e:
                        if self.verbose:
                            log(f"Task error: {str(e)}", Colors.RED, self.verbose)
                
                # 4. If nothing finished this loop and we are waiting on IO, yield execution cleanly
                if not completed_futures and futures:
                    # ---> LIVE TRACKING DEBUG LOGS <---
                    if self.verbose:
                        print(f"[DEBUG] Active Workers: {len(futures)} | Remaining Queue: {to_visit.qsize()} | Discovered URLs: {len(self.urls)}")
                    time.sleep(0.02)
                        
    def _process_url(self, url, depth, to_visit, depth_map, visited):
        try:
            response = safe_get(self.session, url, self.timeout)
            if response is None:
                return
            
            with self.urls_lock:
                if self.max_urls and len(self.urls) >= self.max_urls:
                    return
                self._add_discovered_url(url, response)
            
            if self.request_delay:
                time.sleep(self.request_delay)
            
            # Extract parameters from URL query strings
            parsed = urlparse(url)
            if parsed.query:
                params = parse_qs(parsed.query)
                with self.params_lock:
                    for param_name in params.keys():
                        self.params.add(param_name)
            
            try:
                soup = BeautifulSoup(response.text, 'html.parser')
            except Exception as e:
                if self.verbose:
                    log(f"Failed to parse {url}: {str(e)}", Colors.RED, self.verbose)
                return
            
            self._extract_forms(url, soup)
            self._extract_scripts(url, soup)
            
            # Extract links if we haven't reached max crawling depth boundaries
            if depth < self.crawl_depth:
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    candidate = urljoin(url, href)
                    normalized = candidate.split('#')[0].rstrip('/')
                    if not normalized:
                        continue
                    if urlparse(normalized).path.lower().endswith(".js"):
                        with self.js_urls_lock:
                            self.js_urls.add(normalized)
                        continue
                    if self._should_skip_link(normalized):
                        continue
                    if not url_in_scope(normalized, self.config):
                        continue
                    if same_domain(self.base_url, normalized):
                        with self.crawl_lock:
                            if normalized not in visited and len(self.urls) < self.max_urls:
                                visited.add(normalized)
                                depth_map[normalized] = depth + 1
                                to_visit.put(normalized)
        
        except Exception as e:
            if self.verbose:
                log(f"Error processing {url}: {str(e)}", Colors.RED, self.verbose)
    
    def _extract_forms(self, url, soup):
        """
        Extract forms and their fields from HTML.
        """
        forms = soup.find_all('form')
        
        for form in forms:
            form_data = {
                'url': url,
                'action': urljoin(url, form.get('action', '')),
                'method': form.get('method', 'GET').upper(),
                'fields': []
            }
            
            inputs = form.find_all(['input', 'select', 'textarea'])
            for field in inputs:
                field_info = {
                    'name': field.get('name', ''),
                    'type': field.get('type', field.name),
                    'value': field.get('value', '')
                }
                form_data['fields'].append(field_info)
                
                if field.get('name'):
                    with self.params_lock:
                        self.params.add(field.get('name'))
            
            with self.forms_lock:
                self.forms.append(form_data)
    
    def _enumerate_subdomains(self):
        """
        Enumerate common subdomains via DNS resolution.
        """
        parsed = urlparse(self.target if '://' in self.target else f'http://{self.target}')
        domain = parsed.netloc.split(':')[0]
        
        log(f"Enumerating subdomains for {domain}", Colors.CYAN, self.verbose)
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [
                executor.submit(self._resolve_subdomain, subdomain, domain)
                for subdomain in self.COMMON_SUBDOMAINS
            ]
            
            from concurrent.futures import as_completed
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    if self.verbose:
                        log(f"Subdomain resolution error: {str(e)}", Colors.RED, self.verbose)

    def _discover_robots(self):
        """
        Discover endpoints listed in robots.txt.
        """
        try:
            robots_url = urljoin(self.base_url, "/robots.txt")
            response = safe_get(self.session, robots_url, self.timeout, raise_for_status=False)
            if response and response.status_code == 200:
                for line in response.text.splitlines():
                    line = line.strip()
                    if line.lower().startswith("disallow:"):
                        path = line.split(":", 1)[1].strip()
                        if path and path != "/":
                            candidate = urljoin(self.base_url, path)
                            if same_domain(self.base_url, candidate) and not self._should_skip_link(candidate):
                                with self.urls_lock:
                                    self._add_discovered_url(candidate)
                if self.verbose:
                    log(f"Discovered robots.txt entries from {robots_url}", Colors.GREEN, self.verbose)
        except Exception as e:
            if self.verbose:
                log(f"Error fetching robots.txt: {str(e)}", Colors.RED, self.verbose)

    def _discover_sitemap(self):
        """
        Discover URLs from sitemap.xml.
        """
        for sitemap_path in ["/sitemap.xml", "/sitemap_index.xml"]:
            try:
                sitemap_url = urljoin(self.base_url, sitemap_path)
                response = safe_get(self.session, sitemap_url, self.timeout, raise_for_status=False)
                if response and response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'xml')
                    for loc in soup.find_all('loc'):
                        candidate = loc.text.strip()
                        if same_domain(self.base_url, candidate) and url_in_scope(candidate, self.config):
                            with self.urls_lock:
                                self._add_discovered_url(candidate)
                    if self.verbose:
                        log(f"Discovered sitemap entries from {sitemap_url}", Colors.GREEN, self.verbose)
            except Exception as e:
                if self.verbose:
                    log(f"Error fetching sitemap: {str(e)}", Colors.RED, self.verbose)

    def _should_skip_link(self, url: str) -> bool:
        """Skip out-of-scope URLs, static assets, and excluded paths."""
        if not url_in_scope(url, self.config):
            return True
        path = urlparse(url).path.lower()
        return any(path.endswith(ext) for ext in self.EXCLUDED_EXTENSIONS)

    def mine_js_bundles(self) -> list[dict]:
        """Passively mine JavaScript bundles for secrets and hidden endpoints."""
        findings = []
        for js_url in sorted(self.js_urls):
            try:
                r = self.session.get(js_url, timeout=self.timeout)
            except Exception:
                continue
            for label, pattern in JS_SECRET_PATTERNS.items():
                matches = pattern.findall(r.text)
                for match in list(set(matches))[:5]:
                    if isinstance(match, tuple):
                        match = next((part for part in match if part), "")
                    evidence = str(match)[:120]
                    if not self._confirm_js_evidence(js_url, evidence):
                        continue
                    f = finding(
                        f"JS Secret: {label}", js_url, "high",
                        f"Pattern '{label}' matched in JS bundle",
                        evidence
                    )
                    if f:
                        findings.append(f)
        return findings

    def _confirm_js_evidence(self, js_url: str, evidence: str) -> bool:
        """Re-request a bundle before reporting stable passive JS evidence."""
        try:
            r = self.session.get(js_url, timeout=self.timeout)
            return evidence in r.text
        except Exception:
            return False

    def _resolve_subdomain(self, subdomain, domain):
        """
        Attempt to resolve a subdomain via DNS.
        """
        full_domain = f"{subdomain}.{domain}"
        
        try:
            socket.gethostbyname(full_domain)
            with self.subdomains_lock:
                self.subdomains.add(full_domain)
            
            if self.verbose:
                log(f"Found subdomain: {full_domain}", Colors.GREEN, self.verbose)
        
        except socket.gaierror:
            pass
        except Exception as e:
            if self.verbose:
                log(f"Error resolving {full_domain}: {str(e)}", Colors.RED, self.verbose)
