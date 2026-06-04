import threading
import queue
import socket
import time
from urllib.parse import urljoin, urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor
from bs4 import BeautifulSoup

from modules.utils import make_session, safe_get, same_domain, log, Colors, url_in_scope


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
        self.forms = []
        self.params = set()
        self.subdomains = set()
        
        parsed = urlparse(self.target if '://' in self.target else f'https://{self.target}')
        self.base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        # Thread-safe locks
        self.urls_lock = threading.Lock()
        self.forms_lock = threading.Lock()
        self.params_lock = threading.Lock()
        self.subdomains_lock = threading.Lock()
        self.crawl_lock = threading.Lock()  # Shared lock for visited and depth data
        
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
            'subdomains': sorted(list(self.subdomains))
        }
    
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
        """
        Process a single URL and extract links.
        """
        try:
            response = safe_get(self.session, url, self.timeout)
            if response is None:
                return
            
            with self.urls_lock:
                if self.max_urls and len(self.urls) >= self.max_urls:
                    return
                self.urls.add(url)
            
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
            
            # Extract links if we haven't reached max crawling depth boundaries
            if depth < self.crawl_depth:
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    candidate = urljoin(url, href)
                    normalized = candidate.split('#')[0].rstrip('/')
                    if not normalized:
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
                                    self.urls.add(candidate)
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
                                self.urls.add(candidate)
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
