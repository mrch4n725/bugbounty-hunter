import threading
import queue
import socket
from urllib.parse import urljoin, urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup

from modules.utils import make_session, safe_get, normalize_url, same_domain, log, Colors


class Recon:
    """
    Reconnaissance module for discovering URLs, subdomains, forms, and parameters.
    Performs multithreaded web crawling, subdomain enumeration, and form discovery.
    """
    
    COMMON_SUBDOMAINS = [
        'www', 'mail', 'ftp', 'dev', 'staging', 'test', 'api', 'admin',
        'beta', 'blog', 'shop', 'git', 'jenkins', 'vpn', 'remote', 'internal',
        'secure', 'server', 'host', 'cloud', 'cdn', 'web', 'app', 'service',
        'email', 'smtp', 'pop', 'ns', 'mx', 'dns', 'db', 'database'
    ]
    
    def __init__(self, config):
        """
        Initialize the Recon module.
        
        Args:
            config (dict): Configuration dictionary with keys:
                - target (str): Target domain/URL
                - threads (int): Number of concurrent threads
                - timeout (int): Request timeout in seconds
                - verbose (bool): Enable verbose logging
                - crawl_depth (int): Maximum crawl depth
        """
        self.target = config.get('target')
        self.threads = config.get('threads', 5)
        self.timeout = config.get('timeout', 10)
        self.verbose = config.get('verbose', False)
        self.crawl_depth = config.get('crawl_depth', 2)
        
        self.session = make_session(config)
        self.urls = set()
        self.forms = []
        self.params = set()
        self.subdomains = set()
        
        # Thread-safe locks
        self.urls_lock = threading.Lock()
        self.forms_lock = threading.Lock()
        self.params_lock = threading.Lock()
        self.subdomains_lock = threading.Lock()
        
    def run(self):
        """
        Execute the reconnaissance process.
        
        Returns:
            dict: Results containing:
                - urls (list): Discovered URLs
                - forms (list): Discovered forms with details
                - params (list): Discovered parameters
                - subdomains (list): Discovered subdomains
        """
        log(f"Starting reconnaissance on {self.target}", Colors.CYAN, self.verbose)
        
        # Start with subdomain enumeration
        self._enumerate_subdomains()
        
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
        
        # Start with the target
        start_url = self.target
        to_visit.put(start_url)
        depth_map[start_url] = 0
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {}
            
            while not to_visit.empty() or futures:
                # Submit new tasks from queue
                while not to_visit.empty() and len(futures) < self.threads:
                    url = to_visit.get()
                    if url not in visited:
                        visited.add(url)
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
                
                # Process completed futures
                if futures:
                    try:
                        done, _ = as_completed(futures.keys(), timeout=1)
                        for future in done:
                            futures.pop(future, None)
                            try:
                                future.result()
                            except Exception as e:
                                if self.verbose:
                                    log(f"Task error: {str(e)}", Colors.RED, self.verbose)
                    except:
                        pass
    
    def _process_url(self, url, depth, to_visit, depth_map, visited):
        """
        Process a single URL and extract links.
        
        Args:
            url (str): URL to process
            depth (int): Current crawl depth
            to_visit (queue.Queue): Queue of URLs to visit
            depth_map (dict): Map of URL depths
            visited (set): Set of visited URLs
        """
        try:
            response = safe_get(self.session, url, self.timeout)
            if response is None:
                return
            
            # Add to discovered URLs
            with self.urls_lock:
                self.urls.add(url)
            
            # Extract parameters from URL
            parsed = urlparse(url)
            if parsed.query:
                params = parse_qs(parsed.query)
                with self.params_lock:
                    for param_name in params.keys():
                        self.params.add(param_name)
            
            # Parse HTML
            try:
                soup = BeautifulSoup(response.text, 'html.parser')
            except Exception as e:
                if self.verbose:
                    log(f"Failed to parse {url}: {str(e)}", Colors.RED, self.verbose)
                return
            
            # Extract forms
            self._extract_forms(url, soup)
            
            # Extract links if not at max depth
            if depth < self.crawl_depth:
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    abs_url = urljoin(url, href)
                    
                    if abs_url and same_domain(url, abs_url) and abs_url not in visited:
                        to_visit.put(abs_url)
                        depth_map[normalized] = depth + 1
        
        except Exception as e:
            if self.verbose:
                log(f"Error processing {url}: {str(e)}", Colors.RED, self.verbose)
    
    def _extract_forms(self, url, soup):
        """
        Extract forms and their fields from HTML.
        
        Args:
            url (str): Source URL
            soup (BeautifulSoup): Parsed HTML soup
        """
        forms = soup.find_all('form')
        
        for form in forms:
            form_data = {
                'url': url,
                'action': urljoin(url, form.get('action', '')),
                'method': form.get('method', 'GET').upper(),
                'fields': []
            }
            
            # Extract form fields
            inputs = form.find_all(['input', 'select', 'textarea'])
            for field in inputs:
                field_info = {
                    'name': field.get('name', ''),
                    'type': field.get('type', field.name),
                    'value': field.get('value', '')
                }
                form_data['fields'].append(field_info)
                
                # Add parameter name
                if field.get('name'):
                    with self.params_lock:
                        self.params.add(field.get('name'))
            
            with self.forms_lock:
                self.forms.append(form_data)
    
    def _enumerate_subdomains(self):
        """
        Enumerate common subdomains via DNS resolution.
        Tests a list of common subdomain prefixes to discover active hosts.
        """
        # Extract domain from target
        parsed = urlparse(self.target if '://' in self.target else f'http://{self.target}')
        domain = parsed.netloc.split(':')[0]
        
        log(f"Enumerating subdomains for {domain}", Colors.CYAN, self.verbose)
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [
                executor.submit(self._resolve_subdomain, subdomain, domain)
                for subdomain in self.COMMON_SUBDOMAINS
            ]
            
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    if self.verbose:
                        log(f"Subdomain resolution error: {str(e)}", Colors.RED, self.verbose)
    
    def _resolve_subdomain(self, subdomain, domain):
        """
        Attempt to resolve a subdomain via DNS.
        
        Args:
            subdomain (str): Subdomain to test
            domain (str): Base domain
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
