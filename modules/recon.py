"""
Recon module — crawler, subdomain enumeration, form/param discovery.
"""

import re
import threading
from urllib.parse import urlparse, urljoin, parse_qs, urldefrag
from queue import Queue, Empty
from bs4 import BeautifulSoup

from modules.utils import make_session, safe_get, normalize_url, same_domain, log, Colors


COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "dev", "staging", "test", "api", "admin",
    "beta", "blog", "shop", "app", "portal", "dashboard", "cdn",
    "static", "assets", "media", "vpn", "remote", "support", "help",
    "forum", "docs", "git", "gitlab", "jenkins", "jira", "confluence",
    "m", "mobile", "internal", "corp", "intranet",
]


class Recon:
    def __init__(self, config: dict):
        self.config   = config
        self.target   = config["target"]
        self.depth    = config.get("crawl_depth", 2)
        self.threads  = config.get("threads", 10)
        self.timeout  = config.get("timeout", 10)
        self.verbose  = config.get("verbose", False)
        self.session  = make_session(config)

        self.visited    : set[str]  = set()
        self.urls       : set[str]  = set()
        self.forms      : list[dict] = []
        self.params     : set[str]  = set()
        self.subdomains : set[str]  = set()
        self._lock = threading.Lock()

    def run(self) -> dict:
        self._crawl(self.target, self.depth)
        self._enumerate_subdomains()
        return {
            "urls":       list(self.urls),
            "forms":      self.forms,
            "params":     list(self.params),
            "subdomains": list(self.subdomains),
        }

    def _crawl(self, start_url: str, max_depth: int):
        queue: Queue = Queue()
        queue.put((start_url, 0))

        def worker():
            while True:
                try:
                    url, depth = queue.get(timeout=3)
                except Empty:
                    return

                with self._lock:
                    if url in self.visited or depth > max_depth:
                        queue.task_done()
                        continue
                    self.visited.add(url)

                log(f"  [crawl] {url}", Colors.WHITE, verbose_only=True, verbose=self.verbose)
                resp = safe_get(self.session, url, self.timeout)
                if resp is None or resp.status_code >= 400:
                    queue.task_done()
                    continue

                with self._lock:
                    self.urls.add(url)

                parsed = urlparse(url)
                if parsed.query:
                    for param in parse_qs(parsed.query):
                        with self._lock:
                            self.params.add(param)

                content_type = resp.headers.get("Content-Type", "")
                if "html" not in content_type:
                    queue.task_done()
                    continue

                soup = BeautifulSoup(resp.text, "html.parser")
                self._extract_forms(soup, url)

                for tag in soup.find_all(["a", "link", "script", "img", "iframe"]):
                    href = tag.get("href") or tag.get("src") or ""
                    full = normalize_url(url, href)
                    if full and same_domain(self.target, full):
                        clean, _ = urldefrag(full)
                        with self._lock:
                            if clean not in self.visited:
                                queue.put((clean, depth + 1))

                queue.task_done()

        workers = [threading.Thread(target=worker, daemon=True) for _ in range(self.threads)]
        for w in workers:
            w.start()
        queue.join()

    def _extract_forms(self, soup: BeautifulSoup, page_url: str):
        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = form.get("method", "get").lower()
            action_url = normalize_url(page_url, action) or page_url

            fields = []
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name", "")
                ftype = inp.get("type", "text")
                value = inp.get("value", "")
                if name:
                    fields.append({"name": name, "type": ftype, "value": value})
                    with self._lock:
                        self.params.add(name)

            with self._lock:
                self.forms.append({
                    "action": action_url,
                    "method": method,
                    "fields": fields,
                    "page":   page_url,
                })

    def _enumerate_subdomains(self):
        base_domain = urlparse(self.target).netloc.split(":")[0]
        if base_domain.startswith("www."):
            base_domain = base_domain[4:]

        def check(sub):
            fqdn = f"{sub}.{base_domain}"
            url  = f"https://{fqdn}"
            resp = safe_get(self.session, url, timeout=5)
            if resp is not None and resp.status_code < 500:
                with self._lock:
                    self.subdomains.add(fqdn)
                log(f"  [subdomain] Found: {fqdn}", Colors.GREEN, verbose_only=True, verbose=self.verbose)

        threads = []
        for sub in COMMON_SUBDOMAINS:
            t = threading.Thread(target=check, args=(sub,), daemon=True)
            threads.append(t)
            t.start()
        for t in threads:
            t.join(timeout=8)
