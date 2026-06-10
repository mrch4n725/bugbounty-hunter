"""
Headless browser recon for Single Page Application (SPA) analysis.
Discovers SPA routes, API endpoints, forms, runtime parameters, and framework
details using Playwright headless Chromium.
"""

import json
import re
import time
import threading
from urllib.parse import urljoin, urlparse

try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    sync_playwright = None
    PLAYWRIGHT_AVAILABLE = False


FRAMEWORK_SIGNATURES: dict[str, list[dict]] = {
    "react": [
        {"name": "React", "check": "data-reactroot"},
        {"name": "React", "check": "_reactRootContainer"},
        {"name": "React", "check": "__NEXT_DATA__"},
        {"name": "React", "check": "React.createElement"},
        {"name": "React", "check": "ReactDOM"},
    ],
    "vue": [
        {"name": "Vue", "check": "__VUE__"},
        {"name": "Vue", "check": "__NUXT__"},
        {"name": "Vue", "check": "data-v-"},
        {"name": "Vue", "check": "new Vue"},
        {"name": "Vue", "check": "Vue.createApp"},
    ],
    "angular": [
        {"name": "Angular", "check": "ng-version"},
        {"name": "Angular", "check": "__zone_symbol__"},
        {"name": "Angular", "check": "ng-app"},
    ],
    "spa_indicator": [
        {"name": "SPA (pushState)", "check": "pushState"},
        {"name": "SPA (history API)", "check": "history.pushState"},
        {"name": "SPA (hash router)", "check": "__SAMBA__"},
    ],
    "meta_framework": [
        {"name": "Next.js", "check": "__NEXT_DATA__"},
        {"name": "Next.js", "check": "/_next/static"},
        {"name": "Nuxt.js", "check": "__NUXT__"},
        {"name": "Gatsby", "check": "gatsby"},
        {"name": "SvelteKit", "check": "svelte"},
    ],
}


CONFIG_OBJECTS = [
    "__INITIAL_STATE__",
    "__NUXT__",
    "__NEXT_DATA__",
    "__DATA__",
    "__CONFIG__",
    "__STATE__",
    "__PRELOADED_STATE__",
    "__APOLLO_STATE__",
    "__RELAY_DATA__",
    "__VUE_DEVTOOLS_GLOBAL_HOOK__",
    "window.__INITIAL_STATE__",
    "window.__NUXT__",
    "window.__NEXT_DATA__",
    "window.__DATA__",
    "window.__CONFIG__",
]


class HeadlessReconBrowser:
    """Headless browser recon for SPA analysis.

    Lazily launches Playwright Chromium on ``start()``.  All public methods
    return empty structures when Playwright is unavailable, making the class
    safe to import and instantiate in any environment.
    """

    DEFAULT_TIMEOUT = 10_000
    DEFAULT_VIEWPORT = {"width": 1280, "height": 720}
    USER_AGENT = (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    )

    def __init__(self, config: dict | None = None):
        self.config = config or {}
        self._timeout = self.config.get("timeout", 10) * 1000
        self._target = self.config.get("target", "")
        self._playwright = None
        self._browser = None
        self._context = None
        self._pages: list = []
        self._started = False
        self._lock = threading.Lock()

    # ── Lifecycle ────────────────────────────────────────────────────────

    def start(self) -> bool:
        """Launch Playwright and create browser context.

        Returns True on success, False if Playwright is unavailable.
        Safe to call multiple times — subsequent calls are a no-op.
        """
        if self._started:
            return True
        if not PLAYWRIGHT_AVAILABLE or sync_playwright is None:
            return False
        try:
            self._playwright = sync_playwright().start()
            self._browser = self._playwright.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-dev-shm-usage"],
            )
            self._context = self._browser.new_context(
                user_agent=self.USER_AGENT,
                viewport=self.DEFAULT_VIEWPORT,
                ignore_https_errors=not self.config.get("verify_ssl", True),
                extra_http_headers=self.config.get("extra_headers", {}),
            )
            self._pages = [self._context.new_page()]
            self._started = True
            return True
        except Exception:
            self._started = False
            return False

    def close(self) -> None:
        """Release all browser resources."""
        with self._lock:
            for page in self._pages:
                try:
                    page.close()
                except Exception:
                    pass
            self._pages.clear()
            if self._context:
                try:
                    self._context.close()
                except Exception:
                    pass
                self._context = None
            if self._browser:
                try:
                    self._browser.close()
                except Exception:
                    pass
                self._browser = None
            if self._playwright:
                try:
                    self._playwright.stop()
                except Exception:
                    pass
                self._playwright = None
            self._started = False

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def _page(self) -> object | None:
        """Return the first available page, creating one if needed."""
        if not self._started:
            return None
        with self._lock:
            if not self._pages:
                if self._context:
                    self._pages.append(self._context.new_page())
                else:
                    return None
            return self._pages[0]

    def _new_page(self) -> object | None:
        """Create a dedicated page (for form submission etc.)."""
        if not self._started or not self._context:
            return None
        page = self._context.new_page()
        with self._lock:
            self._pages.append(page)
        return page

    # ── Helpers ──────────────────────────────────────────────────────────

    @staticmethod
    def _normalise(url: str) -> str:
        return url.split("#")[0].rstrip("/")

    def _same_origin(self, url: str) -> bool:
        if not self._target or not url:
            return False
        target_parsed = urlparse(self._target)
        url_parsed = urlparse(url)
        return target_parsed.netloc == url_parsed.netloc

    # ── SPA spider ───────────────────────────────────────────────────────

    def spa_spider(
        self,
        start_url: str,
        max_clicks: int = 50,
        max_depth: int = 3,
    ) -> dict:
        """Crawl an SPA by clicking links and capturing XHR / route changes.

        Returns a dict with keys: urls, api_endpoints, js_endpoints, forms,
        parameters, routes, tech_stack, screenshots, xhr_calls.
        """
        result: dict = {
            "urls": [],
            "api_endpoints": [],
            "js_endpoints": [],
            "forms": [],
            "parameters": [],
            "routes": [],
            "tech_stack": [],
            "screenshots": {},
            "xhr_calls": [],
        }
        if not PLAYWRIGHT_AVAILABLE or not self.start():
            return result

        page = self._page()
        if page is None:
            return result

        # Collection buckets
        visited: set = set()
        discovered_urls: set = set()
        api_calls: list[dict] = []
        xhr_log: list[dict] = []
        screenshot_store: dict = {}
        routes: set = set()
        forms_found: list[dict] = []

        def _on_request(request):
            try:
                rurl = request.url
                method = request.method
                headers = dict(request.headers)

                if request.resource_type in ("xhr", "fetch"):
                    entry = {
                        "method": method,
                        "url": rurl,
                        "headers": headers,
                        "status": 0,
                        "body": "",
                    }
                    try:
                        resp = request.response()
                        if resp:
                            entry["status"] = resp.status
                    except Exception:
                        pass

                    if request.method == "POST":
                        try:
                            post_data = request.post_data
                            if post_data:
                                entry["body"] = post_data
                        except Exception:
                            pass

                    xhr_log.append(entry)
                    normalised = rurl.split("?")[0].rstrip("/")
                    if self._same_origin(rurl):
                        discovered_urls.add(normalised)
                        if "/api/" in rurl or "/graphql" in rurl or "/rest/" in rurl:
                            api_calls.append(entry)

                elif request.resource_type == "script":
                    if self._same_origin(rurl):
                        discovered_urls.add(rurl.split("?")[0].rstrip("/"))
            except Exception:
                pass

        page.on("request", _on_request)

        try:
            page.goto(start_url, wait_until="networkidle", timeout=self._timeout)
            page.wait_for_timeout(1500)
        except Exception:
            try:
                page.goto(start_url, timeout=self._timeout)
                page.wait_for_timeout(3000)
            except Exception:
                return result

        visited.add(self._normalise(start_url))
        discovered_urls.add(self._normalise(start_url))

        # Framework detection
        result["tech_stack"] = self._detect_framework(page)

        # JS config objects
        js_endpoints = self._parse_config_objects(page)
        result["js_endpoints"] = js_endpoints

        # Initial page screenshot
        self._capture_screenshot(page, start_url, screenshot_store)

        # Crawl interactively
        click_count = 0

        def _spa_click(depth: int):
            nonlocal click_count
            if depth > max_depth or click_count >= max_clicks:
                return

            try:
                elements = page.evaluate("""() => {
                    const anchors = Array.from(document.querySelectorAll('a[href]'));
                    const buttons = Array.from(
                        document.querySelectorAll('button:not([disabled])')
                    );
                    return [
                        ...anchors.map(a => ({
                            tag: 'a', href: a.href, text: (a.textContent || '').trim().slice(0, 60)
                        })),
                        ...buttons.map((b, i) => ({
                            tag: 'button',
                            index: i,
                            text: (b.textContent || '').trim().slice(0, 60)
                        }))
                    ];
                }""")
            except Exception:
                return

            for el in elements:
                if click_count >= max_clicks:
                    break
                try:
                    if el["tag"] == "a":
                        href = el.get("href", "")
                        if not href or href.startswith(("javascript:", "#", "mailto:")):
                            continue
                        normalised = self._normalise(href)
                        if normalised in visited:
                            continue
                        if not self._same_origin(href):
                            continue
                        visited.add(normalised)
                        discovered_urls.add(normalised)

                        try:
                            with page.expect_navigation(
                                timeout=5000, wait_until="networkidle"
                            ):
                                page.goto(href, timeout=self._timeout)
                        except Exception:
                            try:
                                page.goto(href, timeout=self._timeout)
                            except Exception:
                                continue
                        page.wait_for_timeout(1000)
                        click_count += 1

                        # Capture screenshot
                        self._capture_screenshot(page, href, screenshot_store)

                        # Route detected (SPA route change without full page reload)
                        if normalised != self._normalise(start_url):
                            routes.add(normalised)

                        # Extract forms
                        self._extract_forms_from_page(page, normalised, forms_found)

                        # Parse config objects on new page
                        js_endpoints.extend(self._parse_config_objects(page))

                        # Recurse
                        _spa_click(depth + 1)

                    elif el["tag"] == "button":
                        index = el.get("index", 0)
                        try:
                            buttons = page.query_selector_all("button:not([disabled])")
                            if index < len(buttons):
                                btn = buttons[index]
                                try:
                                    btn.click()
                                    page.wait_for_timeout(2000)
                                    click_count += 1

                                    # Check if URL changed
                                    current = self._normalise(page.url)
                                    if current != self._normalise(start_url):
                                        discovered_urls.add(current)
                                        routes.add(current)

                                    self._capture_screenshot(
                                        page, page.url, screenshot_store
                                    )
                                    js_endpoints.extend(
                                        self._parse_config_objects(page)
                                    )
                                except Exception:
                                    pass
                        except Exception:
                            pass
                except Exception:
                    continue

        _spa_click(depth=1)

        # De-duplicate js_endpoints
        seen_js = set()
        unique_js = []
        for ep in js_endpoints:
            key = json.dumps(ep, sort_keys=True)
            if key not in seen_js:
                seen_js.add(key)
                unique_js.append(ep)

        # De-duplicate api_calls
        seen_api = set()
        unique_api = []
        for ac in api_calls:
            key = f"{ac['method']} {ac['url']}"
            if key not in seen_api:
                seen_api.add(key)
                unique_api.append(ac)

        # Extract parameters from URLs
        params_found: set = set()
        for u in discovered_urls:
            parsed = urlparse(u)
            if parsed.query:
                for qp in parsed.query.split("&"):
                    if "=" in qp:
                        params_found.add(qp.split("=")[0])

        result["urls"] = sorted(discovered_urls)
        result["api_endpoints"] = unique_api
        result["js_endpoints"] = unique_js
        result["forms"] = forms_found
        result["parameters"] = sorted(params_found)
        result["routes"] = sorted(routes)
        result["screenshots"] = screenshot_store
        result["xhr_calls"] = xhr_log
        return result

    # ── API endpoint capture ─────────────────────────────────────────────

    def capture_api_endpoints(self, url: str, timeout: int = 15) -> dict:
        """Navigate to *url* and capture all XHR / fetch calls.

        Returns a dict keyed by category: ``rest``, ``graphql``, ``other``
        with each entry containing method, url, headers, body, and status.
        Also reports detected authentication tokens in ``auth_tokens``.
        """
        result: dict = {
            "rest": [],
            "graphql": [],
            "other": [],
            "auth_tokens": [],
        }
        if not PLAYWRIGHT_AVAILABLE or not self.start():
            return result

        page = self._page()
        if page is None:
            return result

        captured: list[dict] = []
        auth_tokens: list[dict] = []

        def _on_request(request):
            try:
                if request.resource_type not in ("xhr", "fetch"):
                    return
                entry = {
                    "method": request.method,
                    "url": request.url,
                    "headers": dict(request.headers),
                    "status": 0,
                    "body": "",
                }
                try:
                    resp = request.response()
                    if resp:
                        entry["status"] = resp.status
                except Exception:
                    pass
                if request.method == "POST":
                    try:
                        post_data = request.post_data
                        if post_data:
                            entry["body"] = post_data
                    except Exception:
                        pass

                # Auth token detection
                for hname, hval in request.headers.items():
                    hl = hname.lower()
                    if hl in ("authorization", "x-api-key", "x-auth-token"):
                        auth_tokens.append({
                            "header": hname,
                            "value": hval[:60] + "..." if len(hval) > 60 else hval,
                            "url": request.url,
                        })

                captured.append(entry)
            except Exception:
                pass

        page.on("request", _on_request)

        try:
            page.goto(url, wait_until="networkidle", timeout=timeout * 1000)
            page.wait_for_timeout(3000)
        except Exception:
            try:
                page.goto(url, timeout=timeout * 1000)
                page.wait_for_timeout(4000)
            except Exception:
                return result

        for entry in captured:
            u = entry["url"]
            path = urlparse(u).path.lower()
            if path.startswith("/api") or "/api/" in u:
                result["rest"].append(entry)
            elif "/graphql" in path or path == "/graphql":
                result["graphql"].append(entry)
            else:
                result["other"].append(entry)

        result["auth_tokens"] = auth_tokens
        return result

    # ── Form interaction ─────────────────────────────────────────────────

    def interact_with_forms(self, url: str) -> list[dict]:
        """Find all forms on *url*, fill them with test data, and submit.

        Tracks redirect chains and CSRF tokens. Returns a list of
        form-to-API-call mappings.
        """
        if not PLAYWRIGHT_AVAILABLE or not self.start():
            return []

        page = self._page()
        if page is None:
            return []

        results: list[dict] = []

        try:
            page.goto(url, wait_until="networkidle", timeout=self._timeout)
            page.wait_for_timeout(1500)
        except Exception:
            try:
                page.goto(url, timeout=self._timeout)
                page.wait_for_timeout(3000)
            except Exception:
                return results

        try:
            form_infos = page.evaluate("""() => {
                const forms = document.querySelectorAll('form');
                return Array.from(forms).map((f, idx) => {
                    const inputs = Array.from(f.querySelectorAll('input, select, textarea'));
                    return {
                        index: idx,
                        action: f.action || '',
                        method: (f.method || 'GET').toUpperCase(),
                        inputs: inputs.map(i => ({
                            name: i.name || '',
                            type: i.type || 'text',
                            placeholder: i.placeholder || '',
                            value: i.value || '',
                        })),
                        csrf_fields: inputs
                            .filter(i => /csrf|token|_token|authenticity/i.test(i.name))
                            .map(i => ({ name: i.name, value: i.value })),
                    };
                });
            }""")
        except Exception:
            form_infos = []

        for fi in form_infos:
            form_result = {
                "url": url,
                "action": fi.get("action", ""),
                "method": fi.get("method", "GET"),
                "fields": fi.get("inputs", []),
                "csrf_tokens": fi.get("csrf_fields", []),
                "submitted": False,
                "redirect_chain": [],
                "api_calls": [],
            }

            instrumented = self._new_page()
            if instrumented is None:
                results.append(form_result)
                continue

            submitted_xhr: list[dict] = []

            def _make_recorder(xhr_list):
                def _on_request(request):
                    try:
                        if request.resource_type in ("xhr", "fetch"):
                            entry = {
                                "method": request.method,
                                "url": request.url,
                                "status": 0,
                            }
                            try:
                                resp = request.response()
                                if resp:
                                    entry["status"] = resp.status
                            except Exception:
                                pass
                            xhr_list.append(entry)
                    except Exception:
                        pass
                return _on_request

            instrumented.on("request", _make_recorder(submitted_xhr))

            try:
                instrumented.goto(url, timeout=self._timeout)
                instrumented.wait_for_timeout(1000)

                # Fill form fields
                for inp in fi.get("inputs", []):
                    name = inp.get("name", "")
                    if not name:
                        continue
                    itype = inp.get("type", "")
                    try:
                        if itype in ("checkbox", "radio"):
                            instrumented.check(
                                f'[name="{name}"]', timeout=3000
                            )
                        elif itype == "select":
                            instrumented.select_option(
                                f'[name="{name}"]', index=0, timeout=3000
                            )
                        elif itype == "file":
                            pass
                        elif itype == "email":
                            instrumented.fill(
                                f'[name="{name}"]',
                                "test@example.com",
                                timeout=3000,
                            )
                        elif itype in ("tel", "phone"):
                            instrumented.fill(
                                f'[name="{name}"]', "+1234567890", timeout=3000
                            )
                        else:
                            instrumented.fill(
                                f'[name="{name}"]',
                                f"test_{name}",
                                timeout=3000,
                            )
                    except Exception:
                        pass

                # Submit
                try:
                    with instrumented.expect_navigation(timeout=8000):
                        instrumented.evaluate(
                            f"document.querySelector('form').submit()"
                        )
                    form_result["submitted"] = True
                except Exception:
                    try:
                        instrumented.evaluate(
                            f"document.querySelector('form').submit()"
                        )
                        instrumented.wait_for_timeout(3000)
                        form_result["submitted"] = True
                    except Exception:
                        pass

                # Redirect chain
                form_result["redirect_chain"] = self._redirect_chain(
                    instrumented
                )
                form_result["api_calls"] = submitted_xhr

            except Exception:
                pass
            finally:
                try:
                    instrumented.close()
                except Exception:
                    pass

            results.append(form_result)

        return results

    # ── Runtime parameter discovery ──────────────────────────────────────

    def discover_runtime_params(self, url: str) -> list[dict]:
        """Enumerate ``window`` globals and parse known config objects.

        Returns a list of dicts with keys: ``name``, ``source``, ``type``,
        and optionally ``value`` / ``endpoints`` / ``routes``.
        """
        if not PLAYWRIGHT_AVAILABLE or not self.start():
            return []

        page = self._page()
        if page is None:
            return []

        try:
            page.goto(url, wait_until="networkidle", timeout=self._timeout)
            page.wait_for_timeout(1500)
        except Exception:
            try:
                page.goto(url, timeout=self._timeout)
                page.wait_for_timeout(3000)
            except Exception:
                return []

        result: list[dict] = []

        # Enumerate Object.keys(window)
        try:
            global_keys = page.evaluate("""() => Object.keys(window).filter(
                k => !k.startsWith('_') || k.startsWith('__')
            )""")
            for key in global_keys:
                result.append({
                    "name": key,
                    "source": "window",
                    "type": "global",
                })
        except Exception:
            pass

        # Parse config objects
        for config_name in CONFIG_OBJECTS:
            clean = config_name.replace("window.", "")
            try:
                value = page.evaluate(f"() => window.{clean}")
                if value is None:
                    continue
                entry: dict = {
                    "name": clean,
                    "source": config_name,
                    "type": "config_object",
                }
                if isinstance(value, dict):
                    entry["endpoints"] = self._extract_endpoints_from_config(
                        value
                    )
                    entry["routes"] = self._extract_routes_from_config(
                        value
                    )
                result.append(entry)
            except Exception:
                continue

        return result

    # ── Framework detection ──────────────────────────────────────────────

    def _detect_framework(self, page) -> list[str]:
        """Detect frontend frameworks from page content and global signals."""
        detected: list[str] = []
        try:
            content = page.content()
        except Exception:
            return detected

        content_lower = content.lower()

        for category, signatures in FRAMEWORK_SIGNATURES.items():
            for sig in signatures:
                check = sig["check"].lower()
                if check in content_lower:
                    name = sig["name"]
                    if name not in detected:
                        detected.append(name)

        # Also check via JS evaluation for runtime signals
        try:
            has_next = page.evaluate("() => typeof window.__NEXT_DATA__ !== 'undefined'")
            if has_next and "Next.js" not in detected:
                detected.append("Next.js")
        except Exception:
            pass

        try:
            has_nuxt = page.evaluate("() => typeof window.__NUXT__ !== 'undefined'")
            if has_nuxt and "Nuxt.js" not in detected:
                detected.append("Nuxt.js")
        except Exception:
            pass

        try:
            has_ng = page.evaluate("() => document.querySelector('[ng-version]') !== null")
            if has_ng and "Angular" not in detected:
                detected.append("Angular")
        except Exception:
            pass

        try:
            has_react = page.evaluate(
                "() => typeof document.getElementById('root') !== null "
                "|| document.querySelector('[data-reactroot]') !== null "
                "|| typeof window.__REACT_DEVTOOLS_GLOBAL_HOOK__ !== 'undefined'"
            )
            if has_react and "React" not in detected:
                detected.append("React")
        except Exception:
            pass

        return detected

    # ── Config object parsing ────────────────────────────────────────────

    def _parse_config_objects(self, page) -> list[dict]:
        """Parse JS config objects (__NEXT_DATA__, __NUXT__, etc.) for API
        endpoints and routes."""
        endpoints: list[dict] = []

        for config_name in CONFIG_OBJECTS:
            clean = config_name.replace("window.", "")
            try:
                value = page.evaluate(f"() => window.{clean}")
                if value is None:
                    continue
                ep_list = self._extract_endpoints_from_config(value)
                rt_list = self._extract_routes_from_config(value)
                entry: dict = {
                    "name": clean,
                    "source": config_name,
                    "endpoints": ep_list,
                    "routes": rt_list,
                }
                endpoints.append(entry)
            except Exception:
                continue

        return endpoints

    @staticmethod
    def _extract_endpoints_from_config(obj: dict, depth: int = 0) -> list[str]:
        """Recursively extract URL-like strings from a config object."""
        if depth > 5:
            return []
        found: list[str] = []
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(v, str) and (
                    v.startswith("/") or v.startswith("http://")
                    or v.startswith("https://")
                ):
                    if len(v) > 2 and v not in found:
                        found.append(v)
                else:
                    found.extend(
                        HeadlessReconBrowser._extract_endpoints_from_config(
                            v, depth + 1
                        )
                    )
        elif isinstance(obj, list):
            for item in obj:
                found.extend(
                    HeadlessReconBrowser._extract_endpoints_from_config(
                        item, depth + 1
                    )
                )
        return found

    @staticmethod
    def _extract_routes_from_config(obj: dict, depth: int = 0) -> list[str]:
        """Recursively extract route-like strings from a config object."""
        if depth > 5:
            return []
        found: list[str] = []
        route_keys = {"route", "routes", "path", "paths", "page", "pages"}
        if isinstance(obj, dict):
            for k, v in obj.items():
                kl = k.lower()
                if kl in route_keys and isinstance(v, str):
                    if v.startswith("/") and v not in found:
                        found.append(v)
                if isinstance(v, (dict, list)):
                    found.extend(
                        HeadlessReconBrowser._extract_routes_from_config(
                            v, depth + 1
                        )
                    )
        elif isinstance(obj, list):
            for item in obj:
                found.extend(
                    HeadlessReconBrowser._extract_routes_from_config(
                        item, depth + 1
                    )
                )
        return found

    # ── Form extraction from page ────────────────────────────────────────

    def _extract_forms_from_page(
        self, page, page_url: str, forms: list
    ) -> None:
        """Extract form metadata from current page DOM."""
        try:
            form_data = page.evaluate("""(currentUrl) => {
                return Array.from(document.querySelectorAll('form')).map(f => ({
                    url: currentUrl,
                    action: f.action || '',
                    method: (f.method || 'GET').toUpperCase(),
                    fields: Array.from(f.querySelectorAll('input, select, textarea')).map(i => ({
                        name: i.name || '',
                        type: i.type || i.tagName.toLowerCase(),
                        value: i.value || '',
                    })),
                }));
            }""", page_url)
            if form_data:
                for fd in form_data:
                    if fd not in forms:
                        forms.append(fd)
        except Exception:
            pass

    # ── Screenshot capture ───────────────────────────────────────────────

    def _capture_screenshot(
        self, page, page_url: str, store: dict
    ) -> None:
        """Take a screenshot and store it as base64 in *store*."""
        try:
            b64 = page.screenshot(type="png", full_page=False)
            import base64
            store[page_url] = base64.b64encode(b64).decode("ascii")
        except Exception:
            pass

    # ── Redirect chain ───────────────────────────────────────────────────

    @staticmethod
    def _redirect_chain(page) -> list[str]:
        """Extract the redirect chain from current page URL history."""
        try:
            chain = page.evaluate("""() => {
                const entries = performance.getEntriesByType('navigation');
                if (entries.length > 0) {
                    return entries.map(e => e.name);
                }
                return [window.location.href];
            }""")
            return list(dict.fromkeys(chain)) if chain else [page.url]
        except Exception:
            return [page.url]
