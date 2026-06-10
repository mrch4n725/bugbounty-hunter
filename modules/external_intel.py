"""
External Intelligence Gatherer

Passive reconnaissance module that queries external sources for threat intelligence,
subdomain discovery, historical endpoints, and leaked credentials.

Integrates:
  - Shodan (API key required)
  - Censys (free certificate search)
  - crt.sh (Certificate Transparency logs, no key needed)
  - Wayback Machine (historical URL archive, no key needed)
  - GitHub code search (token optional, for leak detection)
"""

import json
import re
import threading
import time
from typing import Any
from urllib.parse import urlparse, parse_qs

import requests

from modules.utils import log, Colors


class ExternalIntelligenceGatherer:
    """Passive intelligence gatherer that queries external sources.

    Usage:
        intel = ExternalIntelligenceGatherer(config={...})
        result = intel.gather("example.com", config)
    """

    GITHUB_LEAK_PATTERNS: list[re.Pattern] = [
        re.compile(r"(?i)(?:api[_-]?key|apikey)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{16,})"),
        re.compile(r"(?i)(?:secret|token|password|passwd|credential|auth)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-@#$%^&+=]{8,})"),
        re.compile(r"(?:ghp_|gho_|github_pat_)[a-zA-Z0-9_]{36,}"),
        re.compile(r"AKIA[0-9A-Z]{16}"),
        re.compile(r"(?i)(?:endpoint|base_url|api_url|internal_url)\s*[:=]\s*['\"]?(https?://[^'\"\s]+)"),
        re.compile(r"(?i)(?:aws_access_key_id|aws_secret_access_key)\s*[:=]\s*['\"]?(\S+)"),
        re.compile(r"(?i)sk_live_[0-9a-zA-Z]{24,}"),
        re.compile(r"(?i)pk_live_[0-9a-zA-Z]{24,}"),
        re.compile(r"(?i)(?:slack_token|xox[baprs]-)[a-zA-Z0-9\-]{24,}"),
    ]

    GITHUB_SECRET_FILES: list[str] = [
        ".env", ".env.production", ".env.development",
        "config.yml", "config.yaml", "config.json",
        "credentials", "credentials.json",
        "secrets", "secrets.yml", "secrets.yaml",
        "docker-compose.yml", "docker-compose.yaml",
        "settings.py", "settings.json",
        "application.yml", "application.properties",
    ]

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._rate_limit_lock = threading.Lock()
        self._last_request_time: float = 0.0

    def gather(self, domain: str, config: dict) -> dict:
        """Run all external intelligence sources in sequence.

        Args:
            domain: Target domain (e.g. "example.com")
            config: Dict with optional keys:
                shodan_api_key, github_token, github_org,
                timeout (default 10), rate_limit (default 1.0)

        Returns:
            Combined intelligence dict mergeable into recon output.
        """
        timeout = config.get("timeout", 10)
        rate_limit = config.get("rate_limit", 1.0)

        shodan_key = config.get("shodan_api_key", "")
        github_token = config.get("github_token", "")
        github_org = config.get("github_org", "")

        result: dict[str, Any] = {
            "sources": {},
            "subdomains": [],
            "urls": [],
            "js_urls": [],
        }

        # 1. Shodan
        shodan_result = self.gather_shodan(domain, shodan_key, timeout, rate_limit)
        with self._lock:
            result["sources"]["shodan"] = shodan_result
            if shodan_result["status"] == "ok":
                data = shodan_result["data"]
                result["subdomains"].extend(data.get("subdomains", []))
                for host in data.get("hosts", []):
                    candidate = f"https://{host}"
                    if candidate not in result["urls"]:
                        result["urls"].append(candidate)

        # 2. crt.sh
        crtsh_result = self.gather_crtsh(domain, timeout, rate_limit)
        with self._lock:
            result["sources"]["certificate_transparency"] = crtsh_result
            if crtsh_result["status"] == "ok":
                subdomains = crtsh_result["data"].get("subdomains", [])
                result["subdomains"].extend(subdomains)
                for sub in subdomains:
                    candidate = f"https://{sub}"
                    if candidate not in result["urls"]:
                        result["urls"].append(candidate)

        # 3. Wayback Machine
        wayback_result = self.gather_wayback(domain, timeout, rate_limit)
        with self._lock:
            result["sources"]["wayback"] = wayback_result
            if wayback_result["status"] == "ok":
                data = wayback_result["data"]
                result["urls"].extend(data.get("historic_endpoints", []))
                result["js_urls"].extend(data.get("js_urls", []))

        # 4. GitHub leaks
        github_result = self.gather_github(domain, github_org, github_token, timeout, rate_limit)
        with self._lock:
            result["sources"]["github_leaks"] = github_result

        # Deduplicate
        with self._lock:
            result["subdomains"] = sorted(set(result["subdomains"]))
            result["urls"] = sorted(set(result["urls"]))
            result["js_urls"] = sorted(set(result["js_urls"]))

        # Summary
        leaks = github_result.get("data", []) if github_result["status"] == "ok" else []
        result["summary"] = {
            "total_subdomains": len(result["subdomains"]),
            "total_endpoints": len(result["urls"]),
            "total_leaks": len(leaks),
        }

        return result

    def _rate_limit(self, rps: float = 1.0) -> None:
        """Ensure at most *rps* requests per second."""
        with self._rate_limit_lock:
            elapsed = time.time() - self._last_request_time
            if elapsed < 1.0 / rps:
                time.sleep((1.0 / rps) - elapsed)
            self._last_request_time = time.time()

    # ── Shodan ────────────────────────────────────────────────────────────

    def gather_shodan(
        self, domain: str, api_key: str = "",
        timeout: int = 10, rate_limit: float = 1.0,
    ) -> dict:
        """Query Shodan for open ports, services, and hostnames.

        Returns:
            {"status": "ok|error|skipped", "data": {...}, "error": "..."}
        """
        if not api_key:
            return {"status": "skipped", "data": {"hosts": [], "ports": [], "services": [], "subdomains": []}, "error": "No Shodan API key configured"}

        self._rate_limit(rate_limit)
        try:
            # Resolve domain to IP first
            import socket as _socket
            try:
                ip = _socket.gethostbyname(domain)
            except Exception as exc:
                return {"status": "error", "data": {"hosts": [], "ports": [], "services": [], "subdomains": []}, "error": f"DNS resolution failed: {exc}"}

            url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
            resp = requests.get(url, timeout=timeout, headers={"Accept": "application/json"})
            if resp.status_code != 200:
                return {"status": "error", "data": {"hosts": [], "ports": [], "services": [], "subdomains": []}, "error": f"Shodan returned {resp.status_code}"}

            data = resp.json()
            ports: list[int] = data.get("ports", [])
            hostnames: list[str] = data.get("hostnames", [])
            services: list[dict] = []
            for item in data.get("data", []):
                svc = {
                    "port": item.get("port"),
                    "transport": item.get("transport", ""),
                    "product": item.get("product", ""),
                    "version": item.get("version", ""),
                    "name": item.get("_shodan", {}).get("module", item.get("product", "")),
                }
                if svc not in services:
                    services.append(svc)

            return {
                "status": "ok",
                "data": {
                    "hosts": [ip],
                    "ports": sorted(ports),
                    "services": services,
                    "subdomains": [f"{h}.{domain}" for h in hostnames if h and not h.startswith(".")],
                },
                "error": "",
            }
        except requests.RequestException as exc:
            return {"status": "error", "data": {"hosts": [], "ports": [], "services": [], "subdomains": []}, "error": f"Shodan request failed: {exc}"}
        except Exception as exc:
            return {"status": "error", "data": {"hosts": [], "ports": [], "services": [], "subdomains": []}, "error": f"Shodan error: {exc}"}

    # ── Censys (free certificate search) ─────────────────────────────────

    def gather_censys(
        self, domain: str, api_key: str = "",
        timeout: int = 10, rate_limit: float = 1.0,
    ) -> dict:
        """Query Censys certificates endpoint for known subdomains.

        Uses the free Censys certificate search. Returns gracefully when
        no API key is configured or when the request fails.

        Returns:
            {"status": "ok|error|skipped", "data": {...}, "error": "..."}
        """
        if not api_key:
            return {"status": "skipped", "data": {"subdomains": [], "certificates": []}, "error": "No Censys API key configured"}

        self._rate_limit(rate_limit)
        try:
            url = "https://search.censys.io/api/v2/certificates"
            params = {
                "q": f"parsed.names: {domain}",
                "per_page": 100,
            }
            headers = {"Accept": "application/json"}
            resp = requests.get(url, params=params, timeout=timeout, headers=headers)
            if resp.status_code != 200:
                return {"status": "error", "data": {"subdomains": [], "certificates": []}, "error": f"Censys returned {resp.status_code}"}

            data = resp.json()
            subdomains: set[str] = set()
            certificates: list[dict] = []
            for hit in data.get("result", {}).get("hits", []):
                names = hit.get("parsed", {}).get("names", [])
                fingerprint = hit.get("fingerprint_sha256", "")
                for name in names:
                    clean = name.strip().lstrip("*.").lower()
                    if clean.endswith(f".{domain}") or clean == domain:
                        subdomains.add(clean)
                if fingerprint:
                    certificates.append({
                        "fingerprint": fingerprint,
                        "issuer": hit.get("parsed", {}).get("issuer", {}),
                        "valid_from": hit.get("parsed", {}).get("validity", {}).get("start", ""),
                        "valid_to": hit.get("parsed", {}).get("validity", {}).get("end", ""),
                    })

            return {
                "status": "ok",
                "data": {
                    "subdomains": sorted(subdomains),
                    "certificates": certificates[:50],
                },
                "error": "",
            }
        except requests.RequestException as exc:
            return {"status": "error", "data": {"subdomains": [], "certificates": []}, "error": f"Censys request failed: {exc}"}
        except Exception as exc:
            return {"status": "error", "data": {"subdomains": [], "certificates": []}, "error": f"Censys error: {exc}"}

    # ── crt.sh (Certificate Transparency) ────────────────────────────────

    def gather_crtsh(
        self, domain: str,
        timeout: int = 10, rate_limit: float = 1.0,
    ) -> dict:
        """Query crt.sh Certificate Transparency logs for subdomains.

        No API key required. Deduplicates and returns all discovered
        subdomains along with issuer information.

        Returns:
            {"status": "ok|error|skipped", "data": {...}, "error": "..."}
        """
        self._rate_limit(rate_limit)
        try:
            url = f"https://crt.sh/?q=%25.{domain}&output=json"
            resp = requests.get(url, timeout=timeout, headers={"Accept": "application/json"})
            if resp.status_code != 200:
                return {"status": "error", "data": {"subdomains": [], "issuers": []}, "error": f"crt.sh returned {resp.status_code}"}

            entries = resp.json()
            if not isinstance(entries, list):
                return {"status": "error", "data": {"subdomains": [], "issuers": []}, "error": "crt.sh returned unexpected format"}

            subdomains: set[str] = set()
            issuers: set[str] = set()
            for entry in entries:
                name_value = entry.get("name_value", "") or ""
                issuer_name = entry.get("issuer_name", "") or ""
                if issuer_name:
                    issuers.add(issuer_name)

                if "\n" in name_value:
                    for sub in name_value.split("\n"):
                        sub = sub.strip().lstrip("*.").lower()
                        if sub.endswith(f".{domain}") or sub == domain:
                            subdomains.add(sub)
                else:
                    sub = name_value.strip().lstrip("*.").lower()
                    if sub.endswith(f".{domain}") or sub == domain:
                        subdomains.add(sub)

            return {
                "status": "ok",
                "data": {
                    "subdomains": sorted(subdomains),
                    "issuers": sorted(issuers),
                },
                "error": "",
            }
        except json.JSONDecodeError as exc:
            return {"status": "error", "data": {"subdomains": [], "issuers": []}, "error": f"crt.sh JSON decode failed: {exc}"}
        except requests.RequestException as exc:
            return {"status": "error", "data": {"subdomains": [], "issuers": []}, "error": f"crt.sh request failed: {exc}"}
        except Exception as exc:
            return {"status": "error", "data": {"subdomains": [], "issuers": []}, "error": f"crt.sh error: {exc}"}

    # ── Wayback Machine ──────────────────────────────────────────────────

    def gather_wayback(
        self, domain: str,
        timeout: int = 10, rate_limit: float = 1.0,
    ) -> dict:
        """Query the Wayback Machine CDX API for historical URLs.

        Returns historic endpoints, JavaScript file URLs, and extracted
        parameters that may not appear in a current crawl.

        Returns:
            {"status": "ok|error|skipped", "data": {...}, "error": "..."}
        """
        self._rate_limit(rate_limit)
        try:
            url = (
                f"https://web.archive.org/cdx/search/cdx"
                f"?url={domain}/*&output=json&collapse=urlkey"
            )
            resp = requests.get(url, timeout=timeout, headers={"Accept": "application/json"})
            if resp.status_code != 200:
                return {"status": "error", "data": {"historic_endpoints": [], "js_urls": [], "params": []}, "error": f"Wayback returned {resp.status_code}"}

            rows = resp.json()
            if not isinstance(rows, list) or len(rows) < 2:
                return {"status": "ok", "data": {"historic_endpoints": [], "js_urls": [], "params": []}, "error": ""}

            historic_endpoints: set[str] = set()
            js_urls: set[str] = set()
            params: set[str] = set()

            # First row is the column header
            for row in rows[1:]:
                if len(row) < 3:
                    continue
                original_url = row[2] if len(row) > 2 else ""

                if not original_url:
                    continue

                # JavaScript files
                parsed = urlparse(original_url)
                if parsed.path.lower().endswith(".js"):
                    js_urls.add(original_url.split("?")[0].rstrip("/"))
                    continue

                # Extract parameters
                if parsed.query:
                    qs = parse_qs(parsed.query)
                    for param in qs:
                        if param:
                            params.add(param)

                # Normalize endpoint (drop query string)
                normalized = original_url.split("?")[0].rstrip("/")
                if normalized:
                    historic_endpoints.add(normalized)

            return {
                "status": "ok",
                "data": {
                    "historic_endpoints": sorted(historic_endpoints),
                    "js_urls": sorted(js_urls),
                    "params": sorted(params),
                },
                "error": "",
            }
        except json.JSONDecodeError as exc:
            return {"status": "error", "data": {"historic_endpoints": [], "js_urls": [], "params": []}, "error": f"Wayback JSON decode failed: {exc}"}
        except requests.RequestException as exc:
            return {"status": "error", "data": {"historic_endpoints": [], "js_urls": [], "params": []}, "error": f"Wayback request failed: {exc}"}
        except Exception as exc:
            return {"status": "error", "data": {"historic_endpoints": [], "js_urls": [], "params": []}, "error": f"Wayback error: {exc}"}

    # ── GitHub leak search ───────────────────────────────────────────────

    def gather_github(
        self, domain: str, org: str = "",
        token: str = "", timeout: int = 10, rate_limit: float = 1.0,
    ) -> dict:
        """Search GitHub code for leaked credentials, keys, and internal URLs.

        Requires a GITHUB_TOKEN for the GitHub API. Without a token the
        method returns a ``"skipped"`` status.

        Returns:
            {"status": "ok|error|skipped", "data": [...], "error": "..."}
        """
        if not token:
            return {"status": "skipped", "data": [], "error": "No GitHub token configured"}

        query_parts = [domain]
        if org:
            query_parts.append(f"org:{org}")

        # Search for the domain in code
        query = " ".join(query_parts)
        results: list[dict] = []

        self._rate_limit(rate_limit)
        try:
            headers = {
                "Accept": "application/vnd.github.v3+json",
                "Authorization": f"token {token}",
            }
            url = "https://api.github.com/search/code"
            params = {
                "q": query,
                "per_page": 100,
            }

            resp = requests.get(url, params=params, timeout=timeout, headers=headers)
            if resp.status_code == 403:
                return {"status": "error", "data": [], "error": "GitHub API rate limited or token invalid"}
            if resp.status_code != 200:
                return {"status": "error", "data": [], "error": f"GitHub returned {resp.status_code}"}

            data = resp.json()
            items = data.get("items", [])

            for item in items:
                repo_name = item.get("repository", {}).get("full_name", "unknown")
                file_path = item.get("path", "unknown")
                file_url = item.get("html_url", "")
                repo_url = item.get("repository", {}).get("html_url", "")

                # Check if this is a known secret/config file
                is_secret_file = any(
                    file_path.lower().endswith(sf) or f"/{sf}" in file_path.lower()
                    for sf in self.GITHUB_SECRET_FILES
                )

                # Fetch raw content for pattern matching
                raw_url = item.get("git_url", "")
                context = ""
                matched_patterns: list[str] = []

                try:
                    raw_resp = requests.get(
                        item.get("url", ""),
                        timeout=timeout,
                        headers=headers,
                    )
                    if raw_resp.status_code == 200:
                        raw_data = raw_resp.json()
                        content_b64 = raw_data.get("content", "")
                        if content_b64:
                            import base64
                            try:
                                decoded = base64.b64decode(content_b64).decode("utf-8", errors="replace")
                            except Exception:
                                decoded = ""

                            # Run all leak patterns
                            for pattern in self.GITHUB_LEAK_PATTERNS:
                                for match in pattern.finditer(decoded):
                                    matched_patterns.append(match.group(0)[:120])
                                    # Build context snippet
                                    start = max(0, match.start() - 60)
                                    end = min(len(decoded), match.end() + 60)
                                    context = decoded[start:end]

                            if not matched_patterns and is_secret_file:
                                context = decoded[:500]
                                matched_patterns.append(f"[Secret file: {file_path}]")

                            if matched_patterns:
                                # Deduplicate patterns
                                seen = set()
                                unique_patterns: list[str] = []
                                for p in matched_patterns:
                                    if p not in seen:
                                        seen.add(p)
                                        unique_patterns.append(p)

                                results.append({
                                    "url": file_url,
                                    "file": file_path,
                                    "repo": repo_name,
                                    "repo_url": repo_url,
                                    "pattern": unique_patterns[0],
                                    "all_patterns": unique_patterns,
                                    "context": context[:500],
                                })
                except requests.RequestException:
                    # If we can't fetch the raw content, still report secret files by name
                    if is_secret_file:
                        results.append({
                            "url": file_url,
                            "file": file_path,
                            "repo": repo_name,
                            "repo_url": repo_url,
                            "pattern": f"[Potential secret file: {file_path}]",
                            "all_patterns": [],
                            "context": "",
                        })

            return {
                "status": "ok",
                "data": results,
                "error": "",
            }
        except requests.RequestException as exc:
            return {"status": "error", "data": [], "error": f"GitHub request failed: {exc}"}
        except Exception as exc:
            return {"status": "error", "data": [], "error": f"GitHub error: {exc}"}
