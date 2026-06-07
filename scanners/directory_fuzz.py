"""
DirectoryFuzzScanner — discovers common directories and files via path fuzzing.

Lifecycle:
  DETECTED:   HTTP 200 (content accessible), 401/403 (access-controlled)
  VALIDATED:  HTTP 200 with directory listing
  EXPLOITABLE: (not applicable)
  VERIFIED:   (not applicable)

Maturity: Level 1 (Detection only)
"""

from urllib.parse import urlparse

from modules.utils import (
    safe_get, finding, log, Colors, _build_curl,
    VerificationStage,
)
from scanners.base import ScannerBase

COMMON_DIRFUZZ_PATHS = [
    "admin/", "login/", "dashboard/", "config/", "backup/", "uploads/",
    "portal/", "server-status", "shell/", "wp-admin/", "wp-login.php",
    "phpmyadmin/", "vendor/", ".git/", ".env", ".gitignore",
]


class DirectoryFuzzScanner(ScannerBase):
    SCANNER_NAME = "dirb"
    SCANNER_MATURITY = 1
    TARGET_LEVEL = True
    SCANNER_ORDER = 20

    def scan(self, target_urls: list[str] | None = None) -> list[dict]:
        urls = self.recon.get("urls", [])
        base = urlparse(self.base_url).netloc
        if not base:
            return self._get_findings()
        paths = list(COMMON_DIRFUZZ_PATHS)
        custom_wordlist = self.config.get("wordlist")
        if custom_wordlist:
            try:
                with open(custom_wordlist, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line and line not in paths:
                            paths.append(line)
            except Exception:
                pass
        for path in paths:
            try:
                target_url = f"{self.base_url}/{path.lstrip('/')}"
                if not self._in_scope(target_url):
                    continue
                resp = safe_get(self.session, target_url, self.timeout, raise_for_status=False)
                if resp and resp.status_code == 200:
                    title = "Exposed Common Path"
                    details = f"Accessible path found: {target_url}"
                    if any(kw in resp.text.lower() for kw in ["index of /", "directory listing", "parent directory"]):
                        title = "Directory Listing Enabled"
                        details = f"Index listing detected at {target_url}"
                    f = finding(
                        vuln_type=title,
                        url=target_url,
                        severity="medium",
                        details=details,
                        evidence=f"HTTP {resp.status_code}",
                        request=_build_curl("GET", target_url, dict(self.session.headers), cookies=dict(self.session.cookies)),
                        response_excerpt=resp.text[:500],
                        steps_to_reproduce=[f"Send request to {target_url}", "Observe HTTP 200 response"],
                        verification_stage=VerificationStage.VALIDATED.value,
                    )
                    if f:
                        self._add_finding(f)
                    log(f"  [DIRB] {target_url}", Colors.YELLOW, verbose_only=True, verbose=self.verbose)
                elif resp and resp.status_code == 403:
                    f = finding(
                        vuln_type="Forbidden Path (Access Control Exists)",
                        url=target_url,
                        severity="info",
                        details=f"Path exists but is access-controlled (HTTP 403): {target_url}",
                        evidence="HTTP 403",
                        request=_build_curl("GET", target_url, dict(self.session.headers), cookies=dict(self.session.cookies)),
                        response_excerpt=resp.text[:500],
                        steps_to_reproduce=[f"Send request to {target_url}", "Observe HTTP 403 response"],
                        verification_stage=VerificationStage.DETECTED.value,
                    )
                    if f:
                        self._add_finding(f)
                    log(f"  [DIRB 403] {target_url}", Colors.YELLOW, verbose_only=True, verbose=self.verbose)
                elif resp and resp.status_code == 401:
                    f = finding(
                        vuln_type="Authentication Required Path",
                        url=target_url,
                        severity="info",
                        details=f"Path requires authentication (HTTP 401): {target_url}",
                        evidence="HTTP 401",
                        request=_build_curl("GET", target_url, dict(self.session.headers), cookies=dict(self.session.cookies)),
                        response_excerpt=resp.text[:500],
                        steps_to_reproduce=[f"Send request to {target_url}", "Observe HTTP 401 response"],
                        verification_stage=VerificationStage.DETECTED.value,
                    )
                    if f:
                        self._add_finding(f)
                    log(f"  [DIRB 401] {target_url}", Colors.YELLOW, verbose_only=True, verbose=self.verbose)
            except Exception:
                continue
        return self._get_findings()
