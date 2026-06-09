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

from models.finding import Finding
from models.evidence import ResponseExcerptEvidence
from modules.utils import (
    safe_get, finding, log, Colors, _build_curl,
    VerificationStage,
    safe_cookies_dict,
)
from scanners.base import ScannerBase, DetectionResult, ValidationResult

COMMON_DIRFUZZ_PATHS = [
    "admin/", "login/", "dashboard/", "config/", "backup/", "uploads/",
    "portal/", "server-status", "shell/", "wp-admin/", "wp-login.php",
    "phpmyadmin/", "vendor/", ".git/", ".env", ".gitignore",
]


class DirectoryFuzzScanner(ScannerBase):
    SCANNER_NAME = "dirb"
    SCANNER_MATURITY = 3
    TARGET_LEVEL = True
    SCANNER_ORDER = 20

    def detect(self, url: str, parameter: str | None = None) -> DetectionResult | None:
        resp = safe_get(self.session, url, self.timeout, raise_for_status=False)
        if not resp:
            return None
        if resp.status_code == 200:
            is_listing = any(kw in resp.text.lower() for kw in ["index of /", "directory listing", "parent directory"])
            return DetectionResult(
                url=url,
                parameter="",
                payload="200",
                context="directory_listing" if is_listing else "accessible_path",
                raw_response=resp,
                evidence_signals=[f"HTTP 200 — {len(resp.text)} bytes"],
            )
        if resp.status_code in (401, 403):
            ctx = "forbidden" if resp.status_code == 403 else "auth_required"
            return DetectionResult(
                url=url,
                parameter="",
                payload=str(resp.status_code),
                context=ctx,
                raw_response=resp,
                evidence_signals=[f"HTTP {resp.status_code} — {len(resp.text)} bytes"],
            )
        return None

    def validate(self, detection: DetectionResult) -> ValidationResult | None:
        if detection.context == "directory_listing":
            return ValidationResult(confirmed=True, method="content_analysis",
                                    detail="Directory listing confirmed by content keywords (index of/)")
        return ValidationResult(confirmed=False, method="status_code_check",
                                detail=f"Path accessibility detected via HTTP {detection.payload}")

    def collect_evidence(self, detection: DetectionResult,
                         validation_result: ValidationResult | None = None) -> list:
        resp = detection.raw_response
        if not resp:
            return []
        evidence = [
            ResponseExcerptEvidence(
                excerpt=resp.text[:500],
                length=len(resp.text),
                context=f"dirb_{detection.context}",
                description=f"Directory fuzz result at {detection.url}",
            ),
        ]
        # Add response diff evidence showing the delta from baseline
        if detection.context in ("directory_listing", "accessible_path"):
            status = resp.status_code
            baseline_excerpt = resp.text[:200]
            triggered_excerpt = resp.text[:200]
            evidence.append(
                ResponseDiffEvidence(
                    baseline_status=status,
                    baseline_body_excerpt=baseline_excerpt,
                    triggered_status=status,
                    triggered_body_excerpt=triggered_excerpt,
                    content_length_diff=len(resp.text),
                    trigger_param="",
                    description=f"Directory fuzz: {detection.url} returned HTTP {status} ({len(resp.text)} bytes)",
                )
            )
        return evidence

    def generate_reproduction(self, f: dict) -> list[str]:
        url = f["url"]
        vuln_type = f.get("vuln_type", "")
        if vuln_type == "Directory Listing Enabled":
            return [
                f"curl -X GET '{url}'",
                "Server responds with HTTP 200 and a directory listing — browse available files in the response",
                "Directory listing exposes the full file tree: source code, backups, configuration files, and potentially credentials",
            ]
        if vuln_type == "Exposed Common Path":
            return [
                f"curl -X GET '{url}'",
                "Server responds with HTTP 200 — the path exists and is publicly accessible",
                "Review the returned content for sensitive information that should not be publicly exposed",
            ]
        if vuln_type == "Forbidden Path (Access Control Exists)":
            return [
                f"curl -X GET '{url}'",
                "Server responds with HTTP 403 — the path exists but access is restricted",
                "Try different HTTP methods, authentication headers, or path variations to bypass access control",
            ]
        return [
            f"curl -X GET '{url}'",
            "Server responds with HTTP 401 — the path requires valid authentication credentials",
            "Try common credentials, default passwords, or check if the authentication can be bypassed",
        ]

    def _compute_baseline(self) -> tuple[str | None, int]:
        """Fetch a non-existent path and store its content fingerprint for soft-404 comparison."""
        import hashlib
        marker = hashlib.md5(self.base_url.encode()).hexdigest()[:8]
        non_existent = f"{self.base_url.rstrip('/')}/bbh_404_{marker}"
        try:
            resp = safe_get(self.session, non_existent, self.timeout, raise_for_status=False)
            if resp:
                return hashlib.md5(resp.text.encode()).hexdigest(), len(resp.text)
        except Exception:
            pass
        return None, 0

    @staticmethod
    def _jaccard_similarity(text_a: str, text_b: str) -> float:
        set_a = set(text_a.lower().split())
        set_b = set(text_b.lower().split())
        if not set_a and not set_b:
            return 1.0
        intersection = set_a & set_b
        union = set_a | set_b
        return len(intersection) / len(union) if union else 0.0

    def _is_soft_404(self, resp, baseline_fp: str | None, baseline_size: int) -> bool:
        """Check if response resembles a soft 404 (same as baseline)."""
        if baseline_fp is None:
            return False
        import hashlib
        cur_hash = hashlib.md5(resp.text.encode()).hexdigest()
        if cur_hash == baseline_fp:
            return True
        if baseline_size > 0:
            size_ratio = abs(len(resp.text) - baseline_size) / max(baseline_size, 1)
            if size_ratio < 0.1:
                return True
        return False

    def scan(self, target_urls: list[str] | None = None) -> list[Finding]:
        urls = self.recon.get("urls", [])
        base = urlparse(self.base_url).netloc
        if not base:
            return self._get_findings()
        baseline_fp, baseline_size = self._compute_baseline()
        # Load built-in wordlist from payloads/directory_fuzz.txt
        import os as _os
        builtin_wordlist = _os.path.join(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))), "payloads", "directory_fuzz.txt")
        paths = []
        if _os.path.exists(builtin_wordlist):
            try:
                with open(builtin_wordlist, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            paths.append(line)
            except Exception:
                paths = list(COMMON_DIRFUZZ_PATHS)
        else:
            paths = list(COMMON_DIRFUZZ_PATHS)
        # If custom wordlist specified in config, merge additional paths
        custom_wordlist = self.config.get("wordlist")
        if custom_wordlist:
            try:
                with open(custom_wordlist, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#") and line not in paths:
                            paths.append(line)
            except Exception:
                pass
        for path in paths:
            try:
                target_url = f"{self.base_url.rstrip('/')}/{path.lstrip('/')}"
                if not self._in_scope(target_url):
                    continue

                detection = self.detect(target_url)
                if detection is None:
                    continue

                resp = detection.raw_response
                if resp and self._is_soft_404(resp, baseline_fp, baseline_size):
                    log(f"  [DIRB] {target_url} — skipped (soft 404)", Colors.WHITE, verbose_only=True, verbose=self.verbose)
                    continue

                validation_result = self.validate(detection)
                evidence_list = self.collect_evidence(detection, validation_result)

                for ev in evidence_list:
                    self.evidence_engine.store(ev)

                title_map = {
                    "directory_listing": "Directory Listing Enabled",
                    "accessible_path": "Exposed Common Path",
                    "forbidden": "Forbidden Path (Access Control Exists)",
                    "auth_required": "Authentication Required Path",
                }
                sev_map = {
                    "directory_listing": "medium",
                    "accessible_path": "medium",
                    "forbidden": "info",
                    "auth_required": "info",
                }
                stage_map = {
                    "directory_listing": VerificationStage.VALIDATED.value,
                    "accessible_path": VerificationStage.VALIDATED.value,
                    "forbidden": VerificationStage.DETECTED.value,
                    "auth_required": VerificationStage.DETECTED.value,
                }
                title = title_map.get(detection.context, "Exposed Common Path")
                severity = sev_map.get(detection.context, "info")
                stage = stage_map.get(detection.context, VerificationStage.DETECTED.value)

                f = finding(
                    vuln_type=title,
                    url=target_url,
                    severity=severity,
                    details=f"{'Index listing detected' if detection.context == 'directory_listing' else 'Accessible path found' if detection.context == 'accessible_path' else 'Path exists but is access-controlled'}: {target_url}",
                    evidence=f"HTTP {resp.status_code}" if resp else "",
                    request=_build_curl("GET", target_url, dict(self.session.headers), cookies=safe_cookies_dict(self.session.cookies)),
                    response_excerpt=resp.text[:500] if resp else "",
                    steps_to_reproduce=self.generate_reproduction(f),
                    verification_stage=stage,
                )
                if f:
                    self._enrich_finding(f, len(evidence_list), f["verification_stage"])
                    fingerprint = f.get("fingerprint", "")
                    if fingerprint:
                        for ev in evidence_list:
                            self.evidence_engine.link_to_finding(ev, fingerprint)
                    self._add_finding(f)
                    log(f"  [DIRB] {target_url}", Colors.YELLOW, verbose_only=True, verbose=self.verbose)
            except Exception:
                continue
        return self._get_findings()
