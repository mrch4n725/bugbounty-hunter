"""
ScannerModuleBase — lightweight base for scanner modules that don't need
the full VulnScanner lifecycle (ApiScanner, IdorScanner).

Provides shared utility methods previously inherited from VulnScanner.
"""

import hashlib
import os
import threading
from typing import Any, Optional

from models.finding import Finding
from modules.utils import (
    make_session, finding, log, Colors, url_in_scope, _build_curl,
    VerificationStage, safe_cookies_dict,
)
from engines import ValidationEngine, EvidenceEngine


class ScannerModuleBase:
    """Minimal base for scanner modules. Subclasses provide scan logic."""

    def __init__(self, config: dict, recon_data: dict, container=None):
        self.config    = config
        self.recon     = recon_data
        self.container = container
        self.timeout   = config.get("timeout", 10)
        self.verbose   = config.get("verbose", False)
        self.session   = make_session(config)
        self.base_url  = config.get("target", "").rstrip("/")
        self._lock     = threading.Lock()
        self._container = container

    def _in_scope(self, url: str) -> bool:
        return url_in_scope(url, self.config)

    def _append_finding(self, findings_list: list, f: Optional[Finding]) -> None:
        if f:
            findings_list.append(f)

    def _record_confirmed(self, findings_list: list, vuln_type: str, url: str,
                          severity: str, details: str, evidence: str,
                          method: str, request_data: Any = None,
                          response_excerpt: str = "",
                          steps_to_reproduce: Optional[list] = None,
                          parameter: Optional[str] = None) -> None:
        request_str = ""
        if method and url:
            req_headers = dict(self.session.headers) if hasattr(self, 'session') else {}
            req_cookies = safe_cookies_dict(self.session.cookies) if hasattr(self, 'session') else {}
            if request_data is not None:
                import json
                data_str = json.dumps(request_data) if isinstance(request_data, (dict, list)) else str(request_data)
                request_str = _build_curl(method, url, req_headers, data=data_str, cookies=req_cookies)
            else:
                request_str = _build_curl(method, url, req_headers, cookies=req_cookies)
        f = finding(
            vuln_type=vuln_type, url=url, severity=severity,
            details=details, evidence=evidence,
            verification_stage=VerificationStage.VALIDATED.value,
            request=request_str,
            response_excerpt=response_excerpt or "",
            steps_to_reproduce=steps_to_reproduce or [f"Send {method} request to {url}"],
            parameter=parameter or "",
        )
        self._append_finding(findings_list, f)

    def _deduplicate(self, findings_list: list[Finding]) -> list[Finding]:
        seen = set()
        result = []
        for f in findings_list:
            fp = f.get("fingerprint", "") or hashlib.sha256(
                f"{f.get('vuln_type', '')}:{f.get('url', '')}:{f.get('parameter', '')}".encode()
            ).hexdigest()
            if fp not in seen:
                seen.add(fp)
                result.append(f)
        return result

    @staticmethod
    def _inject_param(url: str, param: str, payload: str) -> str:
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        try:
            parsed = urlparse(url)
            qs = parse_qs(parsed.query, keep_blank_values=True)
            qs[param] = [payload]
            new_query = urlencode(qs, doseq=True)
            return urlunparse(parsed._replace(query=new_query))
        except Exception:
            return url

    def _get_module_param(self, module_name: str, key: str, default=None):
        return self.config.get("module_params", {}).get(module_name, {}).get(key, default)

    def _load_payloads(self, payload_type: str) -> Any:
        yaml_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)), "payloads", f"{payload_type}.yaml"
        )
        list_types = {"lfi", "ssrf"}
        try:
            import yaml
            with open(yaml_path, "r") as f:
                loaded = yaml.safe_load(f)
            if loaded and "payloads" in loaded:
                raw = loaded["payloads"]
                if isinstance(raw, dict) and payload_type in list_types:
                    flat = []
                    for cat in raw.values():
                        if isinstance(cat, list):
                            flat.extend(cat)
                    if flat:
                        return flat
                if isinstance(raw, (dict, list)):
                    return raw
        except (FileNotFoundError, ImportError):
            pass

        fallbacks = {
            "sqli": {},
            "xss": {},
            "lfi": [],
            "ssrf": [],
            "xxe": {},
            "ssti": {},
            "cmdi": {},
        }
        fb = fallbacks.get(payload_type, [])
        if self.verbose:
            log(f"[*] Payload YAML for '{payload_type}' not found or empty — using hardcoded fallback",
                Colors.YELLOW, verbose_only=True, verbose=self.verbose)
        return fb
