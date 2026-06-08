"""
OpenAPIScanner — discovers exposed OpenAPI/Swagger specification files.

Lifecycle:
  DETECTED:   Spec file endpoint returns HTTP 200
  VALIDATED:  Body parses as valid JSON/YAML OpenAPI spec with paths
  EXPLOITABLE: (not applicable)
  VERIFIED:   (not applicable)

Maturity: Level 2 (Detect + Validate)
"""

import json
import re
from urllib.parse import urljoin

from modules.utils import (
    safe_get, finding, log, Colors, _build_curl,
    VerificationStage,
)
from scanners.base import ScannerBase
from models.evidence import HttpRequestEvidence, ResponseExcerptEvidence


SPEC_PATHS = [
    "/swagger.json", "/api/swagger.json",
    "/swagger/v1/swagger.json", "/swagger/v2/swagger.json",
    "/openapi.json", "/api/openapi.json",
    "/api-docs", "/v1/api-docs", "/v2/api-docs", "/v3/api-docs",
    "/swagger-ui.html", "/swagger-resources",
    "/api/swagger-ui.html", "/api/swagger-resources",
    "/doc", "/api/doc", "/docs", "/api/docs",
    "/spec", "/api/spec",
    "/swagger.yaml", "/api/swagger.yaml",
    "/openapi.yaml", "/api/openapi.yaml",
]


class OpenAPIScanner(ScannerBase):
    SCANNER_NAME = "openapi"
    SCANNER_MATURITY = 2
    TARGET_LEVEL = True
    SCANNER_ORDER = 10

    def scan(self, target_urls: list[str] | None = None) -> list[dict]:
        discovered: set[str] = set()
        for sp in SPEC_PATHS:
            url = self.base_url + sp
            if not self._in_scope(url):
                continue
            try:
                resp = safe_get(self.session, url, self.timeout)
                if not resp:
                    continue
                paths = self._extract_paths(resp, url)
                if paths:
                    discovered.update(paths)
                    self._emit_finding(url, sp, resp, paths)
            except Exception:
                continue

        if discovered:
            in_scope = [ep for ep in discovered if self._in_scope(ep)]
            if "urls" not in self.recon:
                self.recon["urls"] = []
            existing = set(self.recon["urls"])
            new_eps = [ep for ep in in_scope if ep not in existing]
            self.recon["urls"].extend(new_eps)
            log(f"  [OpenAPI] {len(new_eps)} endpoint(s) injected from spec files", Colors.GREEN)

        return self._get_findings()

    def _extract_paths(self, resp, source_url: str) -> list[str]:
        if source_url.endswith((".json", "/api-docs")) or "swagger-resources" in source_url:
            try:
                spec = resp.json()
                return self._parse_spec_paths(spec)
            except (json.JSONDecodeError, AttributeError):
                pass
        elif source_url.endswith((".yaml", ".yml")):
            try:
                import yaml
                spec = yaml.safe_load(resp.text)
                if isinstance(spec, dict):
                    return self._parse_spec_paths(spec)
            except Exception:
                pass
        else:
            found = re.findall(r'"(/?(?:api|v[0-9]+)/[^"]+)"', resp.text)
            return [
                urljoin(source_url, p)
                for p in found
            ]
        return []

    @staticmethod
    def _parse_spec_paths(spec: dict) -> list[str]:
        raw = spec.get("paths", {}) or spec.get("apis", {}) or {}
        if isinstance(raw, dict):
            return list(raw.keys())
        return []

    def _emit_finding(self, url: str, spec_path: str, resp, paths: list[str]) -> None:
        curl_cmd = _build_curl("GET", url, dict(self.session.headers), cookies=dict(self.session.cookies))
        resp_excerpt = resp.text[:500]

        req_ev = HttpRequestEvidence(
            method="GET",
            url=url,
            curl_command=curl_cmd,
        )
        resp_ev = ResponseExcerptEvidence(
            excerpt=resp_excerpt,
            length=len(resp.text),
            context="openapi_spec_discovered",
        )

        f = finding(
            vuln_type="OpenAPI Specification Discovered",
            url=url,
            severity="info",
            details=f"Exposed spec file at {spec_path} reveals {len(paths)} endpoint(s)",
            evidence=resp_excerpt,
            request=curl_cmd,
            response_excerpt=resp_excerpt,
            steps_to_reproduce=[
                f"Send GET request to {url} — the server returns an OpenAPI/Swagger specification document",
                f"Parse the spec to discover {len(paths)} API endpoint(s) with request/response schemas",
                "Use the exposed spec to craft targeted attacks against all documented API endpoints without manual reverse engineering",
            ],
            verification_stage=VerificationStage.VALIDATED.value,
        )
        if f:
            fingerprint = f.get("fingerprint", "")
            if fingerprint:
                self.evidence_engine.store(req_ev)
                self.evidence_engine.store(resp_ev)
                self.evidence_engine.link_to_finding(req_ev, fingerprint)
                self.evidence_engine.link_to_finding(resp_ev, fingerprint)
            self._add_finding(f)
            log(f"  [OpenAPI] {spec_path} @ {url[:80]}", Colors.GREEN, verbose_only=True, verbose=self.verbose)
