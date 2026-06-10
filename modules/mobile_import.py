"""Mobile API mode — imports Burp Suite and Charles Proxy exports."""

import json
import os
import re
import xml.etree.ElementTree as ET
from base64 import b64decode
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, urlparse


@dataclass
class ImportResult:
    urls: list[str] = field(default_factory=list)
    api_endpoints: list[dict] = field(default_factory=list)
    parameters: set[str] = field(default_factory=set)
    auth_headers: dict[str, str] = field(default_factory=dict)
    custom_headers: dict[str, str] = field(default_factory=dict)
    certificate_pinning_hints: list[str] = field(default_factory=list)
    device_fingerprints: list[dict] = field(default_factory=list)
    app_package_name: str = ""


MOBILE_HEADER_PATTERNS = re.compile(
    r"^(X-Device-ID|X-Device-Token|X-Device-OS|X-Platform|X-App-Version|"
    r"X-App-Build|X-App-Name|X-Installation-ID|X-Android-ID|"
    r"X-iOS-ID|X-Device-Model|X-Device-Brand)$",
    re.IGNORECASE,
)

AUTH_HEADER_NAMES = {"authorization", "x-authorization", "bearer", "token",
                     "x-api-key", "x-auth-token", "api-key", "apikey"}

PINNING_HINTS = re.compile(
    r"(ssl.?pinning.?bypass|frida|okhttp|certificate.?pinning|"
    r"xposed|objection|trust.?all.?certificates|"
    r"nopin|disable.?ssl|unsafe.?okhttp)",
    re.IGNORECASE,
)

PACKAGE_PATTERNS = re.compile(
    r"(com\.\w[\w.]*\w|[a-z]+\.[a-z]+\.[a-z]+[\w.]*)",
    re.IGNORECASE,
)


class MobileApiImporter:
    def import_burp_xml(self, filepath: str) -> ImportResult:
        result = ImportResult()
        tree = ET.parse(filepath)
        root = tree.getroot()
        for item in root.findall(".//item"):
            request_el = item.find("request")
            response_el = item.find("response")
            url_el = item.find("url")
            if url_el is not None and url_el.text:
                url = url_el.text.strip()
            elif request_el is not None and request_el.text:
                url = self._extract_url_from_request(request_el.text)
            else:
                continue
            if url and url not in result.urls:
                result.urls.append(url)
            if request_el is not None and request_el.text:
                endpoint = self._parse_burp_request(request_el.text, url)
                if endpoint:
                    result.api_endpoints.append(endpoint)
                    for p in endpoint.get("params", {}):
                        result.parameters.add(p)
                    self._extract_headers_from_endpoint(endpoint, result)
        self._detect_device_fingerprints(result)
        self._detect_certificate_pinning(result)
        self._detect_package_name(result)
        return result

    def import_charles_session(self, filepath: str) -> ImportResult:
        result = ImportResult()
        tree = ET.parse(filepath)
        root = tree.getroot()
        for req_el in root.findall(".//request"):
            method_el = req_el.find("method")
            url_el = req_el.find("url")
            header_els = req_el.findall("headers/header")
            if url_el is None or url_el.text is None:
                continue
            url = url_el.text.strip()
            method = method_el.text.strip().upper() if method_el is not None else "GET"
            if url not in result.urls:
                result.urls.append(url)
            headers = {}
            for h in header_els:
                name = (h.get("name") or h.findtext("name") or "").strip()
                value = (h.get("value") or h.findtext("value") or "").strip()
                if name and value:
                    headers[name] = value
            parsed = urlparse(url)
            params = {}
            if parsed.query:
                params = {k: v[0] if len(v) == 1 else v for k, v in parse_qs(parsed.query).items()}
            endpoint = {
                "method": method,
                "url": url,
                "headers": headers,
                "params": params,
                "response_body_preview": "",
            }
            result.api_endpoints.append(endpoint)
            for p in params:
                result.parameters.add(p)
            self._extract_headers_from_endpoint(endpoint, result)
        self._detect_device_fingerprints(result)
        self._detect_certificate_pinning(result)
        self._detect_package_name(result)
        return result

    def analyze_mobile_headers(self, headers: dict) -> dict:
        result = {
            "device_id": "",
            "app_version": "",
            "platform": "",
            "device_token": "",
            "authorization_type": "",
            "custom_auth": {},
        }
        for name, value in headers.items():
            lower = name.lower()
            if lower == "x-device-id":
                result["device_id"] = value
            elif lower == "x-app-version":
                result["app_version"] = value
            elif lower in ("x-platform", "x-device-os"):
                result["platform"] = value
            elif lower == "x-device-token":
                result["device_token"] = value
            elif lower == "authorization":
                if value.startswith("Bearer "):
                    result["authorization_type"] = "bearer"
                elif value.startswith("Basic "):
                    result["authorization_type"] = "basic"
                elif value.startswith("Digest "):
                    result["authorization_type"] = "digest"
                else:
                    result["authorization_type"] = "custom"
            elif lower not in (
                "host", "connection", "content-type", "content-length", "accept",
                "accept-encoding", "accept-language", "user-agent", "cache-control",
                "pragma", "upgrade-insecure-requests", "sec-fetch-dest",
                "sec-fetch-mode", "sec-fetch-site", "sec-fetch-user",
                "referer", "origin", "cookie",
            ):
                result["custom_auth"][name] = value
        return result

    def normalize_auth_headers(self, headers: dict) -> dict:
        normalized = {}
        for name, value in headers.items():
            lower = name.lower()
            if lower in AUTH_HEADER_NAMES:
                if value.startswith("Bearer "):
                    normalized["type"] = "bearer"
                    normalized["token"] = value[7:]
                elif value.startswith("Basic "):
                    normalized["type"] = "basic"
                    try:
                        decoded = b64decode(value[6:]).decode("utf-8", errors="replace")
                        if ":" in decoded:
                            parts = decoded.split(":", 1)
                            normalized["credentials"] = {
                                "username": parts[0],
                                "password": parts[1],
                            }
                    except Exception:
                        normalized["credentials"] = {"raw": value[6:]}
                elif value.startswith("Digest "):
                    normalized["type"] = "digest"
                    normalized["raw"] = value
                else:
                    normalized["type"] = "api_key"
                    normalized["key"] = lower
                    normalized["value"] = value
                break
        if not normalized:
            normalized["type"] = "none"
        return normalized

    def injection_point_candidates(self, import_result: ImportResult) -> list[dict]:
        candidates = []
        for ep in import_result.api_endpoints:
            url = ep.get("url", "")
            method = ep.get("method", "GET")
            params = ep.get("params", {})
            headers = ep.get("headers", {})
            name_tokens = re.split(r"[/_.\-?&=]", urlparse(url).path.lower())
            injection_types = self._classify_injection_points(method, params, name_tokens, headers)
            if injection_types:
                candidates.append({
                    "url": url,
                    "method": method,
                    "params": params,
                    "injection_types": injection_types,
                    "score": len(injection_types),
                })
        candidates.sort(key=lambda c: c["score"], reverse=True)
        return candidates

    @staticmethod
    def _extract_url_from_request(raw: str) -> str:
        lines = raw.strip().split("\n")
        if lines:
            first_line = lines[0].strip()
            parts = first_line.split()
            for part in parts:
                if part.startswith(("http://", "https://")):
                    return part
                if part.startswith("/") and len(parts) >= 2:
                    host_line = next((l for l in lines if l.lower().startswith("host:")), None)
                    if host_line:
                        host = host_line.split(":", 1)[1].strip()
                        scheme = "https" if ":443" in host else "http"
                        return f"{scheme}://{host}{part}"
        return ""

    @staticmethod
    def _parse_burp_request(raw: str, url: str) -> dict | None:
        try:
            text = b64decode(raw).decode("utf-8", errors="replace")
        except Exception:
            text = raw
        lines = text.strip().split("\n")
        if not lines:
            return None
        first_line_parts = lines[0].strip().split()
        method = first_line_parts[0] if len(first_line_parts) > 0 else "GET"
        path = first_line_parts[1] if len(first_line_parts) > 1 else "/"
        headers = {}
        body = ""
        header_done = False
        body_lines: list[str] = []
        for line in lines[1:]:
            stripped = line.strip()
            if not header_done and stripped == "":
                header_done = True
                continue
            if not header_done and ":" in stripped:
                k, v = stripped.split(":", 1)
                headers[k.strip()] = v.strip()
            elif header_done:
                body_lines.append(stripped)
        if body_lines:
            body = "\n".join(body_lines)
        parsed = urlparse(url if url else path)
        params = {}
        if parsed.query:
            params = {k: v[0] if len(v) == 1 else v for k, v in parse_qs(parsed.query).items()}
        if body and method in ("POST", "PUT", "PATCH"):
            try:
                body_params = parse_qs(body)
                for k, v in body_params.items():
                    params[k] = v[0] if len(v) == 1 else v
            except Exception:
                pass
        return {
            "method": method,
            "url": url,
            "headers": headers,
            "params": params,
            "response_body_preview": "",
        }

    @staticmethod
    def _extract_headers_from_endpoint(endpoint: dict, result: ImportResult) -> None:
        headers = endpoint.get("headers", {})
        for name, value in headers.items():
            lower = name.lower()
            if lower in AUTH_HEADER_NAMES:
                result.auth_headers[name] = value
            elif MOBILE_HEADER_PATTERNS.match(name):
                result.custom_headers[name] = value

    @staticmethod
    def _detect_device_fingerprints(result: ImportResult) -> None:
        fingerprints = []
        for h_name, h_value in result.custom_headers.items():
            lower = h_name.lower()
            if lower == "x-device-id":
                fingerprints.append({"type": "device_id", "value": h_value})
            elif lower == "x-device-model":
                fingerprints.append({"type": "model", "value": h_value})
            elif lower == "x-device-brand":
                fingerprints.append({"type": "brand", "value": h_value})
            elif lower == "x-platform":
                fingerprints.append({"type": "platform", "value": h_value})
            elif lower == "x-app-version":
                fingerprints.append({"type": "app_version", "value": h_value})
        result.device_fingerprints = fingerprints

    @staticmethod
    def _detect_certificate_pinning(result: ImportResult) -> None:
        hints = set()
        for ep in result.api_endpoints:
            for h_name, h_value in ep.get("headers", {}).items():
                if PINNING_HINTS.search(h_name) or PINNING_HINTS.search(h_value):
                    hints.add(f"{h_name}: {h_value[:200]}")
            for p_name, p_value in ep.get("params", {}).items():
                str_val = str(p_value)
                if PINNING_HINTS.search(p_name) or PINNING_HINTS.search(str_val):
                    hints.add(f"{p_name}={str_val[:200]}")
        result.certificate_pinning_hints = sorted(hints)

    @staticmethod
    def _detect_package_name(result: ImportResult) -> None:
        for url in result.urls:
            match = PACKAGE_PATTERNS.search(url)
            if match:
                result.app_package_name = match.group(1)
                return
        for ep in result.api_endpoints:
            for h_name, h_value in ep.get("headers", {}).items():
                match = PACKAGE_PATTERNS.search(h_value)
                if match:
                    result.app_package_name = match.group(1)
                    return

    @staticmethod
    def _classify_injection_points(method: str, params: dict, name_tokens: list[str],
                                    headers: dict) -> list[str]:
        types: list[str] = []
        if method in ("GET", "POST", "PUT", "PATCH") and params:
            id_tokens = {"id", "uid", "uuid", "user", "account", "profile", "token"}
            query_tokens = {"q", "search", "query", "keyword", "filter", "sort"}
            action_tokens = {"delete", "update", "create", "edit", "modify", "patch"}
            if any(t in id_tokens for t in name_tokens):
                types.append("idor")
                types.append("authorization")
            if any(t in query_tokens for t in name_tokens):
                types.append("injection")
            if any(t in action_tokens for t in name_tokens):
                types.append("authorization")
            for p_name in params:
                lower = p_name.lower()
                if lower in ("file", "path", "document", "download", "upload"):
                    types.append("path_traversal")
                if lower in ("url", "redirect", "next", "return", "goto"):
                    types.append("open_redirect")
                if lower in ("cmd", "exec", "command", "shell", "run"):
                    types.append("command_injection")
            if "authorization" in headers or "Authorization" in headers:
                types.append("authenticated")
        return list(set(types))
