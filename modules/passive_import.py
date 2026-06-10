"""Passive analysis mode — reads HAR files, Burp Suite XML exports,
and Charles Proxy session files.

Usage:
    result = BurpXmlImporter.import_xml("export.xml")
    result = HarImporter.import_har("capture.har")
    result = CharlesImporter.import_session("charles.xml")
"""

import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse

from modules.utils import log, Colors


@dataclass
class ImportResult:
    urls: list[str] = field(default_factory=list)
    parameters: set[str] = field(default_factory=set)
    forms: list[dict] = field(default_factory=list)
    js_endpoints: list[str] = field(default_factory=list)
    api_endpoints: list[dict] = field(default_factory=list)
    auth_headers: dict[str, str] = field(default_factory=dict)
    tech_stack: list[str] = field(default_factory=list)
    response_patterns: list[dict] = field(default_factory=list)
    status_counts: dict[int, int] = field(default_factory=dict)

    def to_recon_dict(self) -> dict[str, Any]:
        return {
            "urls": sorted(set(self.urls)),
            "parameters": sorted(self.parameters),
            "forms": self.forms,
            "js_endpoints": self.js_endpoints,
            "api_endpoints": self.api_endpoints,
            "auth_headers": self.auth_headers,
            "tech_stack": self.tech_stack,
            "response_patterns": self.response_patterns,
            "status_counts": self.status_counts,
        }

    def merge_into_recon(self, recon_data: dict[str, Any]) -> dict[str, Any]:
        """Merge this ImportResult into a Recon run() result dict.

        Handles key name differences (parameters→params, tech_stack→technology)
        and feeds api_endpoints as URLs so downstream scanners can discover them.
        """
        recon = dict(recon_data)

        # urls: merge with dedup (api_endpoints also contribute URLs)
        existing_urls = set(recon.get("urls", []))
        existing_urls.update(self.urls)
        for ep in self.api_endpoints:
            ep_url = ep.get("url", "")
            if ep_url:
                existing_urls.add(ep_url)
        recon["urls"] = sorted(existing_urls)

        # params (Recon key) ← parameters (ImportResult key)
        existing_params = set(recon.get("params", []))
        existing_params.update(self.parameters)
        recon["params"] = sorted(existing_params)

        # forms: append
        recon.setdefault("forms", []).extend(self.forms)

        # js_endpoints: merge
        existing_js_ep = set(recon.get("js_endpoints", []))
        existing_js_ep.update(self.js_endpoints)
        recon["js_endpoints"] = sorted(existing_js_ep)

        # technology ← tech_stack
        existing_tech = dict(recon.get("technology", {}))
        for tech in self.tech_stack:
            existing_tech[tech] = True
        recon["technology"] = existing_tech

        # Store extra intelligence that Recon doesn't produce natively
        if self.api_endpoints:
            existing_api = recon.setdefault("_imported_api_endpoints", [])
            seen_urls = {e.get("url", "") for e in existing_api}
            for ep in self.api_endpoints:
                if ep.get("url", "") not in seen_urls:
                    existing_api.append(ep)
                    seen_urls.add(ep.get("url", ""))

        if self.auth_headers:
            existing_auth = recon.setdefault("_imported_auth_headers", {})
            existing_auth.update(self.auth_headers)

        if self.response_patterns:
            existing_rp = recon.setdefault("_imported_response_patterns", [])
            seen_patterns = {(p["url"], p["pattern"]) for p in existing_rp}
            for p in self.response_patterns:
                key = (p["url"], p["pattern"])
                if key not in seen_patterns:
                    existing_rp.append(p)
                    seen_patterns.add(key)

        if self.status_counts:
            existing_sc = recon.setdefault("_imported_status_counts", {})
            for code, count in self.status_counts.items():
                existing_sc[code] = existing_sc.get(code, 0) + count

        return recon

    def merge(self, other: "ImportResult") -> "ImportResult":
        merged = ImportResult()
        merged.urls = list(set(self.urls + other.urls))
        merged.parameters = self.parameters | other.parameters
        merged.forms = self.forms + other.forms
        merged.js_endpoints = list(
            set(self.js_endpoints + other.js_endpoints)
        )
        merged.api_endpoints = self.api_endpoints + other.api_endpoints
        merged.auth_headers = {**self.auth_headers, **other.auth_headers}
        merged.tech_stack = list(set(self.tech_stack + other.tech_stack))
        merged.response_patterns = (
            self.response_patterns + other.response_patterns
        )
        merged.status_counts = dict(self.status_counts)
        for code, count in other.status_counts.items():
            merged.status_counts[code] = (
                merged.status_counts.get(code, 0) + count
            )
        return merged


_INTERESTING_PATTERNS = [
    (re.compile(r"(?i)csrf|csrf-token|csrfmiddlewaretoken|xsrf-token"), "CSRF Token"),
    (re.compile(r"(?i)access-token|bearer\s", re.MULTILINE), "Bearer Auth"),
    (re.compile(r"(?i)api[-_]?key"), "API Key"),
    (re.compile(r"(?i)graphql|graphiql|playground"), "GraphQL"),
    (re.compile(r"(?i)swagger|openapi|api-docs"), "OpenAPI/Swagger"),
    (re.compile(r"(?i)sso|oauth|openid|saml"), "SSO/OAuth"),
    (re.compile(r"(?i)admin|administrator|dashboard"), "Admin Panel"),
    (re.compile(r"(?i)wp-admin|wp-content|wp-includes|wp-login"), "WordPress"),
    (re.compile(r"(?i)(\.env|config\.php|config\.json|credentials)"), "Config File"),
]


def _extract_params_from_url(url: str) -> set[str]:
    parsed = urlparse(url)
    if parsed.query:
        return set(parse_qs(parsed.query).keys())
    return set()


def _extract_tech(headers: dict[str, str]) -> list[str]:
    tech: list[str] = []
    server = headers.get("Server", "")
    if server:
        tech.append(server)
    powered_by = headers.get("X-Powered-By", "")
    if powered_by:
        tech.append(powered_by)
    asp = headers.get("X-AspNet-Version", "")
    if asp:
        tech.append(f"ASP.NET {asp}")
    content_type = headers.get("Content-Type", "")
    if "application/json" in content_type:
        tech.append("JSON API")
    return tech


def _classify_endpoint(url: str, content_type: str = "") -> str | None:
    path = urlparse(url).path.lower()
    if "/graphql" in path or "/graphiql" in path:
        return "graphql"
    if any(p in path for p in ("/api/", "/rest/", "/v1/", "/v2/", "/v3/")):
        return "api"
    if content_type and "json" in content_type:
        return "api"
    return None


def _extract_response_patterns(
    url: str, body: str, headers: dict[str, str]
) -> list[dict]:
    patterns: list[dict] = []
    for regex, label in _INTERESTING_PATTERNS:
        if regex.search(body) or regex.search(json.dumps(headers)):
            patterns.append({"url": url, "pattern": label})
    return patterns


def _extract_auth(headers: dict[str, str]) -> dict[str, str]:
    auth: dict[str, str] = {}
    auth_header = headers.get("Authorization", "")
    if auth_header:
        auth["Authorization"] = auth_header
    cookie = headers.get("Cookie", "")
    if cookie:
        auth["Cookie"] = cookie.split(";")[0].strip()
    x_api_key = headers.get("X-API-Key") or headers.get("X-Api-Key", "")
    if x_api_key:
        auth["X-API-Key"] = x_api_key
    return auth


class BurpXmlImporter:
    NS = {"burp": "http://www.portswigger.net/burp"}

    @staticmethod
    def import_xml(filepath: str) -> ImportResult:
        result = ImportResult()
        tree = ET.parse(filepath)
        root = tree.getroot()

        for item in root.iter("item"):
            request_el = item.find("request")
            response_el = item.find("response")
            url_el = item.find("url")
            host_el = item.find("host")

            url = ""
            if url_el is not None and url_el.text:
                url = url_el.text.strip()
            elif host_el is not None and host_el.text:
                path_el = item.find("path")
                path = path_el.text.strip() if path_el is not None else ""
                url = f"https://{host_el.text.strip()}{path}"

            if not url:
                continue

            result.urls.append(url)
            result.parameters |= _extract_params_from_url(url)

            status_el = item.find("status")
            status_code = 0
            if status_el is not None and status_el.text:
                try:
                    status_code = int(status_el.text.strip())
                except (ValueError, TypeError):
                    pass
            if status_code:
                result.status_counts[status_code] = (
                    result.status_counts.get(status_code, 0) + 1
                )

            request_headers: dict[str, str] = {}
            request_body = ""
            if request_el is not None and request_el.text:
                raw = request_el.text
                if isinstance(raw, bytes):
                    raw = raw.decode("utf-8", errors="replace")
                header_part, _, body_part = raw.partition("\r\n\r\n")
                if body_part:
                    request_body = body_part
                for line in header_part.split("\r\n")[1:]:
                    if ":" in line:
                        k, v = line.split(":", 1)
                        request_headers[k.strip()] = v.strip()

            response_headers: dict[str, str] = {}
            response_body = ""
            if response_el is not None and response_el.text:
                raw = response_el.text
                if isinstance(raw, bytes):
                    raw = raw.decode("utf-8", errors="replace")
                header_part, _, body_part = raw.partition("\r\n\r\n")
                if body_part:
                    response_body = body_part
                for line in header_part.split("\r\n")[1:]:
                    if ":" in line:
                        k, v = line.split(":", 1)
                        response_headers[k.strip()] = v.strip()

            content_type = response_headers.get("Content-Type", "")
            endpoint_type = _classify_endpoint(url, content_type)
            if endpoint_type == "api":
                result.api_endpoints.append(
                    {
                        "url": url,
                        "method": request_headers.get("Method", "GET"),
                        "content_type": content_type,
                        "status_code": status_code,
                        "body": request_body[:500] if request_body else "",
                    }
                )
            elif endpoint_type == "graphql":
                result.api_endpoints.append(
                    {
                        "url": url,
                        "method": request_headers.get("Method", "POST"),
                        "content_type": "graphql",
                        "status_code": status_code,
                        "body": request_body[:500] if request_body else "",
                    }
                )

            result.tech_stack.extend(
                _extract_tech({**response_headers})
            )
            result.response_patterns.extend(
                _extract_response_patterns(url, response_body, response_headers)
            )

            auth = _extract_auth(request_headers)
            if auth:
                result.auth_headers.update(auth)

            if "text/html" in content_type:
                form_url = url
                action_url = url
                params_in_body = _extract_params_from_url(url)

                if request_body and "=" in request_body:
                    try:
                        parsed_body = parse_qs(request_body)
                        for param_name in parsed_body:
                            result.parameters.add(param_name)
                        result.forms.append(
                            {
                                "url": form_url,
                                "action": action_url,
                                "method": request_headers.get(
                                    "Method", "POST"
                                ).upper(),
                                "fields": [
                                    {"name": p, "type": "text", "value": ""}
                                    for p in parsed_body
                                ],
                            }
                        )
                    except Exception:
                        pass

                if params_in_body:
                    for p in params_in_body:
                        result.parameters.add(p)

        result.tech_stack = list(set(result.tech_stack))
        result.urls = sorted(set(result.urls))
        result.js_endpoints = sorted(set(result.js_endpoints))
        return result


class HarImporter:
    @staticmethod
    def import_har(filepath: str) -> ImportResult:
        result = ImportResult()

        with open(filepath) as f:
            har = json.load(f)

        log_data = har.get("log", {})
        entries = log_data.get("entries", [])

        for entry in entries:
            request = entry.get("request", {})
            response = entry.get("response", {})

            url = request.get("url", "")
            if not url:
                continue

            result.urls.append(url)

            query_params = request.get("queryString", [])
            for qp in query_params:
                name = qp.get("name", "")
                if name:
                    result.parameters.add(name)

            result.parameters |= _extract_params_from_url(url)

            status_code = response.get("status", 0)
            if status_code:
                result.status_counts[status_code] = (
                    result.status_counts.get(status_code, 0) + 1
                )

            request_headers = {
                h.get("name", ""): h.get("value", "")
                for h in request.get("headers", [])
            }
            response_headers = {
                h.get("name", ""): h.get("value", "")
                for h in response.get("headers", [])
            }

            content_type = response_headers.get("Content-Type", "")
            endpoint_type = _classify_endpoint(url, content_type)
            if endpoint_type:
                post_data = request.get("postData", {})
                body = post_data.get("text", "")
                if isinstance(body, str) and body.startswith("{"):
                    pass
                result.api_endpoints.append(
                    {
                        "url": url,
                        "method": request.get("method", "GET"),
                        "content_type": content_type if endpoint_type == "api" else "graphql",
                        "status_code": status_code,
                        "body": body[:500] if body else "",
                    }
                )

            result.tech_stack.extend(_extract_tech(response_headers))
            result.response_patterns.extend(
                _extract_response_patterns(
                    url, response.get("content", {}).get("text", ""), response_headers
                )
            )

            auth = _extract_auth(dict(request_headers))
            if auth:
                result.auth_headers.update(auth)

            if "text/html" in content_type:
                post_data = request.get("postData", {})
                params_text = post_data.get("text", "")
                if params_text and "=" in params_text:
                    try:
                        parsed = parse_qs(params_text)
                        for param_name in parsed:
                            result.parameters.add(param_name)
                        result.forms.append(
                            {
                                "url": url,
                                "action": url,
                                "method": request.get("method", "POST").upper(),
                                "fields": [
                                    {"name": p, "type": "text", "value": ""}
                                    for p in parsed
                                ],
                            }
                        )
                    except Exception:
                        pass

            response_content = response.get("content", {})
            response_text = response_content.get("text", "")
            if response_text:
                js_pattern = re.compile(
                    r'(?:fetch|axios|ajax|XMLHttpRequest)\s*\(\s*["\']([^"\']+)["\']'
                )
                for match in js_pattern.findall(response_text):
                    result.js_endpoints.append(match)

        result.tech_stack = list(set(result.tech_stack))
        result.urls = sorted(set(result.urls))
        return result


class CharlesImporter:
    @staticmethod
    def import_session(filepath: str) -> ImportResult:
        result = ImportResult()
        tree = ET.parse(filepath)

        for charles_request in tree.iter():
            if charles_request.tag.endswith("request"):
                continue
            if charles_request.tag.endswith("response"):
                continue

        for req_elem in tree.iter():
            tag = req_elem.tag.lower()
            if "request" not in tag and "req" not in tag:
                continue

            url = ""
            method = "GET"
            request_headers: dict[str, str] = {}
            request_body = ""
            status_code = 0
            response_headers: dict[str, str] = {}
            response_body = ""

            for child in req_elem.iter():
                child_tag = child.tag.lower()
                if child_tag.endswith("url") or child_tag == "uri":
                    if child.text:
                        url = child.text.strip()
                elif child_tag.endswith("method"):
                    if child.text:
                        method = child.text.strip().upper()
                elif child_tag.endswith("statuscode") or child_tag == "status":
                    if child.text:
                        try:
                            status_code = int(child.text.strip())
                        except (ValueError, TypeError):
                            pass
                elif child_tag.endswith("headers") or child_tag == "header":
                    for header in child.iter():
                        if header.tag.endswith("header"):
                            name = header.get("name", "") or header.get("key", "")
                            value = header.get("value", "") or header.text or ""
                            if name:
                                if "request" in tag or "req" in tag:
                                    request_headers[name] = value
                                else:
                                    response_headers[name] = value

                elif child_tag.endswith("body") or child_tag == "data":
                    if child.text:
                        if "request" in tag or "req" in tag:
                            request_body = child.text
                        else:
                            response_body = child.text

            if not url:
                continue

            result.urls.append(url)
            result.parameters |= _extract_params_from_url(url)

            if status_code:
                result.status_counts[status_code] = (
                    result.status_counts.get(status_code, 0) + 1
                )

            content_type = response_headers.get("Content-Type", "")
            endpoint_type = _classify_endpoint(url, content_type)
            if endpoint_type:
                result.api_endpoints.append(
                    {
                        "url": url,
                        "method": method,
                        "content_type": content_type if endpoint_type == "api" else "graphql",
                        "status_code": status_code,
                        "body": request_body[:500] if request_body else "",
                    }
                )

            result.tech_stack.extend(_extract_tech(dict(response_headers)))
            result.response_patterns.extend(
                _extract_response_patterns(url, response_body, response_headers)
            )

            auth = _extract_auth(dict(request_headers))
            if auth:
                result.auth_headers.update(auth)

            if request_body and "=" in request_body:
                try:
                    parsed = parse_qs(request_body)
                    for param_name in parsed:
                        result.parameters.add(param_name)
                    result.forms.append(
                        {
                            "url": url,
                            "action": url,
                            "method": method,
                            "fields": [
                                {"name": p, "type": "text", "value": ""}
                                for p in parsed
                            ],
                        }
                    )
                except Exception:
                    pass

        result.tech_stack = list(set(result.tech_stack))
        result.urls = sorted(set(result.urls))
        result.js_endpoints = sorted(set(result.js_endpoints))
        return result


class PostmanImporter:
    @staticmethod
    def import_collection(filepath: str) -> ImportResult:
        result = ImportResult()
        with open(filepath) as f:
            collection = json.load(f)

        items = collection.get("item", [])
        queue: list = list(items)
        while queue:
            item = queue.pop(0)
            if "item" in item:
                queue.extend(item["item"])
                continue
            req = item.get("request", {})
            if not req:
                continue
            url = PostmanImporter._resolve_url(req.get("url", {}))
            if not url:
                continue
            result.urls.append(url)
            result.parameters |= _extract_params_from_url(url)
            method = req.get("method", "GET").upper()
            request_headers = {
                h["key"]: h["value"] for h in req.get("header", []) if h.get("key")
            }
            auth = _extract_auth(request_headers)
            if auth:
                result.auth_headers.update(auth)
            body_data = ""
            body = req.get("body", {})
            if body.get("mode") == "raw":
                body_data = body.get("raw", "")
            elif body.get("mode") == "urlencoded":
                parts = [
                    f"{p['key']}={p.get('value', '')}"
                    for p in body.get("urlencoded", []) if p.get("key")
                ]
                body_data = "&".join(parts)
            elif body.get("mode") == "formdata":
                parts = [
                    f"{p['key']}={p.get('value', '')}"
                    for p in body.get("formdata", []) if p.get("key")
                ]
                body_data = "&".join(parts)

            for resp in item.get("response", []):
                status_code = resp.get("code", 0)
                if status_code:
                    result.status_counts[status_code] = result.status_counts.get(status_code, 0) + 1
                resp_headers = {
                    h["key"]: h["value"] for h in resp.get("header", []) if h.get("key")
                }
                content_type = resp_headers.get("Content-Type", "")
                result.tech_stack.extend(_extract_tech(resp_headers))
                resp_body = resp.get("body", "") or resp.get("text", "") or ""
                if resp_body:
                    result.response_patterns.extend(
                        _extract_response_patterns(url, resp_body, resp_headers)
                    )
                    if "text/html" in content_type and body_data and "=" in body_data:
                        try:
                            parsed_body = parse_qs(body_data)
                            for param_name in parsed_body:
                                result.parameters.add(param_name)
                            result.forms.append({
                                "url": url, "action": url, "method": method,
                                "fields": [{"name": p, "type": "text", "value": ""} for p in parsed_body],
                            })
                        except Exception:
                            pass
                endpoint_type = _classify_endpoint(url, content_type)
                if endpoint_type:
                    result.api_endpoints.append({
                        "url": url, "method": method,
                        "content_type": content_type if endpoint_type == "api" else "graphql",
                        "status_code": status_code,
                        "body": body_data[:500] if body_data else "",
                    })

        result.tech_stack = list(set(result.tech_stack))
        result.urls = sorted(set(result.urls))
        result.js_endpoints = sorted(set(result.js_endpoints))
        return result

    @staticmethod
    def _resolve_url(url_data: dict | str) -> str:
        if isinstance(url_data, str):
            return url_data
        raw = url_data.get("raw", "")
        if raw:
            return raw
        protocol = url_data.get("protocol", "https")
        host = ".".join(url_data.get("host", [])) if isinstance(url_data.get("host"), list) else (url_data.get("host") or "")
        port = url_data.get("port", "")
        path_parts = url_data.get("path", [])
        path = "/" + "/".join(path_parts) if isinstance(path_parts, list) else (path_parts or "")
        query = url_data.get("query", [])
        qs = ""
        if query:
            parts = [f"{q['key']}={q.get('value', '')}" for q in query if q.get("key")]
            if parts:
                qs = "?" + "&".join(parts)
        port_str = f":{port}" if port else ""
        return f"{protocol}://{host}{port_str}{path}{qs}"
