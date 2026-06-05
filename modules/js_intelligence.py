"""
JSIntelligence — JavaScript analysis engine.

Uses AST parsing (esprima) when available, falls back to enhanced
regex-based extraction for endpoint discovery, secret detection,
and attack surface expansion.
"""

import re
import json
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

try:
    import esprima
    ESPRIMA_AVAILABLE = True
except ImportError:
    ESPRIMA_AVAILABLE = False


# ── Enhanced regex patterns (fallback) ────────────────────────────────────

ENDPOINT_PATTERNS = [
    (re.compile(r"""(?:fetch|axios|\.get|\.post|\.put|\.delete|\.patch)\s*\(\s*["']([^"']+)["']"""), "api"),
    (re.compile(r"""\$\s*\.\s*(?:get|post|put|delete|ajax)\s*\(\s*["']([^"']+)["']"""), "jquery"),
    (re.compile(r"""["'](/api/[^"']+)["']"""), "api_path"),
    (re.compile(r"""["'](/v[0-9]+/[^"']+)["']"""), "versioned_api"),
    (re.compile(r"""["'](/graphql[^"']*)["']"""), "graphql"),
    (re.compile(r"""["'](/rest/[^"']+)["']"""), "rest"),
    (re.compile(r"""["'](/?[a-z]+/[a-z]+/[a-z0-9_]+)["']""", re.I), "potential_endpoint"),
    (re.compile(r"""["'](/?[a-z]+/[a-z0-9_]+\.(json|xml))["']""", re.I), "data_file"),
]

SECRET_PATTERNS_JS = [
    ("AWS Key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("GitHub Token", re.compile(r"(?:ghp_|github_pat_|gho_|ghu_|ghs_|ghr_)[A-Za-z0-9_]{36,}")),
    ("Slack Token", re.compile(r"(?:xox[baprs]-|xapp-)[0-9A-Za-z-]{10,}")),
    ("Generic API Key", re.compile(r"""["'](?:api[_-]?key|apikey|api_secret|secret|token)["']\s*[:=]\s*["']([^"']{8,})["']""", re.I)),
    ("Bearer Token", re.compile(r"""["'](?:bearer|access_token|auth_token)["']\s*[:=]\s*["']([^"']{8,})["']""", re.I)),
    ("Basic Auth", re.compile(r"""["'](?:authorization|basic_auth)["']\s*[:=]\s*["']Basic\s+([^"']+)["']""", re.I)),
    ("Private Key", re.compile(r"-----BEGIN (?:RSA|EC|OPENSSH) PRIVATE KEY-----")),
    ("JWT Token", re.compile(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+")),
]

ROUTE_PATTERNS = [
    (re.compile(r"""\.(?:get|post|put|delete|patch)\s*\(\s*["']([^"']+)["']"""), "express"),
    (re.compile(r"""router\.(?:get|post|put|delete|patch)\s*\(\s*["']([^"']+)["']"""), "router"),
    (re.compile(r"""@app\.(?:route|get|post|put|delete)\s*\(\s*["']([^"']+)["']"""), "flask"),
    (re.compile(r"""app\.(?:get|post|put|delete)\s*\(\s*["']([^"']+)["']"""), "fastapi"),
    (re.compile(r"""Route::(?:get|post|put|delete)\s*\(\s*["']([^"']+)["']"""), "laravel"),
    (re.compile(r"""@(?:GetMapping|PostMapping|PutMapping|DeleteMapping)\s*\(\s*["']([^"']+)["']"""), "spring"),
]

FEATURE_FLAG_PATTERNS = [
    (re.compile(r"""["'](feature|flag|experiment|beta|beta_feature|preview|early_access)["']\s*[:=]\s*["']([^"']+)["']""", re.I), "feature_flag"),
    (re.compile(r"""["'](isEnabled|isActive|isBeta|isPreview|is_feature_enabled)["']\s*[:=]\s*(true|false)""", re.I), "feature_flag_bool"),
    (re.compile(r"if\s*\(\s*featureFlags?\s*\.\s*(\w+)", re.I), "feature_flag_check"),
]

HARDCODED_PATTERNS = [
    (re.compile(r"""["'](password|passwd|pwd|secret|api_secret|db_password)["']\s*[:=]\s*["']([^"']{4,})["']""", re.I), "hardcoded_cred"),
    (re.compile(r"""["'](host|hostname|database|db_host|db_name|server)["']\s*[:=]\s*["']([^"']{3,})["']""", re.I), "internal_host"),
    (re.compile(r'(?:https?://internal[^\s"\']+|https?://10\.\d+\.\d+\.\d+)', re.I), "internal_url"),
    (re.compile(r'(?:https?://[a-z]+-api\.(?:internal|corp|local|dev)[^\s"\']*)', re.I), "internal_api"),
]

HIDDEN_ENDPOINT_PATTERNS = [
    (re.compile(r"""["'](/admin[^"']*)["']""", re.I), "admin"),
    (re.compile(r"""["'](/internal[^"']*)["']""", re.I), "internal"),
    (re.compile(r"""["'](/debug[^"']*)["']""", re.I), "debug"),
    (re.compile(r"""["'](/health[^"']*)["']""", re.I), "health"),
    (re.compile(r"""["'](/metrics[^"']*)["']""", re.I), "metrics"),
    (re.compile(r"""["'](/swagger[^"']*)["']""", re.I), "swagger"),
    (re.compile(r"""["'](/docs[^"']*)["']""", re.I), "docs"),
    (re.compile(r"""["'](/webhook[^"']*)["']""", re.I), "webhook"),
    (re.compile(r"""["'](/callback[^"']*)["']""", re.I), "callback"),
    (re.compile(r"""["'](/console[^"']*)["']""", re.I), "console"),
]


class JSIntelligence:
    """Analyze JavaScript source code for endpoints, secrets, and hidden functionality."""

    def __init__(self, base_url: str = ""):
        self.base_url = base_url.rstrip("/")
        self._ast_available = ESPRIMA_AVAILABLE

    def analyze(self, js_code: str, source_url: str = "") -> Dict[str, Any]:
        """Full analysis of a JavaScript source."""
        results: Dict[str, Any] = {
            "endpoints": [],
            "secrets": [],
            "routes": [],
            "feature_flags": [],
            "hidden_endpoints": [],
            "hardcoded_values": [],
            "internal_apis": [],
            "graphql_endpoints": [],
            "tokens": [],
            "suspicious_patterns": [],
        }

        self._extract_endpoints(js_code, results, source_url)
        self._extract_secrets(js_code, results)
        self._extract_routes(js_code, results)
        self._extract_feature_flags(js_code, results)
        self._extract_hidden(js_code, results, source_url)

        return results

    def _extract_endpoints(self, js_code: str, results: Dict[str, Any], source_url: str) -> None:
        for pattern, label in ENDPOINT_PATTERNS:
            for match in pattern.finditer(js_code):
                endpoint = match.group(1)
                if not endpoint.startswith(("http://", "https://", "//")):
                    full = urljoin(source_url, endpoint) if source_url else endpoint
                elif endpoint.startswith("//"):
                    parsed = urlparse(source_url)
                    full = f"{parsed.scheme}:{endpoint}" if source_url else endpoint
                else:
                    full = endpoint
                results["endpoints"].append({"url": full, "source": match.group(0)[:80], "type": label})

    def _extract_secrets(self, js_code: str, results: Dict[str, Any]) -> None:
        for label, pattern in SECRET_PATTERNS_JS:
            for match in pattern.finditer(js_code):
                value = match.group(0)[:120]
                results["secrets"].append({"type": label, "value": value, "match": match.group(0)[:80]})

    def _extract_routes(self, js_code: str, results: Dict[str, Any]) -> None:
        for pattern, framework in ROUTE_PATTERNS:
            for match in pattern.finditer(js_code):
                route = match.group(1)
                results["routes"].append({"route": route, "framework": framework, "match": match.group(0)[:80]})

    def _extract_feature_flags(self, js_code: str, results: Dict[str, Any]) -> None:
        for pattern, label in FEATURE_FLAG_PATTERNS:
            for match in pattern.finditer(js_code):
                results["feature_flags"].append({"type": label, "match": match.group(0)[:80]})

    def _extract_hidden(self, js_code: str, results: Dict[str, Any], source_url: str) -> None:
        for pattern, label in HIDDEN_ENDPOINT_PATTERNS:
            for match in pattern.finditer(js_code):
                endpoint = match.group(1)
                if not endpoint.startswith(("http://", "https://", "//")):
                    full = urljoin(source_url, endpoint) if source_url else endpoint
                else:
                    full = endpoint
                results["hidden_endpoints"].append({"url": full, "type": label, "match": match.group(0)[:80]})

        for pattern, label in HARDCODED_PATTERNS:
            for match in pattern.finditer(js_code):
                results["hardcoded_values"].append({"type": label, "match": match.group(0)[:120]})

    def extract_tokens(self, js_code: str) -> List[Dict[str, str]]:
        """Quick token extraction — returns list of {type, value} dicts."""
        tokens = []
        for label, pattern in SECRET_PATTERNS_JS:
            for match in pattern.finditer(js_code):
                tokens.append({"type": label, "value": match.group(0)[:120]})
        return tokens

    def extract_all_endpoints(self, js_code: str, source_url: str = "") -> List[str]:
        """Extract all discovered endpoints as a flat URL list."""
        results = self.analyze(js_code, source_url)
        urls = [e["url"] for e in results["endpoints"]]
        urls.extend(e["url"] for e in results["hidden_endpoints"])
        return list(set(urls))
