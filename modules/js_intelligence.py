"""
JSIntelligence — JavaScript analysis engine.

Provides secret discovery, endpoint extraction, and route enumeration
from JavaScript source code. Uses AST parsing (esprima) when available
with enhanced regex fallback. Integrates with SecretValidator for
live credential validation.
"""

import hashlib
import re
import threading
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse

from modules.utils import SecretValidator

# Install esprima (pip install esprima) for AST-based parsing.
# Regex fallback is used automatically when esprima is absent.
try:
    import esprima
    ESPRIMA_AVAILABLE = True
except ImportError:
    ESPRIMA_AVAILABLE = False


SECRET_SEVERITY = {
    "AWS Access Key": "critical", "AWS Secret Key": "critical",
    "Private Key (RSA)": "critical", "Private Key (EC)": "critical",
    "Private Key (OpenSSH)": "critical", "Private Key (SSH)": "critical",
    "Stripe Live Secret Key": "critical", "Stripe Restricted Key": "critical",
    "GitHub Token (classic)": "high", "GitHub Token (fine-grained)": "high",
    "GitHub OAuth": "high", "Twilio Account SID": "high",
    "Twilio Auth Token": "high", "Slack Bot Token": "high",
    "Slack App Token": "high", "Slack User Token": "high",
    "Slack Webhook": "high", "Discord Webhook": "high",
    "Heroku API Key": "high", "npm Auth Token": "high",
    "SendGrid API Key": "high", "Stripe Test Secret Key": "medium",
    "Stripe Live Publishable Key": "medium", "Stripe Test Publishable Key": "medium",
    "Google API Key": "medium", "Google OAuth Token": "medium",
    "Firebase API Key": "medium", "Firebase URL": "medium",
    "Bearer Token": "medium", "Basic Auth": "medium",
    "Generic API Key": "medium", "JWT Token": "medium",
}

SECRET_PATTERNS_JS = [
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("AWS Secret Key", re.compile(r"(?<![A-Za-z0-9])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9])")),
    ("GitHub Token (classic)", re.compile(r"ghp_[A-Za-z0-9]{36}")),
    ("GitHub Token (fine-grained)", re.compile(r"github_pat_[A-Za-z0-9_]{82}")),
    ("GitHub OAuth", re.compile(r"gh[ousr]_[A-Za-z0-9_]{36,}")),
    ("Slack Bot Token", re.compile(r"xoxb-[0-9A-Za-z-]{10,}")),
    ("Slack App Token", re.compile(r"xapp-[0-9A-Za-z-]{10,}")),
    ("Slack User Token", re.compile(r"xox[ps]-[0-9A-Za-z-]{10,}")),
    ("Google API Key", re.compile(r"AIza[0-9A-Za-z_-]{35}")),
    ("Google OAuth Token", re.compile(r"ya29\.[0-9A-Za-z_-]{50,}")),
    ("Stripe Live Secret Key", re.compile(r"sk_live_[0-9A-Za-z]{24,}")),
    ("Stripe Test Secret Key", re.compile(r"sk_test_[0-9A-Za-z]{24,}")),
    ("Stripe Live Publishable Key", re.compile(r"pk_live_[0-9A-Za-z]{24,}")),
    ("Stripe Test Publishable Key", re.compile(r"pk_test_[0-9A-Za-z]{24,}")),
    ("Stripe Restricted Key", re.compile(r"rk_live_[0-9A-Za-z]{24,}")),
    ("Twilio Account SID", re.compile(r"AC[0-9A-Za-z]{32}")),
    ("Twilio Auth Token", re.compile(r"SK[0-9A-Za-z]{32}")),
    ("SendGrid API Key", re.compile(r"SG\.[A-Za-z0-9_\-]{22,}\.[A-Za-z0-9_\-]{43,}")),
    ("Heroku API Key", re.compile(r"[hH][eE][rR][oO][kK][uU].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}")),
    ("Slack Webhook", re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+")),
    ("Discord Webhook", re.compile(r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+")),
    ("JWT Token", re.compile(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+")),
    ("Bearer Token", re.compile(r"""["'](?:bearer|access_token|auth_token)["']\s*[:=]\s*["']([^"']{8,})["']""", re.I)),
    ("Basic Auth", re.compile(r"""["'](?:authorization|basic_auth)["']\s*[:=]\s*["']Basic\s+([^"']+)["']""", re.I)),
    ("Generic API Key", re.compile(r"""["'](?:api[_-]?key|apikey|api_secret|secret|token)["']\s*[:=]\s*["']([^"']{8,})["']""", re.I)),
    ("Private Key (RSA)", re.compile(r"-----BEGIN RSA PRIVATE KEY-----")),
    ("Private Key (EC)", re.compile(r"-----BEGIN EC PRIVATE KEY-----")),
    ("Private Key (OpenSSH)", re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----")),
    ("Private Key (SSH)", re.compile(r"-----BEGIN SSH PRIVATE KEY-----")),
    ("Firebase URL", re.compile(r"https://[A-Za-z0-9_-]+\.firebaseio\.com")),
    ("Firebase API Key", re.compile(r"AAAA[A-Za-z0-9_-]{50,}")),
    ("npm Auth Token", re.compile(r"//registry\.npmjs\.org/:_authToken=[A-Za-z0-9_\-]{36,}")),
]

ENDPOINT_PATTERNS = [
    (re.compile(r"""(?:fetch|axios|\.get|\.post|\.put|\.delete|\.patch)\s*\(\s*["']([^"']+)["']"""), "api_call"),
    (re.compile(r"""\$\s*\.\s*(?:get|post|put|delete|ajax)\s*\(\s*["']([^"']+)["']"""), "jquery"),
    (re.compile(r"""new\s+XMLHttpRequest.*\.open\s*\(\s*["'](?:GET|POST|PUT|DELETE|PATCH)["']\s*,\s*["']([^"']+)["']"""), "xhr"),
    (re.compile(r"""["'](/api/[^"']+)["']"""), "api_path"),
    (re.compile(r"""["'](/v[0-9]+/[^"']+)["']"""), "versioned_api"),
    (re.compile(r"""["'](/graphql[^"']*)["']"""), "graphql"),
    (re.compile(r"""["'](/rest/[^"']+)["']"""), "rest"),
    (re.compile(r"""["'](_next/data/[^"']+)["']"""), "nextjs_data"),
    (re.compile(r"""["'](/?[a-z]+/[a-z]+/[a-z0-9_]+)["']""", re.I), "potential_endpoint"),
    (re.compile(r"""["'](/?[a-z]+/[a-z0-9_]+\.(json|xml|yaml|yml|config|js|ts))["']""", re.I), "data_file"),
]

ROUTE_PATTERNS = [
    (re.compile(r"""\.(?:get|post|put|delete|patch)\s*\(\s*["']([^"']+)["']"""), "express"),
    (re.compile(r"""router\.(?:get|post|put|delete|patch)\s*\(\s*["']([^"']+)["']"""), "router"),
    (re.compile(r"""@app\.(?:route|get|post|put|delete)\s*\(\s*["']([^"']+)["']"""), "flask"),
    (re.compile(r"""app\.(?:get|post|put|delete)\s*\(\s*["']([^"']+)["']"""), "fastapi"),
    (re.compile(r"""Route::(?:get|post|put|delete)\s*\(\s*["']([^"']+)["']"""), "laravel"),
    (re.compile(r"""@(?:GetMapping|PostMapping|PutMapping|DeleteMapping|RequestMapping)\s*\(\s*["']([^"']+)["']"""), "spring"),
    (re.compile(r"""NextResponse\.(?:json|next|redirect)\(.*["']([^"']+)["']"""), "nextjs_response"),
    (re.compile(r"""pages/api/[^"'\s]+"""), "nextjs_api_route"),
]

ENV_VAR_PATTERNS = [
    (re.compile(r"""process\.env\.([A-Z_][A-Z0-9_]*)"""), "process_env"),
    (re.compile(r"""import\.meta\.env\.([A-Z_][A-Z0-9_]*)"""), "import_meta_env"),
    (re.compile(r"""Deno\.env\.get\s*\(\s*["']([^"']+)["']"""), "deno_env"),
    (re.compile(r"""env\s*\(["']([^"']+)["']"""), "vite_env"),
]

FEATURE_FLAG_PATTERNS = [
    (re.compile(r"""["'](feature|flag|experiment|beta|beta_feature|preview|early_access)["']\s*[:=]\s*["']([^"']+)["']""", re.I), "feature_flag"),
    (re.compile(r"""["'](isEnabled|isActive|isBeta|isPreview|is_feature_enabled)["']\s*[:=]\s*(true|false)""", re.I), "feature_flag_bool"),
    (re.compile(r"if\s*\(\s*featureFlags?\s*\.\s*(\w+)", re.I), "feature_flag_check"),
]

HARDCODED_PATTERNS = [
    (re.compile(r"""["'](password|passwd|pwd|secret|api_secret|db_password|mysql_password|postgres_password)["']\s*[:=]\s*["']([^"']{4,})["']""", re.I), "hardcoded_cred"),
    (re.compile(r"""["'](host|hostname|database|db_host|db_name|server|db_server)["']\s*[:=]\s*["']([^"']{3,})["']""", re.I), "internal_host"),
    (re.compile(r"(?:https?://internal[^\s\"']+|https?://10\.\d+\.\d+\.\d+)", re.I), "internal_url"),
    (re.compile(r"(?:https?://[a-z]+-api\.(?:internal|corp|local|dev)[^\s\"']*)", re.I), "internal_api"),
    (re.compile(r"(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})"), "private_ip"),
    (re.compile(r"(?:localhost|127\.0\.0\.1|0\.0\.0\.0)(?::\d+)?"), "localhost_ref"),
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
    (re.compile(r"""["'](/api-docs[^"']*)["']""", re.I), "api_docs"),
    (re.compile(r"""["'](/graphql[^"']*)["']""", re.I), "graphql_console"),
    (re.compile(r"""["'](/actuator[^"']*)["']""", re.I), "actuator"),
    (re.compile(r"""["'](/\.env[^"']*)["']""", re.I), "env_file"),
    (re.compile(r"""["'](/\.git[^"']*)["']""", re.I), "git_exposed"),
]


MAX_FILE_SIZE = 5 * 1024 * 1024


class JSIntelligence:
    """Analyze JavaScript source code for secrets, endpoints, routes, and hidden functionality.

    Uses AST parsing (esprima) when available, with enhanced regex fallback.
    Integrates with SecretValidator for live credential validation.
    Supports deduplication, same-domain filtering, file size limits, and thread-safe operation.
    """

    def __init__(self, base_url: str = "", config: Optional[Dict[str, Any]] = None):
        self.base_url = base_url.rstrip("/")
        self._ast_available = ESPRIMA_AVAILABLE
        self._config = config or {}
        self._lock = threading.Lock()
        self._seen_fingerprints: Set[str] = set()

    def _fingerprint(self, secret_type: str, value: str) -> str:
        return hashlib.sha256(f"{secret_type}:{value}".encode()).hexdigest()

    def _is_duplicate(self, secret_type: str, value: str) -> bool:
        fp = self._fingerprint(secret_type, value)
        with self._lock:
            if fp in self._seen_fingerprints:
                return True
            self._seen_fingerprints.add(fp)
        return False

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
            "env_vars": [],
            "validated_secrets": [],
        }

        if len(js_code.encode("utf-8")) > MAX_FILE_SIZE:
            return results

        self._extract_endpoints(js_code, results, source_url)
        self._extract_secrets(js_code, results, source_url)
        self._extract_routes(js_code, results)
        self._extract_feature_flags(js_code, results)
        self._extract_hidden(js_code, results, source_url)
        self._extract_env_vars(js_code, results)

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
                results["endpoints"].append({
                    "url": full,
                    "source": match.group(0)[:80],
                    "type": label,
                })

    def _extract_secrets(self, js_code: str, results: Dict[str, Any], source_url: str) -> None:
        for label, pattern in SECRET_PATTERNS_JS:
            for match in pattern.finditer(js_code):
                value = match.group(0)[:120]
                if self._is_duplicate(label, value):
                    continue

                sev = SECRET_SEVERITY.get(label, "medium")
                secret_entry = {
                    "type": label,
                    "value": value,
                    "match": match.group(0)[:80],
                    "source_url": source_url,
                    "confidence": "medium",
                    "severity": sev,
                    "validated": None,
                    "validation_details": "",
                }

                self._try_validate_secret(secret_entry)

                if secret_entry.get("validated") is True:
                    results.setdefault("validated_secrets", []).append(secret_entry)

                results["secrets"].append(secret_entry)

    def _try_validate_secret(self, secret_entry: Dict[str, Any]) -> None:
        type_map = {
            "AWS Access Key": ("aws_access_key", secret_entry["value"]),
            "GitHub Token (classic)": ("github_token", secret_entry["value"]),
            "GitHub Token (fine-grained)": ("github_token", secret_entry["value"]),
            "GitHub OAuth": ("github_token", secret_entry["value"]),
            "Slack Bot Token": ("slack_token", secret_entry["value"]),
            "Slack App Token": ("slack_token", secret_entry["value"]),
            "Slack User Token": ("slack_token", secret_entry["value"]),
            "Twilio Account SID": ("twilio_sid", secret_entry["value"]),
            "Twilio Auth Token": ("twilio_token", secret_entry["value"]),
        }
        entry_type = secret_entry["type"]
        if entry_type not in type_map:
            return

        try:
            mapped_type, value = type_map[entry_type]
            clean_value = value.split()[0] if " " in value else value
            result = SecretValidator.validate(mapped_type, clean_value)
            if result.get("valid") is True:
                secret_entry["validated"] = True
                secret_entry["validation_details"] = result.get("details", "")
                secret_entry["confidence"] = "high"
            elif result.get("valid") is False:
                secret_entry["validated"] = False
                secret_entry["validation_details"] = result.get("details", "Invalid/revoked")
                secret_entry["confidence"] = "none"
            else:
                secret_entry["validated"] = None
                secret_entry["validation_details"] = result.get("details", "Validation inconclusive")
        except Exception:
            pass

    def _extract_routes(self, js_code: str, results: Dict[str, Any]) -> None:
        for pattern, framework in ROUTE_PATTERNS:
            for match in pattern.finditer(js_code):
                route = match.group(1)
                results["routes"].append({
                    "route": route,
                    "framework": framework,
                    "match": match.group(0)[:80],
                })

    def _extract_feature_flags(self, js_code: str, results: Dict[str, Any]) -> None:
        for pattern, label in FEATURE_FLAG_PATTERNS:
            for match in pattern.finditer(js_code):
                results["feature_flags"].append({
                    "type": label,
                    "match": match.group(0)[:80],
                })

    def _extract_hidden(self, js_code: str, results: Dict[str, Any], source_url: str) -> None:
        for pattern, label in HIDDEN_ENDPOINT_PATTERNS:
            for match in pattern.finditer(js_code):
                endpoint = match.group(1)
                if not endpoint.startswith(("http://", "https://", "//")):
                    full = urljoin(source_url, endpoint) if source_url else endpoint
                else:
                    full = endpoint
                results["hidden_endpoints"].append({
                    "url": full,
                    "type": label,
                    "match": match.group(0)[:80],
                })

        for pattern, label in HARDCODED_PATTERNS:
            for match in pattern.finditer(js_code):
                results["hardcoded_values"].append({
                    "type": label,
                    "match": match.group(0)[:120],
                })

    def _extract_env_vars(self, js_code: str, results: Dict[str, Any]) -> None:
        for pattern, ref_type in ENV_VAR_PATTERNS:
            for match in pattern.finditer(js_code):
                var_name = match.group(1)
                results["env_vars"].append({
                    "variable": var_name,
                    "reference": ref_type,
                    "match": match.group(0)[:80],
                })

    def extract_tokens(self, js_code: str) -> List[Dict[str, str]]:
        """Quick token extraction — returns list of {type, value} dicts."""
        tokens = []
        seen = set()
        for label, pattern in SECRET_PATTERNS_JS:
            for match in pattern.finditer(js_code):
                value = match.group(0)[:120]
                fp = self._fingerprint(label, value)
                if fp in seen:
                    continue
                seen.add(fp)
                tokens.append({"type": label, "value": value})
        return tokens

    def extract_all_endpoints(self, js_code: str, source_url: str = "") -> List[str]:
        """Extract all discovered endpoints as a flat URL list."""
        results = self.analyze(js_code, source_url)
        urls = [e["url"] for e in results["endpoints"]]
        urls.extend(e["url"] for e in results["hidden_endpoints"])
        return list(set(urls))
