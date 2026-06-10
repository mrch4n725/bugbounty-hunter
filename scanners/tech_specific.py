"""
Technology-aware scanner registry with framework-specific probes.

Provides a TechSpecificScannerRegistry that maintains probe sets for common
web frameworks (WordPress, Spring Boot, Rails, Laravel, GraphQL), auto-detects
frameworks from URL patterns, and runs targeted probes against detected stacks.
"""

import json
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin

from models.evidence import HttpRequestEvidence, ResponseExcerptEvidence
from models.finding import VerificationStage
from modules.utils import finding, log, Colors, safe_get, safe_post, _build_curl


@dataclass
class Probe:
    id: str
    vulnerable_pattern: str
    impact: str
    severity: str
    url_template: str
    method: str = "GET"
    data_template: str | None = None
    detection_headers: dict[str, str] = field(default_factory=dict)
    false_positive_check: str | None = None


@dataclass
class ProbeSet:
    framework_name: str
    probes: list[Probe] = field(default_factory=list)


FRAMEWORK_PROBES: dict[str, list[Probe]] = {
    "wordpress": [
        Probe(
            id="wordpress_xmlrpc_ssrf",
            vulnerable_pattern=r"system\.listMethods",
            impact="XML-RPC system.listMethods exposed — SSRF amplification risk via pingbacks",
            severity="medium",
            url_template="{base}/xmlrpc.php?rsd",
            method="GET",
            false_positive_check=r"XML-RPC server accepts POST requests only",
        ),
        Probe(
            id="wordpress_user_enum",
            vulnerable_pattern=r"Location:.*/author/\d+",
            impact="User enumeration via author ID — attackers can map usernames for brute-force",
            severity="low",
            url_template="{base}/?author=1",
            method="GET",
            detection_headers={},
        ),
        Probe(
            id="wordpress_rest_users",
            vulnerable_pattern=r'"slug":\s*"[^"]+"',
            impact="WP REST API user endpoint exposed — user list disclosure",
            severity="medium",
            url_template="{base}/wp-json/wp/v2/users",
            method="GET",
        ),
        Probe(
            id="wordpress_admin_ajax_sqli",
            vulnerable_pattern=r"action=.*handler",
            impact="admin-ajax.php plugin action parameter — SQLi testing required",
            severity="high",
            url_template="{base}/wp-admin/admin-ajax.php",
            method="POST",
            data_template="action=test_handler",
        ),
        Probe(
            id="wordpress_debug_log",
            vulnerable_pattern=r"(PHP\s*(Warning|Notice|Fatal)|Stack trace:)",
            impact="Debug log exposed — sensitive error information and stack traces leaked",
            severity="medium",
            url_template="{base}/wp-content/debug.log",
            method="GET",
            false_positive_check=r"404 Not Found",
        ),
    ],
    "spring": [
        Probe(
            id="spring_actuator_env",
            vulnerable_pattern=r"""(?:JAVA_HOME|java\.runtime|spring\.datasource|server\.port)""",
            impact="Actuator /env endpoint exposed — environment properties including potential secrets leaked",
            severity="high",
            url_template="{base}/actuator/env",
            method="GET",
        ),
        Probe(
            id="spring_actuator_heapdump",
            vulnerable_pattern=r"Java\s*Heap\s*Dump|JAVA\s*PROFILE",
            impact="Heap dump download available — sensitive in-memory data (credentials, tokens) can be extracted",
            severity="critical",
            url_template="{base}/actuator/heapdump",
            method="GET",
        ),
        Probe(
            id="spring_actuator_listing",
            vulnerable_pattern=r"""href="[/\w]+actuator""",
            impact="Actuator endpoint listing exposed — multiple sensitive management endpoints discoverable",
            severity="high",
            url_template="{base}/actuator/",
            method="GET",
        ),
        Probe(
            id="spring_spel_injection",
            vulnerable_pattern=r"49",
            impact="SpEL injection in request parameters — arithmetic evaluation via ${7*7} syntax",
            severity="critical",
            url_template="{base}/?${7*7}",
            method="GET",
            false_positive_check=r"404|Not Found",
        ),
        Probe(
            id="spring_swagger_ui",
            vulnerable_pattern=r"(swagger|openapi|api-docs|Swagger UI)",
            impact="Swagger UI / API docs exposed — API surface disclosure without authentication",
            severity="medium",
            url_template="{base}/swagger-ui.html",
            method="GET",
        ),
    ],
    "rails": [
        Probe(
            id="rails_mass_assignment",
            vulnerable_pattern=r"(admin|role|permission).*(?:true|granted)",
            impact="Mass assignment via JSON params — potential privilege escalation through parameter pollution",
            severity="high",
            url_template="{base}/users",
            method="POST",
            data_template=json.dumps({"user": {"admin": True}}),
            detection_headers={"Content-Type": "application/json"},
        ),
        Probe(
            id="rails_csrf_forgery",
            vulnerable_pattern=r"Cross-Site Request Forgery|InvalidAuthenticityToken",
            impact="CSRF token validation potentially bypassable — empty X-CSRF-Token accepted",
            severity="high",
            url_template="{base}/",
            method="POST",
            data_template="_method=post",
            detection_headers={"X-CSRF-Token": ""},
        ),
        Probe(
            id="rails_send_file_traversal",
            vulnerable_pattern=r"(?i)(root:|etc/passwd|boot\.ini|windows)",
            impact="send_file path traversal in file-download endpoints — arbitrary file read",
            severity="critical",
            url_template="{base}/download?file=../../../../etc/passwd",
            method="GET",
        ),
        Probe(
            id="rails_version_disclosure",
            vulnerable_pattern=r"(Rails\s*\d+\.\d+|X-Rails|rails-\d+\.\d+)",
            impact="Rails version disclosed in error pages or headers — helps attackers target version-specific CVEs",
            severity="low",
            url_template="{base}/rails/info",
            method="GET",
        ),
    ],
    "laravel": [
        Probe(
            id="laravel_app_debug",
            vulnerable_pattern=r"(Whoops\\\Exception\\\ErrorException|laravel.*stack trace)",
            impact="APP_DEBUG enabled — full stack traces with file paths, query logs, and env values leaked",
            severity="high",
            url_template="{base}/_debug",
            method="GET",
        ),
        Probe(
            id="laravel_env_exposure",
            vulnerable_pattern=r"APP_KEY=|DB_HOST=|DB_DATABASE=",
            impact=".env file exposed — database credentials, app key, and other secrets leaked",
            severity="critical",
            url_template="{base}/.env",
            method="GET",
            false_positive_check=r"404 Not Found",
        ),
        Probe(
            id="laravel_queue_injection",
            vulnerable_pattern=r"(serialize|O:\d+:|__PHP_Incomplete_Class)",
            impact="Queue deserialization via _token param — potential PHP object injection",
            severity="high",
            url_template="{base}/queue/work",
            method="POST",
            data_template="_token=O:1:\"A\":0:{}&job=test",
        ),
        Probe(
            id="laravel_debug_toolbar",
            vulnerable_pattern=r"(laravel-debugbar|phpdebugbar|debugbar\.widget)",
            impact="Laravel Debugbar exposed — SQL queries, session data, and request info leaked",
            severity="medium",
            url_template="{base}/",
            method="GET",
            detection_headers={},
        ),
    ],
    "graphql": [
        Probe(
            id="graphql_batch_abuse",
            vulnerable_pattern=r"""\[\{.*"data".*\}""",
            impact="GraphQL batch query accepted — attackers can send multiple queries in one request for brute-force",
            severity="high",
            url_template="{base}/graphql",
            method="POST",
            data_template=json.dumps([{"query": "{__typename}"}, {"query": "{__typename}"}]),
            detection_headers={"Content-Type": "application/json"},
        ),
        Probe(
            id="graphql_alias_bypass",
            vulnerable_pattern=r"\"__typename\"",
            impact="Alias-based introspection works — rate limit bypass via field aliasing",
            severity="medium",
            url_template="{base}/graphql",
            method="POST",
            data_template=json.dumps({
                "query": "query { a: __typename b: __typename c: __typename d: __typename e: __typename f: __typename }",
            }),
            detection_headers={"Content-Type": "application/json"},
        ),
        Probe(
            id="graphql_depth_attack",
            vulnerable_pattern=r"(timeout|Complexity|depth|100ms|200ms|error.*depth)",
            impact="Deeply nested query accepted — potential DoS through query depth explosion",
            severity="medium",
            url_template="{base}/graphql",
            method="POST",
            data_template=json.dumps({
                "query": "query { user { friends { friends { friends { friends { friends { id } } } } } } }",
            }),
            detection_headers={"Content-Type": "application/json"},
        ),
    ],
}


FRAMEWORK_DETECTORS: list[tuple[str, list[str]]] = [
    ("wordpress", [r"/wp-content/", r"wp-json", r"/xmlrpc\.php"]),
    ("spring", [r"/actuator/", r"/swagger-ui"]),
    ("rails", [r"/assets/rails\.png", r"/rails/info"]),
    ("laravel", [r"/vendor/laravel", r"/artisan"]),
    ("graphql", [r"/graphql", r"/graphiql", r"/v1/graphql"]),
]


def detect_framework(url: str) -> str | None:
    for framework, patterns in FRAMEWORK_DETECTORS:
        for pat in patterns:
            if re.search(pat, url, re.IGNORECASE):
                return framework
    return None


class TechSpecificScannerRegistry:
    def __init__(self):
        self._probe_sets: dict[str, list[Probe]] = {}
        for fw_name, probes in FRAMEWORK_PROBES.items():
            self._probe_sets[fw_name] = list(probes)

    def register_probe_set(self, framework: str, probes: list[Probe]) -> None:
        self._probe_sets[framework] = probes

    def get_probes_for_framework(self, framework: str) -> list[Probe]:
        return list(self._probe_sets.get(framework, []))

    def get_supported_frameworks(self) -> list[str]:
        return list(self._probe_sets.keys())

    def scan_framework(
        self, base_url: str, framework: str, session: Any
    ) -> list[dict]:
        findings_list: list[dict] = []
        probes = self._probe_sets.get(framework, [])
        base = base_url.rstrip("/")

        log(f"[*] Running {len(probes)} probes for {framework} on {base}", Colors.CYAN)

        for probe in probes:
            url = probe.url_template.format(base=base)
            headers = dict(probe.detection_headers) if probe.detection_headers else {}

            try:
                if probe.method.upper() == "POST":
                    data = probe.data_template or ""
                    if isinstance(data, str) and probe.detection_headers.get("Content-Type") == "application/json":
                        resp = safe_post(
                            session, url, data=data,
                            timeout=10, raise_for_status=False,
                            headers=headers,
                        )
                    else:
                        resp = safe_post(
                            session, url, data=data,
                            timeout=10, raise_for_status=False,
                            headers=headers,
                        )
                else:
                    resp = safe_get(
                        session, url, timeout=10, raise_for_status=False,
                        headers=headers,
                    )

                if resp is None:
                    continue

                body = resp.text
                status = resp.status_code

                if status in (404, 405, 501):
                    continue

                match = re.search(probe.vulnerable_pattern, body, re.IGNORECASE | re.DOTALL)
                if not match:
                    continue

                if probe.false_positive_check:
                    fp_match = re.search(probe.false_positive_check, body, re.IGNORECASE)
                    if fp_match:
                        continue

                severity = probe.severity
                excerpt = body[:500]
                curl_cmd = _build_curl(probe.method, url, headers, data=probe.data_template)

                f = finding(
                    vuln_type=f"{framework.title()} Probe: {probe.id}",
                    url=url,
                    severity=severity,
                    details=probe.impact,
                    evidence=f"Pattern matched: {probe.vulnerable_pattern}",
                    request=curl_cmd,
                    response_excerpt=excerpt,
                    steps_to_reproduce=[
                        f"Send {probe.method} request to {url}",
                        f"Check response for pattern: {probe.vulnerable_pattern}",
                        probe.impact,
                    ],
                    verification_stage=VerificationStage.DETECTED.value,
                )

                if f:
                    req_ev = HttpRequestEvidence(
                        method=probe.method,
                        url=url,
                        headers=headers,
                        body=probe.data_template or "",
                        curl_command=curl_cmd,
                        description=f"{probe.id} probe request",
                    )
                    resp_ev = ResponseExcerptEvidence(
                        excerpt=excerpt,
                        length=len(body),
                        context=probe.id,
                        description=f"{probe.id} probe response excerpt",
                    )
                    ev_list = [str(f.get("evidence", "")), req_ev, resp_ev]
                    f["evidence"] = ev_list

                    findings_list.append(f)

                    log(
                        f"  [FOUND] [{severity.upper()}] {probe.id} @ {url}",
                        Colors.RED if severity in ("critical", "high") else Colors.YELLOW,
                    )

            except Exception as e:
                log(f"  [!] Error running probe {probe.id}: {e}", Colors.WHITE)
                continue

        return findings_list

    def scan_all(
        self,
        base_urls: list[str],
        detected_frameworks: dict[str, list[str]],
        session: Any,
    ) -> list[dict]:
        all_findings: list[dict] = []

        for url in base_urls:
            base = url.rstrip("/")
            frameworks = detected_frameworks.get(base, [])

            auto_fw = detect_framework(url)
            if auto_fw and auto_fw not in frameworks:
                frameworks.append(auto_fw)

            for fw_name in frameworks:
                results = self.scan_framework(base, fw_name, session)
                all_findings.extend(results)

            if not frameworks:
                for fw_name in self._probe_sets:
                    results = self.scan_framework(base, fw_name, session)
                    all_findings.extend(results)

        return all_findings
