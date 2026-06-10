from typing import Any

from models.finding import Finding
from models.evidence import EvidenceBase, EvidenceType
from models.escalation import EscalationPath, EscalationResult
from engines.root_cause import classify_root_cause


SENSITIVE_DATA_PATTERNS: dict[str, list[str]] = {
    "pii": ["email", "ssn", "address", "phone", "name", "dob", "passport"],
    "financial": ["card", "payment", "balance", "transaction", "invoice", "billing"],
    "credentials": ["password", "secret", "token", "api_key", "auth", "session"],
    "internal": ["internal", "admin", "config", "env", ".env", "debug", "health"],
}

ESCALATION_MAP: dict[str, list[dict[str, Any]]] = {
    "idor": [
        {"path_type": "sensitive_data", "target": "user_profile",
         "description": "Attempt to access user profile data (email, phone, address) via IDOR",
         "impact_if_confirmed": "Access to PII of other users",
         "estimated_effort": "low", "confidence_gain": 25},
        {"path_type": "sensitive_data", "target": "payment_methods",
         "description": "Check if payment/billing information of other users is accessible",
         "impact_if_confirmed": "Access to financial data of other users",
         "estimated_effort": "low", "confidence_gain": 25},
        {"path_type": "sensitive_data", "target": "admin_panel",
         "description": "Attempt to access admin-level resources via identifier enumeration",
         "impact_if_confirmed": "Privilege escalation to admin access",
         "estimated_effort": "medium", "confidence_gain": 30},
        {"path_type": "account_modification", "target": "account_settings",
         "description": "Check if account settings (email, password) can be modified via IDOR",
         "impact_if_confirmed": "Account takeover via settings modification",
         "estimated_effort": "medium", "confidence_gain": 30},
    ],
    "ssrf": [
        {"path_type": "internal_service", "target": "cloud_metadata",
         "description": "Attempt to access cloud metadata service (169.254.169.254 for AWS/GCP/Azure)",
         "impact_if_confirmed": "Cloud instance credentials compromised",
         "estimated_effort": "low", "confidence_gain": 35},
        {"path_type": "internal_service", "target": "internal_services",
         "description": "Probe internal network services (Redis, MySQL, Elasticsearch, internal APIs)",
         "impact_if_confirmed": "Internal network pivot and lateral movement",
         "estimated_effort": "medium", "confidence_gain": 25},
        {"path_type": "internal_service", "target": "container_metadata",
         "description": "Check container metadata endpoints (Docker socket, k8s API)",
         "impact_if_confirmed": "Container escape or cluster compromise",
         "estimated_effort": "medium", "confidence_gain": 30},
        {"path_type": "file_read", "target": "local_files",
         "description": "Use file:// protocol to read local server files",
         "impact_if_confirmed": "Source code and configuration disclosure",
         "estimated_effort": "low", "confidence_gain": 25},
    ],
    "xss": [
        {"path_type": "persistence", "target": "stored_xss",
         "description": "Check if XSS payload persists to database and renders for other users",
         "impact_if_confirmed": "Stored XSS affects all users visiting the page",
         "estimated_effort": "high", "confidence_gain": 30},
        {"path_type": "privilege_context", "target": "admin_session",
         "description": "Check if XSS executes in admin/privileged context",
         "impact_if_confirmed": "Admin session hijacking, full account takeover",
         "estimated_effort": "medium", "confidence_gain": 25},
        {"path_type": "sensitive_data", "target": "csrf_token_exfiltration",
         "description": "Demonstrate CSRF token exfiltration via XSS",
         "impact_if_confirmed": "Chained XSS+CSRF for privileged actions",
         "estimated_effort": "medium", "confidence_gain": 20},
    ],
    "sqli": [
        {"path_type": "data_exfiltration", "target": "database_schema",
         "description": "Extract database schema (table names, column names) via SQLi",
         "impact_if_confirmed": "Full database schema disclosure",
         "estimated_effort": "low", "confidence_gain": 20},
        {"path_type": "data_exfiltration", "target": "credentials",
         "description": "Extract user credentials table via SQLi",
         "impact_if_confirmed": "Mass credential compromise",
         "estimated_effort": "medium", "confidence_gain": 30},
        {"path_type": "privilege_escalation", "target": "file_read",
         "description": "Use LOAD_FILE or bulk insert to read server files",
         "impact_if_confirmed": "Server file disclosure, potential RCE",
         "estimated_effort": "medium", "confidence_gain": 25},
    ],
    "ssti": [
        {"path_type": "rce", "target": "remote_code_execution",
         "description": "Escalate SSTI to remote code execution via template engine builtins",
         "impact_if_confirmed": "Full server compromise",
         "estimated_effort": "medium", "confidence_gain": 35},
        {"path_type": "file_read", "target": "sensitive_files",
         "description": "Read server-side files via template engine file primitives",
         "impact_if_confirmed": "Source code and configuration disclosure",
         "estimated_effort": "low", "confidence_gain": 20},
    ],
    "lfi": [
        {"path_type": "rce", "target": "log_poisoning",
         "description": "Attempt log poisoning via LFI + User-Agent injection to achieve RCE",
         "impact_if_confirmed": "Remote code execution via log poisoning",
         "estimated_effort": "medium", "confidence_gain": 30},
        {"path_type": "sensitive_data", "target": "source_code",
         "description": "Read application source code via LFI",
         "impact_if_confirmed": "Full source code disclosure",
         "estimated_effort": "low", "confidence_gain": 20},
        {"path_type": "sensitive_data", "target": "config_files",
         "description": "Read server config files (.env, config.php, web.config, etc.)",
         "impact_if_confirmed": "Database credentials and API keys exposed",
         "estimated_effort": "low", "confidence_gain": 25},
    ],
    "open_redirect": [
        {"path_type": "phishing", "target": "oauth_abuse",
         "description": "Chain open redirect with OAuth flow for token theft",
         "impact_if_confirmed": "Account takeover via OAuth token theft",
         "estimated_effort": "medium", "confidence_gain": 25},
        {"path_type": "phishing", "target": "credential_theft",
         "description": "Create convincing phishing URL using the open redirect",
         "impact_if_confirmed": "Credential theft via phishing",
         "estimated_effort": "low", "confidence_gain": 15},
    ],
    "subdomain_takeover": [
        {"path_type": "account_takeover", "target": "cookie_theft",
         "description": "Host payload on claimed subdomain to steal cookies from parent domain",
         "impact_if_confirmed": "Account takeover of parent domain users",
         "estimated_effort": "high", "confidence_gain": 30},
        {"path_type": "phishing", "target": "phishing_page",
         "description": "Host convincing phishing page on claimed subdomain",
         "impact_if_confirmed": "Credential theft via trusted subdomain",
         "estimated_effort": "low", "confidence_gain": 15},
    ],
}


class ImpactEscalationAnalyzer:
    """Identifies opportunities to demonstrate stronger impact.

    For each validated finding, determines the next escalation paths
    that would increase impact proof. Does NOT execute any action —
    only recommends safe investigation paths.
    """

    @classmethod
    def analyze(cls, finding: Finding, asset_graph: Any = None) -> EscalationResult:
        vuln_type = (finding.vuln_type or "").lower()
        title = (finding.title or "").lower()
        combined = f"{vuln_type} {title}"

        severity = finding.severity or "info"

        matched_key = cls._match_vuln_type(combined)
        escalation_defs = ESCALATION_MAP.get(matched_key, [])

        paths = []
        for edef in escalation_defs:
            path = EscalationPath(
                path_type=edef["path_type"],
                target=edef["target"],
                description=edef["description"],
                impact_if_confirmed=edef["impact_if_confirmed"],
                estimated_effort=edef.get("estimated_effort", "medium"),
                confidence_gain=edef.get("confidence_gain", 20),
                unsafe=False,
            )
            paths.append(path)

        worst_case = cls._determine_worst_case(paths, severity)

        return EscalationResult(
            finding_fingerprint=finding.fingerprint or "",
            vuln_type=finding.vuln_type or "",
            current_impact=f"Current severity: {severity}",
            escalation_paths=paths,
            worst_case_impact=worst_case,
            has_safe_paths=True,
        )

    @classmethod
    def analyze_all(cls, findings: list[Finding], asset_graph: Any = None) -> list[EscalationResult]:
        return [cls.analyze(f, asset_graph=asset_graph) for f in findings]

    @classmethod
    def _match_vuln_type(cls, combined: str) -> str | None:
        for key in ESCALATION_MAP:
            if key in combined:
                return key
        for key in ESCALATION_MAP:
            words = key.split("_")
            if any(w in combined for w in words if len(w) > 3):
                return key
        return None

    @classmethod
    def _determine_worst_case(cls, paths: list[EscalationPath], current_severity: str) -> str:
        impact_rank = {
            "rce": "Remote Code Execution",
            "account_takeover": "Account Takeover",
            "cloud_compromise": "Cloud Compromise",
            "privilege_escalation": "Privilege Escalation",
            "data_exfiltration": "Mass Data Exfiltration",
            "phishing": "Phishing Attack Surface",
        }
        for p in paths:
            for keyword, label in impact_rank.items():
                if keyword in p.impact_if_confirmed.lower():
                    return label
        return f"Confirmed {current_severity} impact"
