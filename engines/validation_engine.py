import json
import time
import threading
from typing import Any

from modules.utils import (
    OOBDetectionFramework,
    BrowserValidator,
    SecretValidator,
    safe_get,
    safe_post,
)
from models.evidence import (
    EvidenceBase,
    EvidenceStatus,
    EvidenceType,
    OOBCallbackEvidence,
    BrowserExecutionEvidence,
    TimingEvidence,
    SecretValidationEvidence,
    AuthorizationComparisonEvidence,
    GraphQLSchemaEvidence,
)
from models.config import ScanConfig


class ValidationEngine:
    """Centralized validation layer wrapping OOB, Browser, Secret, Timing, Auth, and GraphQL validation.

    Decommission plan:
    - Phase 2: build here, scanners call through this engine
    - Phase 3: scanners call directly (inline OOB/browser calls removed from scanner.py)
    """

    def __init__(
        self,
        config: ScanConfig | dict[str, Any],
        capabilities: Any | None = None,
    ):
        self.config = config
        self._capabilities = capabilities
        cfg_dict = config if isinstance(config, dict) else config.to_dict()

        # Normalize capabilities to support both CapabilityRegistry and plain dict
        def _has_cap(name: str) -> bool:
            if capabilities is None:
                return False
            if hasattr(capabilities, "has"):
                return capabilities.has(name)
            if isinstance(capabilities, dict):
                return capabilities.get(name, False)
            return False

        def _browser_available() -> bool:
            if capabilities is None:
                return False
            if hasattr(capabilities, "browser_validation"):
                return capabilities.browser_validation
            if isinstance(capabilities, dict):
                return capabilities.get("playwright", False) and capabilities.get("chromium", False)
            return False

        if not _has_cap("oob_validation"):
            self._oob = None
        else:
            self._oob = OOBDetectionFramework(cfg_dict)

        if not _browser_available():
            self._browser = None
        else:
            self._browser = BrowserValidator(cfg_dict)

        self._lock = threading.Lock()

    # ── OOB Confirmation ─────────────────────────────────────────────────

    @property
    def callback_host(self) -> str:
        if self._oob is None:
            return ""
        return self._oob.callback_host

    @property
    def callback_url(self) -> str:
        if self._oob is None:
            return ""
        return self._oob.callback_url

    def generate_oob_payload(self, placeholder: str = "{oob}") -> str:
        if self._oob is None:
            return ""
        return self._oob.generate_payload(placeholder)

    def register_oob(self, vuln_type: str, payload: str, url: str,
                     fingerprint: str = "") -> None:
        if self._oob is None:
            return
        self._oob.register_interaction(vuln_type, payload, url, fingerprint)

    def poll_oob(self, timeout: float = 120.0) -> list[OOBCallbackEvidence]:
        """Poll for OOB callbacks and return structured evidence.

        Every returned OOBCallbackEvidence is populated with:
          callback_type, callback_host, callback_token,
          interaction_time (entry timestamp), raw_data (full entry dict).
        """
        if self._oob is None:
            return []
        confirmed = self._oob.poll(timeout=timeout)
        results: list[OOBCallbackEvidence] = []
        for entry in confirmed:
            entry_ts = entry.get("timestamp", time.time())
            if isinstance(entry_ts, (int, float)):
                interaction_time = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(entry_ts))
            else:
                interaction_time = str(entry_ts)

            ev = OOBCallbackEvidence(
                callback_type="dns" if self._oob._dnslog_domain else "http",
                callback_host=self._oob.callback_host,
                callback_token=entry.get("token", self._oob.callback_token),
                interaction_time=interaction_time,
                raw_data=json.dumps(entry, default=str),
                description=f"OOB callback confirmed @ {entry.get('url', '')}",
                status=EvidenceStatus.VERIFIED,
            )
            ev._original_url = entry.get("url", "")
            results.append(ev)
        return results

    def confirm_oob(self, vuln_type: str, url: str, payload: str) -> OOBCallbackEvidence | None:
        """Register an OOB interaction and poll once. Returns evidence if confirmed."""
        self.register_oob(vuln_type, payload, url)
        time.sleep(1)
        results = self.poll_oob()
        for ev in results:
            if ev.callback_host in payload or vuln_type in str(ev.raw_data):
                return ev
        return None

    # ── Browser Execution Confirmation ───────────────────────────────────

    def confirm_browser_xss(
        self,
        url: str,
        payload: str,
        html_content: str | None = None,
        screenshot_dir: str | None = None,
    ) -> BrowserExecutionEvidence | None:
        """Validate XSS execution in headless browser. Returns evidence or None."""
        if self._browser is None:
            return None
        result = self._browser.check_xss_execution(
            url=url,
            payload=payload,
            html_content=html_content,
            screenshot_dir=screenshot_dir,
        )
        if not result:
            return None
        return BrowserExecutionEvidence(
            alert_fired=result.get("alert_fired", False),
            dom_mutation=result.get("dom_mutation", False),
            screenshot_path=result.get("screenshot_path", ""),
            execution_context="set_content" if html_content else "goto",
            description=f"Browser XSS validation: alert={result.get('alert_fired')}, dom={result.get('dom_mutation')}",
            status=EvidenceStatus.VERIFIED
            if result.get("alert_fired") or result.get("dom_mutation")
            else EvidenceStatus.FAILED,
        )

    def scan_dom_xss(self, url: str, probes: list[str]) -> list[BrowserExecutionEvidence]:
        """Scan for DOM-based XSS sinks. Returns list of evidence per sink."""
        if self._browser is None:
            return []
        raw = self._browser.scan_dom_xss(url, probes)
        results: list[BrowserExecutionEvidence] = []
        for r in raw:
            ev = BrowserExecutionEvidence(
                alert_fired=r.get("executed", False),
                dom_mutation=r.get("executed", False),
                execution_context=r.get("sink", "unknown"),
                description=f"DOM XSS sink '{r.get('sink', '?')}' triggered by probe '{r.get('probe', '?')}'",
                status=EvidenceStatus.VERIFIED if r.get("executed") else EvidenceStatus.FAILED,
            )
            results.append(ev)
        return results

    def close_browser(self) -> None:
        if self._browser is not None:
            self._browser.close()

    # ── Timing Verification ──────────────────────────────────────────────

    def verify_timing(
        self,
        session: Any,
        url: str,
        baseline_payload: str,
        trigger_payload: str,
        param_name: str,
        threshold_ms: float = 4000.0,
        samples: int = 1,
    ) -> TimingEvidence | None:
        """Measure baseline vs trigger response times. Returns evidence if delay exceeds threshold."""
        baseline_times: list[float] = []
        trigger_times: list[float] = []

        # Baseline
        for _ in range(max(samples, 1)):
            bl_url = _inject_param(url, param_name, baseline_payload)
            start = time.time()
            safe_get(session, bl_url, timeout=30, raise_for_status=False)
            elapsed = (time.time() - start) * 1000
            baseline_times.append(elapsed)

        # Trigger
        for _ in range(max(samples, 1)):
            tr_url = _inject_param(url, param_name, trigger_payload)
            start = time.time()
            safe_get(session, tr_url, timeout=30, raise_for_status=False)
            elapsed = (time.time() - start) * 1000
            trigger_times.append(elapsed)

        avg_baseline = sum(baseline_times) / len(baseline_times) if baseline_times else 0
        avg_trigger = sum(trigger_times) / len(trigger_times) if trigger_times else 0

        if avg_trigger - avg_baseline >= threshold_ms:
            return TimingEvidence(
                baseline_time_ms=avg_baseline,
                triggered_time_ms=avg_trigger,
                delay_threshold_ms=threshold_ms,
                total_attempts=samples * 2,
                description=f"Timing-based confirmation: +{avg_trigger - avg_baseline:.0f}ms vs baseline {avg_baseline:.0f}ms",
                status=EvidenceStatus.VERIFIED,
            )
        return TimingEvidence(
            baseline_time_ms=avg_baseline,
            triggered_time_ms=avg_trigger,
            delay_threshold_ms=threshold_ms,
            total_attempts=samples * 2,
            description=f"Timing check: +{avg_trigger - avg_baseline:.0f}ms (below {threshold_ms:.0f}ms threshold)",
            status=EvidenceStatus.FAILED,
        )

    # ── Secret Validation ────────────────────────────────────────────────

    def verify_secret(self, secret_type: str, value: str, **kwargs: Any) -> SecretValidationEvidence:
        """Validate a discovered secret against its live API."""
        validation_map = {
            "aws": lambda: SecretValidator.validate_aws_key(value, kwargs.get("secret_key")),
            "github": lambda: SecretValidator.validate_github_token(value),
            "slack": lambda: SecretValidator.validate_slack_token(value),
            "twilio": lambda: SecretValidator._has_long_run(value),
        }
        validator = validation_map.get(secret_type)
        if not validator:
            return SecretValidationEvidence(
                secret_type=secret_type,
                validation_method="none",
                is_valid=False,
                description=f"No validator for secret type '{secret_type}'",
                status=EvidenceStatus.FAILED,
            )
        result = validator()
        return SecretValidationEvidence(
            secret_type=secret_type,
            validation_method=f"live_api_{secret_type}",
            is_valid=bool(result.get("valid")),
            api_response=result.get("details", ""),
            description=f"Secret validation ({secret_type}): {'valid' if result.get('valid') else 'invalid or unknown'}",
            status=EvidenceStatus.VERIFIED if result.get("valid") else EvidenceStatus.FAILED,
        )

    # ── Authorization Verification ───────────────────────────────────────

    def verify_authorization(
        self,
        url: str,
        session_original: Any,
        session_target: Any,
        method: str = "GET",
        data: dict | None = None,
    ) -> AuthorizationComparisonEvidence | None:
        """Compare response between original and target user sessions."""
        if method == "POST":
            resp_orig = safe_post(session_original, url, data or {}, timeout=10, raise_for_status=False)
            resp_targ = safe_post(session_target, url, data or {}, timeout=10, raise_for_status=False)
        else:
            resp_orig = safe_get(session_original, url, timeout=10, raise_for_status=False)
            resp_targ = safe_get(session_target, url, timeout=10, raise_for_status=False)

        if not resp_orig or not resp_targ:
            return None

        content_diff = resp_targ.text != resp_orig.text
        same_status = resp_orig.status_code == resp_targ.status_code

        return AuthorizationComparisonEvidence(
            original_user="user_a",
            target_user="user_b",
            original_status=resp_orig.status_code,
            target_status=resp_targ.status_code,
            content_different=content_diff,
            ownership_violated=(content_diff and same_status and resp_targ.status_code == 200),
            original_body_excerpt=resp_orig.text[:200],
            target_body_excerpt=resp_targ.text[:200],
            description=f"Authorization check: user_a vs user_b @ {url} — {'violation' if content_diff and same_status else 'no violation'}",
            status=EvidenceStatus.VERIFIED
            if (content_diff and same_status and resp_targ.status_code == 200)
            else EvidenceStatus.COLLECTED,
        )

    # ── GraphQL Execution ────────────────────────────────────────────────

    def execute_graphql(
        self,
        session: Any,
        url: str,
        query: str,
        variables: dict | None = None,
    ) -> GraphQLSchemaEvidence | None:
        """Execute a GraphQL query and return schema evidence."""
        import json
        try:
            payload: dict[str, Any] = {"query": query}
            if variables:
                payload["variables"] = variables
            resp = session.post(url, json=payload, timeout=10)
            if resp.status_code != 200:
                return None
            data = resp.json()
            return GraphQLSchemaEvidence(
                query_text=query,
                schema_preview=json.dumps(data.get("data", {}), indent=2)[:500],
                operation_name=query.split("{")[0].strip() if "{" in query else "",
                description=f"GraphQL query executed against {url}",
                status=EvidenceStatus.VERIFIED,
            )
        except Exception:
            return None

    # ── Lifecycle ────────────────────────────────────────────────────────

    def cleanup(self) -> None:
        self.close_browser()
        if self._oob is not None:
            self._oob.clear()


# ── Utility ──────────────────────────────────────────────────────────────────

def _inject_param(url: str, param: str, value: str) -> str:
    """Replace or add a query parameter in a URL."""
    from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [value]
    new_query = urlencode(params, doseq=True)
    return urlunparse(parsed._replace(query=new_query))
