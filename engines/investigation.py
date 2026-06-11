import hashlib
import time as time_module
from typing import Any

import requests

from modules.utils import build_role_sessions, log, Colors, safe_get

from models.finding import Finding, calculate_confidence, ConfidenceLevel
from models.evidence import EvidenceType, EvidenceStatus
from models.evidence import (
    BrowserExecutionEvidence, OOBCallbackEvidence, TimingEvidence,
    HttpRequestEvidence, HttpResponseEvidence, ResponseDiffEvidence,
    AuthorizationComparisonEvidence,
)
from models.investigation import InvestigationTask, InvestigationPlan, InvestigationResult
from engines.evidence_quality import EvidenceQualityEngine


STRATEGY_REGISTRY: dict[str, dict[str, Any]] = {
    "horizontal_idor": {
        "capability": "none",
        "cost": 2,
        "priority": 80,
        "description": "Try horizontal access (same role, different resource)",
    },
    "vertical_idor": {
        "capability": "none",
        "cost": 2,
        "priority": 70,
        "description": "Try vertical access (different privilege level)",
    },
    "ownership_validation": {
        "capability": "none",
        "cost": 3,
        "priority": 90,
        "description": "Prove ownership violation with before/after comparison",
    },
    "browser_xss": {
        "capability": "playwright",
        "cost": 5,
        "priority": 85,
        "description": "Validate XSS in headless browser context",
    },
    "stored_xss_check": {
        "capability": "playwright",
        "cost": 8,
        "priority": 75,
        "description": "Check if XSS payload persists across requests",
    },
    "dom_xss_check": {
        "capability": "playwright",
        "cost": 6,
        "priority": 70,
        "description": "Check for DOM-based XSS sinks",
    },
    "oob_ssrf": {
        "capability": "oob",
        "cost": 3,
        "priority": 90,
        "description": "Confirm SSRF via OOB callback",
    },
    "ssrf_internal": {
        "capability": "none",
        "cost": 3,
        "priority": 85,
        "description": "Probe internal network targets (localhost, RFC 1918) via SSRF",
    },
    "ssrf_cloud_metadata": {
        "capability": "none",
        "cost": 2,
        "priority": 80,
        "description": "Attempt cloud metadata service access (AWS/GCP/Azure IMDS)",
    },
    "oob_cmdi": {
        "capability": "oob",
        "cost": 3,
        "priority": 85,
        "description": "Confirm command injection via OOB callback",
    },
    "oob_xxe": {
        "capability": "oob",
        "cost": 3,
        "priority": 85,
        "description": "Confirm XXE via OOB callback",
    },
    "oob_sqli": {
        "capability": "oob",
        "cost": 3,
        "priority": 85,
        "description": "Confirm SQLi via OOB callback",
    },
    "timing_sqli": {
        "capability": "none",
        "cost": 4,
        "priority": 60,
        "description": "Time-based SQLi confirmation",
    },
    "boolean_sqli": {
        "capability": "none",
        "cost": 6,
        "priority": 50,
        "description": "Boolean-based SQLi confirmation",
    },
    "error_sqli": {
        "capability": "none",
        "cost": 2,
        "priority": 40,
        "description": "Error-based SQLi pattern matching",
    },
    "lfi_file_read": {
        "capability": "none",
        "cost": 4,
        "priority": 75,
        "description": "Confirm LFI by reading known files",
    },
    "ssti_eval": {
        "capability": "none",
        "cost": 4,
        "priority": 75,
        "description": "Confirm SSTI via template evaluation",
    },
    "ssti_oob": {
        "capability": "oob",
        "cost": 3,
        "priority": 85,
        "description": "Confirm SSTI via OOB callback",
    },
    "open_redirect_follow": {
        "capability": "none",
        "cost": 1,
        "priority": 50,
        "description": "Follow redirect to confirm off-domain destination",
    },
    "replay_with_auth": {
        "capability": "none",
        "cost": 2,
        "priority": 60,
        "description": "Replay finding with authentication context",
    },
    "replay_without_auth": {
        "capability": "none",
        "cost": 1,
        "priority": 50,
        "description": "Replay finding without authentication",
    },
    "cross_account_idor": {
        "capability": "none",
        "cost": 3,
        "priority": 85,
        "description": "Compare responses across multiple role sessions for IDOR detection",
    },
    "differential_auth": {
        "capability": "none",
        "cost": 4,
        "priority": 80,
        "description": "Field-level JSON comparison with sensitivity classification across roles",
    },
}

VULN_STRATEGY_MAP: dict[str, list[str]] = {
    "xss": ["browser_xss", "stored_xss_check", "dom_xss_check"],
    "reflected xss": ["browser_xss", "dom_xss_check"],
    "dom xss": ["dom_xss_check", "browser_xss"],
    "dom-based xss": ["dom_xss_check", "browser_xss"],
    "confirmed xss": ["browser_xss", "stored_xss_check"],
    "sqli": ["timing_sqli", "boolean_sqli", "error_sqli", "oob_sqli"],
    "sql injection": ["timing_sqli", "boolean_sqli", "error_sqli", "oob_sqli"],
    "ssrf": ["oob_ssrf", "ssrf_internal", "ssrf_cloud_metadata"],
    "xxe": ["oob_xxe"],
    "ssti": ["ssti_eval", "ssti_oob"],
    "cmd_injection": ["oob_cmdi"],
    "command injection": ["oob_cmdi"],
    "lfi": ["lfi_file_read"],
    "idor": ["cross_account_idor", "horizontal_idor", "vertical_idor", "ownership_validation", "differential_auth"],
    "potential idor": ["cross_account_idor", "horizontal_idor", "vertical_idor", "ownership_validation"],
    "authorization": ["cross_account_idor", "horizontal_idor", "vertical_idor", "ownership_validation", "differential_auth"],
    "open_redirect": ["open_redirect_follow"],
    "open redirect": ["open_redirect_follow"],
    "bola": ["horizontal_idor", "vertical_idor"],
    "graphql": ["replay_with_auth", "replay_without_auth"],
}

CONFIDENCE_BOOST: dict[str, int] = {
    "horizontal_idor": 15,
    "vertical_idor": 20,
    "ownership_validation": 35,
    "browser_xss": 40,
    "stored_xss_check": 30,
    "dom_xss_check": 35,
    "oob_ssrf": 40,
    "ssrf_internal": 25,
    "ssrf_cloud_metadata": 35,
    "oob_cmdi": 40,
    "oob_xxe": 40,
    "oob_sqli": 40,
    "timing_sqli": 15,
    "boolean_sqli": 15,
    "error_sqli": 10,
    "lfi_file_read": 35,
    "ssti_eval": 35,
    "ssti_oob": 40,
    "open_redirect_follow": 15,
    "replay_with_auth": 10,
    "replay_without_auth": 5,
    "cross_account_idor": 30,
    "differential_auth": 35,
}


class InvestigationPlanner:
    """Chooses the best validation strategy for a finding based on capabilities, resources, and confidence gain."""

    def __init__(self, capabilities: dict[str, bool] | None = None):
        self.capabilities = capabilities or {}

    @staticmethod
    def _match_strategies(vuln_type: str) -> list[str]:
        if vuln_type in VULN_STRATEGY_MAP:
            return list(VULN_STRATEGY_MAP[vuln_type])
        matched: list[tuple[int, list[str]]] = []
        for key, strategies in VULN_STRATEGY_MAP.items():
            if key in vuln_type:
                matched.append((len(key), list(strategies)))
        if matched:
            matched.sort(key=lambda x: -x[0])
            return matched[0][1]
        return []

    def plan(
        self,
        finding: Finding,
        budget: int = 5,
        available_strategies: list[str] | None = None,
    ) -> InvestigationPlan:
        vuln_type = (finding.vuln_type or "").lower()
        candidates = available_strategies or self._match_strategies(vuln_type)

        tasks = []
        for strategy in candidates:
            config = STRATEGY_REGISTRY.get(strategy)
            if not config:
                continue

            cap = config["capability"]
            if cap and cap != "none" and cap not in self.capabilities:
                if not self.capabilities.get(cap, False):
                    continue
            if config["cost"] > budget:
                continue

            tasks.append(InvestigationTask(
                finding_fingerprint=finding.fingerprint,
                strategy=strategy,
                target_url=finding.url,
                estimated_cost=config["cost"],
                priority=config["priority"],
                capability_required=cap,
            ))

        tasks.sort(key=lambda t: -t.priority)
        total_cost = sum(t.estimated_cost for t in tasks)
        while tasks and total_cost > budget:
            removed = tasks.pop()
            total_cost -= removed.estimated_cost

        current_conf = finding.confidence_score or 25
        target_conf = min(100, current_conf + sum(CONFIDENCE_BOOST.get(t.strategy, 0) for t in tasks))

        reason = f"Planned {len(tasks)} investigation tasks for {vuln_type}"
        if tasks:
            reason += f": {', '.join(t.strategy for t in tasks[:3])}"

        return InvestigationPlan(
            finding_fingerprint=finding.fingerprint,
            tasks=tasks,
            current_confidence=current_conf,
            target_confidence=target_conf,
            budget_remaining=budget - total_cost,
            reason=reason,
        )


class InvestigationEngine:
    """Executes investigation plans to increase finding confidence."""

    def __init__(
        self,
        planner: InvestigationPlanner | None = None,
        capabilities: dict[str, bool] | None = None,
        browser: Any = None,
        oob: Any = None,
        session: requests.Session | None = None,
        config: dict[str, Any] | None = None,
    ):
        self.planner = planner or InvestigationPlanner(capabilities)
        self.browser = browser
        self.oob = oob
        self.session = session or requests.Session()
        self.config = config or {}
        self.results: dict[str, list[InvestigationResult]] = {}
        self._evidence_store: list[tuple] = []

    def collect_evidence(self) -> list[tuple]:
        """Return all evidence pairs (evidence, finding_fingerprint) created during investigation."""
        result = list(self._evidence_store)
        self._evidence_store.clear()
        return result

    def _record_evidence(self, evidence: Any, fingerprint: str) -> str:
        """Store evidence and return its fingerprint."""
        raw = hashlib.sha256(str(evidence.to_dict()).encode()).hexdigest()[:16]
        self._evidence_store.append((evidence, fingerprint))
        return raw

    def investigate(
        self,
        finding: Finding,
        budget: int = 5,
        available_strategies: list[str] | None = None,
    ) -> list[InvestigationResult]:
        plan = self.planner.plan(finding, budget, available_strategies)
        results: list[InvestigationResult] = []

        for task in plan.tasks:
            result = self._execute_task(task, finding)
            results.append(result)
            if result.success:
                self._apply_result(finding, result)

        self.results[finding.fingerprint] = results
        return results

    def investigate_all(
        self,
        findings: list[Finding],
        budget_per_finding: int = 5,
        max_findings: int = 20,
    ) -> dict[str, list[InvestigationResult]]:
        low_conf = [
            f for f in findings
            if (f.confidence_score or 0) < 60
            and f.fingerprint
        ]
        low_conf.sort(key=lambda f: -(f.confidence_score or 0))
        candidates = low_conf[:max_findings]

        for f in candidates:
            self.investigate(f, budget=budget_per_finding)

        return self.results

    def _execute_task(self, task: InvestigationTask, finding: Finding) -> InvestigationResult:
        strategy = task.strategy
        fp = finding.fingerprint or ""

        # ── Open Redirect ───────────────────────────────────────────
        if strategy == "open_redirect_follow":
            return self._exec_open_redirect(task, finding)

        # ── Replay ─────────────────────────────────────────────────
        if strategy in ("replay_with_auth", "replay_without_auth"):
            return self._exec_replay(task, finding)

        # ── OOB strategies ─────────────────────────────────────────
        if strategy in ("oob_ssrf", "oob_cmdi", "oob_xxe", "oob_sqli", "ssti_oob"):
            return self._exec_oob(task, finding, strategy)

        # ── SSRF internal / cloud metadata ─────────────────────────
        if strategy in ("ssrf_internal", "ssrf_cloud_metadata"):
            next_s = "ssrf_cloud_metadata" if strategy == "ssrf_internal" else None
            return self._exec_ssrf_probe(task, finding, strategy, next_s)

        # ── Browser XSS strategies ─────────────────────────────────
        if strategy in ("browser_xss", "stored_xss_check", "dom_xss_check"):
            return self._exec_browser(task, finding, strategy)

        # ── IDOR / Authz strategies ───────────────────────────────
        if strategy == "cross_account_idor":
            return self._exec_cross_account_idor(task, finding)
        if strategy == "differential_auth":
            return self._exec_differential_auth(task, finding)
        if strategy in ("horizontal_idor", "vertical_idor", "ownership_validation"):
            return self._exec_idor(task, finding, strategy)

        # ── SQLi confirmation ──────────────────────────────────────
        if strategy in ("timing_sqli", "boolean_sqli", "error_sqli"):
            return self._exec_sqli(task, finding, strategy)

        # ── LFI file read ──────────────────────────────────────────
        if strategy == "lfi_file_read":
            return self._exec_lfi(task, finding)

        # ── SSTI eval ──────────────────────────────────────────────
        if strategy == "ssti_eval":
            return self._exec_ssti(task, finding)

        return self._build_result(task, success=False, delta=0,
            next_strategy=None, evidence_fp="")

    def _build_result(
        self, task: InvestigationTask, success: bool, delta: int,
        next_strategy: str | None, evidence_fp: str,
        reason: str = "",
    ) -> InvestigationResult:
        task.completed = True
        task.result_fingerprint = evidence_fp
        return InvestigationResult(
            task=task,
            evidence_fingerprint=evidence_fp,
            confidence_delta=delta if success else 0,
            success=success,
            next_strategy=next_strategy,
            reason=reason,
        )

    def _make_request(
        self, url: str, finding: Finding, timeout: int = 15,
    ) -> tuple[requests.Response | None, HttpRequestEvidence | None, HttpResponseEvidence | None]:
        """Make an HTTP request and return (response, req_evidence, resp_evidence)."""
        try:
            resp = self.session.get(url, timeout=timeout, allow_redirects=False)
            req_ev = HttpRequestEvidence(
                method="GET", url=url,
                headers=dict(resp.request.headers) if resp.request else {},
                description=f"Investigation probe: {url}",
                status=EvidenceStatus.COLLECTED,
            )
            resp_ev = HttpResponseEvidence(
                status_code=resp.status_code,
                headers=dict(resp.headers),
                body=resp.text[:4000],
                description=f"Response to investigation probe: {url}",
                status=EvidenceStatus.VERIFIED if resp.ok else EvidenceStatus.COLLECTED,
            )
            return resp, req_ev, resp_ev
        except Exception:
            return None, None, None

    def _exec_open_redirect(self, task: InvestigationTask, finding: Finding) -> InvestigationResult:
        resp, req_ev, resp_ev = self._make_request(finding.url, finding, timeout=10)
        if resp is None:
            return self._build_result(task, success=False, delta=0, next_strategy=None, evidence_fp="")
        fp = finding.fingerprint or ""
        if req_ev:
            self._record_evidence(req_ev, fp)
        if resp_ev:
            self._record_evidence(resp_ev, fp)

        location = resp.headers.get("Location", "") or resp.headers.get("location", "")
        if location:
            # Check if redirect goes off-domain
            from urllib.parse import urlparse
            orig_domain = urlparse(finding.url).netloc
            target_domain = urlparse(location).netloc
            if target_domain and target_domain != orig_domain:
                return self._build_result(task, success=True, delta=CONFIDENCE_BOOST.get("open_redirect_follow", 15),
                    next_strategy=None, evidence_fp=self._record_evidence(
                        ResponseDiffEvidence(
                            original_response=finding.response_excerpt or "",
                            new_response=f"Redirect to: {location}",
                            comparison="Location header analysis",
                            status=EvidenceStatus.VERIFIED,
                        ), fp))
        return self._build_result(task, success=False, delta=0, next_strategy=None, evidence_fp="")

    def _exec_replay(self, task: InvestigationTask, finding: Finding) -> InvestigationResult:
        resp, req_ev, resp_ev = self._make_request(finding.url, finding)
        if resp is None:
            return self._build_result(task, success=False, delta=0, next_strategy=None, evidence_fp="")
        fp = finding.fingerprint or ""
        if req_ev:
            self._record_evidence(req_ev, fp)
        if resp_ev:
            self._record_evidence(resp_ev, fp)

        # Replay succeeded if we got a response
        delta = CONFIDENCE_BOOST.get(task.strategy, 10) if resp.ok else 0
        return self._build_result(task, success=resp.ok, delta=delta,
            next_strategy=None, evidence_fp=fp)

    def _exec_oob(self, task: InvestigationTask, finding: Finding, strategy: str) -> InvestigationResult:
        if not self.oob:
            return self._build_result(task, success=False, delta=0, next_strategy=None, evidence_fp="",
                reason="capability_unavailable")
        fp = finding.fingerprint or ""
        payload_url = self.oob.callback_url
        if not payload_url:
            return self._build_result(task, success=False, delta=0, next_strategy=None, evidence_fp="",
                reason="capability_unavailable")

        # Use the target URL param if available
        probe_url = f"{finding.url}&oob={hashlib.md5(payload_url.encode()).hexdigest()[:8]}" if "?" in (finding.url or "") else finding.url
        resp, req_ev, resp_ev = self._make_request(probe_url, finding)
        self.oob.register_interaction(vuln_type=strategy, payload=probe_url, url=finding.url, fingerprint=fp)
        if req_ev:
            self._record_evidence(req_ev, fp)
        if resp_ev:
            self._record_evidence(resp_ev, fp)

        # Poll briefly for the callback
        callbacks = self.oob.poll(timeout=15.0)
        if callbacks:
            cb_ev = OOBCallbackEvidence(
                callback_type="dns",
                callback_host=self.oob.callback_host,
                callback_token=self.oob.callback_token,
                raw_data=str(callbacks),
                status=EvidenceStatus.VERIFIED,
            )
            ev_fp = self._record_evidence(cb_ev, fp)
            return self._build_result(task, success=True,
                delta=CONFIDENCE_BOOST.get(strategy, 40),
                next_strategy=None, evidence_fp=ev_fp)
        return self._build_result(task, success=False, delta=0, next_strategy=None, evidence_fp="")

    def _exec_ssrf_probe(self, task: InvestigationTask, finding: Finding, strategy: str, next_s: str | None) -> InvestigationResult:
        targets = []
        if strategy == "ssrf_cloud_metadata":
            targets = [
                "http://169.254.169.254/latest/meta-data/",
                "http://metadata.google.internal/computeMetadata/v1/",
                "http://100.100.100.200/latest/meta-data/",
            ]
        else:
            targets = [
                "http://127.0.0.1:22/",
                "http://127.0.0.1:80/",
                "http://127.0.0.1:443/",
                "http://localhost/",
            ]

        fp = finding.fingerprint or ""
        probe_url_tmpl = finding.url
        for target in targets:
            probe_url = probe_url_tmpl
            if "?" in (probe_url or ""):
                probe_url = f"{probe_url}&ssrf_url={target}"
            elif probe_url:
                probe_url = f"{probe_url}?ssrf_url={target}"

            resp, req_ev, resp_ev = self._make_request(probe_url, finding, timeout=10)
            if resp is not None and resp.status_code < 500:
                if req_ev:
                    self._record_evidence(req_ev, fp)
                if resp_ev:
                    self._record_evidence(resp_ev, fp)
                return self._build_result(task, success=True,
                    delta=CONFIDENCE_BOOST.get(strategy, 30),
                    next_strategy=next_s,
                    evidence_fp=self._record_evidence(
                        ResponseDiffEvidence(
                            original_response=finding.response_excerpt or "",
                            new_response=f"SSRF probe returned status {resp.status_code} for {target}",
                            comparison=f"SSRF probe via param injection to {target}",
                            status=EvidenceStatus.VERIFIED,
                        ), fp))
        return self._build_result(task, success=False, delta=0, next_strategy=next_s, evidence_fp="")

    def _exec_browser(self, task: InvestigationTask, finding: Finding, strategy: str) -> InvestigationResult:
        if not self.browser:
            return self._build_result(task, success=False, delta=0, next_strategy=None, evidence_fp="",
                reason="capability_unavailable")
        fp = finding.fingerprint or ""

        try:
            result = None
            if strategy == "dom_xss_check":
                result_list = self.browser.scan_dom_xss(finding.url, probes=["<img src=x onerror=alert(1)>"])
                if result_list:
                    result = result_list[0]
            else:
                param_val = finding.parameter or "test"
                result = self.browser.check_xss_execution(finding.url, payload=param_val)

            if result and (result.get("alert_fired") or result.get("dom_mutation")):
                bv_ev = BrowserExecutionEvidence(
                    alert_fired=result.get("alert_fired", False),
                    dom_mutation=result.get("dom_mutation", False),
                    screenshot_path=result.get("screenshot_path", ""),
                    status=EvidenceStatus.VERIFIED,
                )
                ev_fp = self._record_evidence(bv_ev, fp)
                return self._build_result(task, success=True,
                    delta=CONFIDENCE_BOOST.get(strategy, 35),
                    next_strategy=None, evidence_fp=ev_fp)
        except Exception:
            pass
        return self._build_result(task, success=False, delta=0, next_strategy=None, evidence_fp="")

    def _exec_idor(self, task: InvestigationTask, finding: Finding, strategy: str) -> InvestigationResult:
        next_s = None
        if strategy == "horizontal_idor":
            next_s = "vertical_idor"
        elif strategy == "vertical_idor":
            next_s = "ownership_validation"

        role_sessions = build_role_sessions(self.config, self.session)
        if len(role_sessions) < 2:
            return self._build_result(task, success=False, delta=0, next_strategy=next_s, evidence_fp="",
                reason="capability_unavailable")

        fp = finding.fingerprint or ""
        roles = list(role_sessions.keys())
        default_role = roles[0]
        other_roles = roles[1:]
        default_sess = role_sessions[default_role]

        try:
            resp_a = default_sess.get(finding.url, timeout=15, allow_redirects=False)
        except Exception:
            return self._build_result(task, success=False, delta=0, next_strategy=next_s, evidence_fp="")

        req_ev = HttpRequestEvidence(
            method="GET", url=finding.url,
            headers=dict(resp_a.request.headers) if resp_a.request else {},
            description=f"IDOR probe as {default_role}: {finding.url}",
            status=EvidenceStatus.COLLECTED,
        )
        resp_ev = HttpResponseEvidence(
            status_code=resp_a.status_code,
            headers=dict(resp_a.headers),
            body=resp_a.text[:4000],
            description=f"Response as {default_role}: {finding.url}",
            status=EvidenceStatus.VERIFIED if resp_a.ok else EvidenceStatus.COLLECTED,
        )
        self._record_evidence(req_ev, fp)
        self._record_evidence(resp_ev, fp)

        body_a = resp_a.text or ""
        status_a = resp_a.status_code
        success_count = 0

        for alt_role in other_roles:
            alt_sess = role_sessions[alt_role]
            try:
                resp_b = alt_sess.get(finding.url, timeout=10, allow_redirects=False)
            except Exception:
                continue
            body_b = resp_b.text or ""
            status_b = resp_b.status_code

            # Both succeed but bodies differ → data leakage
            if status_a == 200 and status_b == 200 and body_a != body_b:
                success_count += 1
                authz_ev = AuthorizationComparisonEvidence(
                    url=finding.url,
                    original_role=default_role,
                    target_role=alt_role,
                    original_status=status_a,
                    target_status=status_b,
                    original_body_excerpt=body_a[:500],
                    target_body_excerpt=body_b[:500],
                    body_diff_detected=True,
                    description=f"Cross-account IDOR ({strategy}): {default_role} vs {alt_role} differ at {finding.url}",
                    status=EvidenceStatus.ANALYZED,
                )
                self._record_evidence(authz_ev, fp)
            # Status bypass: alt gets content default role cannot
            elif status_a != 200 and status_b == 200:
                success_count += 1
                authz_ev = AuthorizationComparisonEvidence(
                    url=finding.url,
                    original_role=default_role,
                    target_role=alt_role,
                    original_status=status_a,
                    target_status=status_b,
                    original_body_excerpt="",
                    target_body_excerpt=body_b[:500],
                    body_diff_detected=True,
                    description=f"Status bypass ({strategy}): {default_role} got {status_a}, {alt_role} got {status_b} at {finding.url}",
                    status=EvidenceStatus.ANALYZED,
                )
                self._record_evidence(authz_ev, fp)

        if success_count:
            return self._build_result(task, success=True,
                delta=CONFIDENCE_BOOST.get(strategy, 20),
                next_strategy=next_s, evidence_fp=fp)
        return self._build_result(task, success=False, delta=0, next_strategy=next_s, evidence_fp="")

    def _exec_sqli(self, task: InvestigationTask, finding: Finding, strategy: str) -> InvestigationResult:
        next_s = None
        if strategy == "error_sqli":
            next_s = "timing_sqli"
        elif strategy == "timing_sqli":
            next_s = "boolean_sqli"

        fp = finding.fingerprint or ""
        payloads = {
            "error_sqli": ["'", "\"", "1'", "1\"", "' OR '1'='1"],
            "timing_sqli": ["' OR SLEEP(5)--", "1'; WAITFOR DELAY '0:0:5'--", "' OR pg_sleep(5)--"],
            "boolean_sqli": ["' OR '1'='1", "' AND '1'='2", "' OR 1=1--", "' AND 1=2--"],
        }
        for payload in payloads.get(strategy, []):
            probe_url = finding.url
            if "?" in (probe_url or ""):
                probe_url = f"{probe_url}&invest={payload}"
            elif probe_url:
                probe_url = f"{probe_url}?invest={payload}"

            t0 = time_module.time()
            resp, req_ev, resp_ev = self._make_request(probe_url, finding, timeout=10)
            elapsed = (time_module.time() - t0) * 1000

            if resp is None:
                continue
            if req_ev:
                self._record_evidence(req_ev, fp)
            if resp_ev:
                self._record_evidence(resp_ev, fp)

            if strategy == "timing_sqli" and elapsed > 4000:
                te = TimingEvidence(triggered_time_ms=elapsed, baseline_time_ms=500)
                ev_fp = self._record_evidence(te, fp)
                return self._build_result(task, success=True,
                    delta=CONFIDENCE_BOOST.get("timing_sqli", 15),
                    next_strategy=next_s, evidence_fp=ev_fp)
            if strategy == "error_sqli":
                errors = ["sql", "mysql", "sqlite", "postgresql", "ora-", "syntax error",
                          "unclosed quotation", "odbc", "driver error"]
                body_lower = (resp.text or "").lower()
                if any(e in body_lower for e in errors):
                    if resp_ev:
                        self._record_evidence(resp_ev, fp)
                    return self._build_result(task, success=True,
                        delta=CONFIDENCE_BOOST.get("error_sqli", 10),
                        next_strategy=next_s, evidence_fp=fp)
            if strategy == "boolean_sqli":
                # Check for response size difference between true/false payloads
                continue
        return self._build_result(task, success=False, delta=0, next_strategy=next_s, evidence_fp="")

    def _exec_lfi(self, task: InvestigationTask, finding: Finding) -> InvestigationResult:
        payloads = [
            "/etc/passwd", "/etc/hosts",
            "../../../../etc/passwd", "../../../../etc/hosts",
            "....//....//....//etc/passwd",
        ]
        fp = finding.fingerprint or ""
        for payload in payloads:
            probe_url = finding.url
            if "?" in (probe_url or ""):
                probe_url = f"{probe_url}&file={payload}"
            else:
                probe_url = f"{probe_url}?file={payload}"
            resp, req_ev, resp_ev = self._make_request(probe_url, finding, timeout=10)
            if resp is None:
                continue
            if req_ev:
                self._record_evidence(req_ev, fp)
            if resp_ev:
                self._record_evidence(resp_ev, fp)
            body = resp.text or ""
            if "root:" in body or "daemon:" in body or "localhost" in body:
                return self._build_result(task, success=True,
                    delta=CONFIDENCE_BOOST.get("lfi_file_read", 35),
                    next_strategy=None, evidence_fp=fp)
        return self._build_result(task, success=False, delta=0, next_strategy=None, evidence_fp="")

    def _exec_ssti(self, task: InvestigationTask, finding: Finding) -> InvestigationResult:
        payloads = [
            "{{7*7}}", "${7*7}", "#{7*7}", "{{7*'7'}}",
            "{{config}}", "{{self}}", "<%= 7*7 %>",
        ]
        fp = finding.fingerprint or ""
        for payload in payloads:
            probe_url = finding.url
            if "?" in (probe_url or ""):
                probe_url = f"{probe_url}&ssti={payload}"
            else:
                probe_url = f"{probe_url}?ssti={payload}"
            resp, req_ev, resp_ev = self._make_request(probe_url, finding, timeout=10)
            if resp is None:
                continue
            if req_ev:
                self._record_evidence(req_ev, fp)
            if resp_ev:
                self._record_evidence(resp_ev, fp)
            body = resp.text or ""
            if "49" in body and "{{7*7}}" in payload:
                return self._build_result(task, success=True,
                    delta=CONFIDENCE_BOOST.get("ssti_eval", 35),
                    next_strategy=None, evidence_fp=fp)
        return self._build_result(task, success=False, delta=0, next_strategy=None, evidence_fp="")

    def _exec_cross_account_idor(self, task: InvestigationTask, finding: Finding) -> InvestigationResult:
        """Compare responses across multiple role sessions for IDOR detection."""
        role_sessions = build_role_sessions(self.config, self.session)
        if len(role_sessions) < 2:
            return self._build_result(task, success=False, delta=0, next_strategy=None, evidence_fp="")

        fp = finding.fingerprint or ""
        roles = list(role_sessions.keys())
        default_role = roles[0]
        other_roles = roles[1:]
        default_sess = role_sessions[default_role]

        resp_a, req_ev, resp_ev = self._make_request(finding.url, finding, timeout=10)
        if resp_a is None or resp_a.status_code != 200:
            return self._build_result(task, success=False, delta=0, next_strategy=None, evidence_fp="")
        if req_ev:
            self._record_evidence(req_ev, fp)
        if resp_ev:
            self._record_evidence(resp_ev, fp)

        body_a = resp_a.text or ""
        status_a = resp_a.status_code
        success_count = 0

        for alt_role in other_roles:
            alt_sess = role_sessions[alt_role]
            try:
                resp_b = alt_sess.get(finding.url, timeout=10, allow_redirects=False)
            except Exception:
                continue
            body_b = resp_b.text or ""
            status_b = resp_b.status_code

            if status_a == 200 and status_b == 200:
                # Both succeeded — check body diff for data leakage
                if body_a != body_b:
                    success_count += 1
                    authz_ev = AuthorizationComparisonEvidence(
                        url=finding.url,
                        original_role=default_role,
                        target_role=alt_role,
                        original_status=status_a,
                        target_status=status_b,
                        original_body_excerpt=body_a[:500],
                        target_body_excerpt=body_b[:500],
                        body_diff_detected=True,
                        description=f"Cross-account IDOR: {default_role} vs {alt_role} differ at {finding.url}",
                        status=EvidenceStatus.ANALYZED,
                    )
                    self._record_evidence(authz_ev, fp)
            elif status_a != 200 and status_b == 200:
                # Status bypass: alt role gets content default role can't
                success_count += 1
                authz_ev = AuthorizationComparisonEvidence(
                    url=finding.url,
                    original_role=default_role,
                    target_role=alt_role,
                    original_status=status_a,
                    target_status=status_b,
                    original_body_excerpt="",
                    target_body_excerpt=body_b[:500],
                    body_diff_detected=True,
                    description=f"Status bypass: {default_role} got {status_a}, {alt_role} got {status_b} at {finding.url}",
                    status=EvidenceStatus.ANALYZED,
                )
                self._record_evidence(authz_ev, fp)

        if success_count:
            return self._build_result(task, success=True,
                delta=CONFIDENCE_BOOST.get("cross_account_idor", 30),
                next_strategy="differential_auth" if success_count >= 1 else "ownership_validation",
                evidence_fp=fp)
        return self._build_result(task, success=False, delta=0, next_strategy="horizontal_idor", evidence_fp="")

    def _exec_differential_auth(self, task: InvestigationTask, finding: Finding) -> InvestigationResult:
        """Field-level JSON comparison with sensitivity classification across roles."""
        import json

        role_sessions = build_role_sessions(self.config, self.session)
        if len(role_sessions) < 2:
            return self._build_result(task, success=False, delta=0, next_strategy=None, evidence_fp="")

        fp = finding.fingerprint or ""
        roles = list(role_sessions.keys())
        default_role = roles[0]
        other_roles = roles[1:]
        default_sess = role_sessions[default_role]

        resp_a, req_ev, resp_ev = self._make_request(finding.url, finding, timeout=10)
        if resp_a is None or resp_a.status_code != 200:
            return self._build_result(task, success=False, delta=0, next_strategy=None, evidence_fp="")
        if req_ev:
            self._record_evidence(req_ev, fp)
        if resp_ev:
            self._record_evidence(resp_ev, fp)

        try:
            body_a_json = json.loads(resp_a.text or "{}")
        except (json.JSONDecodeError, TypeError):
            return self._build_result(task, success=False, delta=0, next_strategy=None, evidence_fp="")

        if not isinstance(body_a_json, dict):
            return self._build_result(task, success=False, delta=0, next_strategy=None, evidence_fp="")

        SENSITIVE_FIELD_KEYWORDS = {
            "pii": ["email", "phone", "ssn", "name", "address", "dob", "birth"],
            "financial": ["price", "cost", "salary", "balance", "card", "payment"],
            "credential": ["password", "token", "secret", "key", "auth"],
            "ownership": ["owner", "user_id", "account_id", "customer_id", "belongs_to"],
            "internal": ["internal", "admin", "system", "debug", "trace", "config"],
        }

        def _classify_fields(obj: dict, prefix: str = "") -> dict[str, list[str]]:
            classified: dict[str, list[str]] = {}
            for key, val in obj.items():
                full_key = f"{prefix}.{key}" if prefix else key
                key_lower = key.lower()
                for category, keywords in SENSITIVE_FIELD_KEYWORDS.items():
                    if any(kw in key_lower for kw in keywords):
                        classified.setdefault(category, []).append(full_key)
                if isinstance(val, dict):
                    sub = _classify_fields(val, full_key)
                    for cat, fields in sub.items():
                        classified.setdefault(cat, []).extend(fields)
            return classified

        default_classified = _classify_fields(body_a_json)
        default_fields = set()

        def _flatten(obj: dict, prefix: str = ""):
            for key, val in obj.items():
                full_key = f"{prefix}.{key}" if prefix else key
                default_fields.add(full_key)
                if isinstance(val, dict):
                    _flatten(val, full_key)
                elif isinstance(val, list) and val and isinstance(val[0], dict):
                    _flatten(val[0], full_key)

        _flatten(body_a_json)

        success_count = 0
        for alt_role in other_roles:
            alt_sess = role_sessions[alt_role]
            try:
                resp_b = alt_sess.get(finding.url, timeout=10, allow_redirects=False)
            except Exception:
                continue
            if resp_b.status_code != 200:
                continue
            try:
                body_b_json = json.loads(resp_b.text or "{}")
            except (json.JSONDecodeError, TypeError):
                continue
            if not isinstance(body_b_json, dict):
                continue

            alt_fields = set()

            def _flatten_b(obj: dict, prefix: str = ""):
                for key, val in obj.items():
                    full_key = f"{prefix}.{key}" if prefix else key
                    alt_fields.add(full_key)
                    if isinstance(val, dict):
                        _flatten_b(val, full_key)
                    elif isinstance(val, list) and val and isinstance(val[0], dict):
                        _flatten_b(val[0], full_key)

            _flatten_b(body_b_json)

            extra_fields = alt_fields - default_fields
            missing_fields = default_fields - alt_fields

            if extra_fields:
                # Alt role sees extra sensitive data
                for cat in ("pii", "financial", "credential", "ownership", "internal"):
                    sensitive_extra = [f for f in extra_fields
                                       if any(kw in f.lower() for kw in SENSITIVE_FIELD_KEYWORDS[cat])]
                    if sensitive_extra:
                        success_count += 1
                        authz_ev = AuthorizationComparisonEvidence(
                            url=finding.url,
                            original_role=default_role,
                            target_role=alt_role,
                            original_status=resp_a.status_code,
                            target_status=resp_b.status_code,
                            original_body_excerpt=resp_a.text[:500],
                            target_body_excerpt=resp_b.text[:500],
                            body_diff_detected=True,
                            description=f"Differential auth: {alt_role} sees extra {cat} fields: {', '.join(sensitive_extra[:5])}",
                            status=EvidenceStatus.ANALYZED,
                        )
                        self._record_evidence(authz_ev, fp)

        if success_count:
            return self._build_result(task, success=True,
                delta=CONFIDENCE_BOOST.get("differential_auth", 35),
                next_strategy="ownership_validation",
                evidence_fp=fp)
        return self._build_result(task, success=False, delta=0, next_strategy=None, evidence_fp="")

    def investigate_candidate(
        self,
        candidate: Any,
        budget: int = 5,
    ) -> list[InvestigationResult]:
        """Investigate a LogicAbuseCandidate directly.

        Creates a lightweight investigation context from the candidate's
        abuse URL and suggested strategies. Results are stored under
        the candidate's abuse_url fingerprint.
        """
        from models.finding import Finding
        abuse_url = candidate.abuse_url or (candidate.workflow.source_urls or [""])[0]
        fake_finding = Finding(
            vuln_type="business_logic",
            url=abuse_url,
            severity="medium",
            details=f"Business logic abuse candidate: {candidate.workflow.name}",
            evidence="",
            fingerprint=hashlib.sha256(abuse_url.encode()).hexdigest()[:16],
            confidence_score=25,
        )
        object.__setattr__(fake_finding, "_from_candidate", candidate.workflow.name)
        return self.investigate(
            fake_finding,
            budget=budget,
            available_strategies=candidate.suggested_strategies,
        )

    def _apply_result(self, finding: Finding, result: InvestigationResult) -> None:
        new_score = min(100, (finding.confidence_score or 25) + result.confidence_delta)
        object.__setattr__(finding, "confidence_score", new_score)
        object.__setattr__(finding, "confidence_label", ConfidenceLevel.from_score(new_score).value)
        if result.success:
            stage = "verified" if result.confidence_delta >= 35 else "validated"
            object.__setattr__(finding, "verification_stage", stage)
            from models.finding import FindingState
            object.__setattr__(finding, "finding_state", FindingState.from_verification_stage(stage).value)
            reason = f"+{result.confidence_delta} via investigation:{result.task.strategy}"
            if not hasattr(finding, "confidence_reasons") or not isinstance(finding.confidence_reasons, list):
                object.__setattr__(finding, "confidence_reasons", [])
            if reason not in finding.confidence_reasons:
                finding.confidence_reasons.append(reason)
