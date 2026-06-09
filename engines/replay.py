import hashlib
import json
import os
from datetime import datetime
from typing import Any

from models.finding import Finding
from models.evidence import EvidenceType, HttpRequestEvidence, HttpResponseEvidence
from models.replay import ValidationSnapshot, ReplayBundle


class ReplayEngine:
    """Captures and manages replay bundles for retesting and regression tracking."""

    def __init__(self):
        self.bundles: dict[str, ReplayBundle] = {}

    def capture_snapshot(
        self,
        finding: Finding,
        request: str = "",
        response: str = "",
        validation_step: str = "",
        evidence_fingerprint: str = "",
    ) -> ValidationSnapshot:
        snapshot = ValidationSnapshot(
            request=request or finding.request or "",
            response=response or finding.response_excerpt or "",
            validation_step=validation_step,
            evidence_fingerprint=evidence_fingerprint,
        )
        return snapshot

    def build_bundle(
        self,
        finding: Finding,
        snapshots: list[ValidationSnapshot] | None = None,
    ) -> ReplayBundle:
        fp = finding.fingerprint
        existing = self.bundles.get(fp)

        if existing:
            if snapshots:
                existing.snapshots.extend(snapshots)
            return existing

        bundle_snapshots = snapshots or self._generate_snapshots(finding)
        commands = self._build_validation_commands(finding)
        behavior = self._describe_expected_behavior(finding)

        bundle = ReplayBundle(
            finding_fingerprint=fp,
            snapshots=bundle_snapshots,
            validation_commands=commands,
            expected_behavior=behavior,
        )
        self.bundles[fp] = bundle
        return bundle

    def _generate_snapshots(self, finding: Finding) -> list[ValidationSnapshot]:
        snapshots = []
        for ev in (finding.evidence or []):
            if isinstance(ev, str):
                continue
            if hasattr(ev, "evidence_type"):
                if ev.evidence_type == EvidenceType.HTTP_REQUEST:
                    snapshots.append(ValidationSnapshot(
                        request=getattr(ev, "curl_command", ""),
                        response="",
                        validation_step="HTTP request",
                        evidence_fingerprint=getattr(ev, "fingerprint", ""),
                    ))
                elif ev.evidence_type == EvidenceType.HTTP_RESPONSE:
                    snapshots.append(ValidationSnapshot(
                        request="",
                        response=getattr(ev, "body_excerpt", ""),
                        validation_step="HTTP response",
                        evidence_fingerprint=getattr(ev, "fingerprint", ""),
                    ))
        if not snapshots:
            snapshots.append(ValidationSnapshot(
                request=finding.request or "",
                response=finding.response_excerpt or "",
                validation_step="initial finding",
                evidence_fingerprint=finding.evidence_fingerprint or "",
            ))
        return snapshots

    def _build_validation_commands(self, finding: Finding) -> list[str]:
        commands = []
        curl = finding.curl_command or finding.request or ""
        if curl:
            commands.append(curl)
        steps = finding.reproduction_steps or []
        commands.extend(steps[:5])
        return commands

    def _describe_expected_behavior(self, finding: Finding) -> str:
        vuln_type = (finding.vuln_type or "").lower()
        templates = {
            "xss": "JavaScript alert() should fire in browser, or script payload appears in response",
            "sqli": "Database error, timing delay, or boolean difference should be observable",
            "ssrf": "OOB callback should be received from target server",
            "lfi": "File contents should appear in response body",
            "idor": "Response content differs between users for the same resource ID",
            "open redirect": "Redirect to external domain should occur",
            "ssti": "Template expression should evaluate in response",
        }
        for key, desc in templates.items():
            if key in vuln_type:
                return desc
        return "Vulnerability should be reproducible using the provided commands"

    def get_bundle(self, fingerprint: str) -> ReplayBundle | None:
        return self.bundles.get(fingerprint)

    def all_bundles(self) -> list[ReplayBundle]:
        return list(self.bundles.values())

    def clear(self) -> None:
        self.bundles.clear()

    @staticmethod
    def _bundle_fingerprint(bundle: ReplayBundle) -> str:
        raw = json.dumps(bundle.to_dict(), sort_keys=True, default=str)
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def compare_across_scans(
        self,
        findings: list[Finding],
        history_path: str,
        target: str,
    ) -> list[Finding]:
        """Compare current replay bundles against the previous scan's snapshots.
        Sets ``replay_regression`` on findings whose request/response changed.
        """
        try:
            if not os.path.isfile(history_path):
                return findings
            with open(history_path) as f:
                data = json.load(f)
            scans = data.get("scans", [])
            matching = [s for s in scans if s.get("target") == target]
            if len(matching) < 2:
                return findings
            prev = matching[-2]
        except Exception:
            return findings

        prev_records = {r.get("fingerprint"): r for r in prev.get("findings", []) if r.get("fingerprint")}

        for f in findings:
            fp = f.fingerprint or ""
            if not fp or fp not in prev_records:
                continue
            bundle = self.get_bundle(fp)
            if bundle is None:
                continue
            current_fp = self._bundle_fingerprint(bundle)

            prev_record = prev_records[fp]
            prev_req = prev_record.get("request", "")
            prev_resp = prev_record.get("response_excerpt", "")
            prev_hash = hashlib.sha256(f"{prev_req}{prev_resp}".encode()).hexdigest()[:16]

            if current_fp != prev_hash:
                object.__setattr__(f, "replay_regression", {
                    "changed": True,
                    "previous_scan": prev.get("scan_id", ""),
                    "previous_timestamp": prev.get("timestamp", ""),
                })
            else:
                object.__setattr__(f, "replay_regression", {
                    "changed": False,
                    "previous_scan": prev.get("scan_id", ""),
                    "previous_timestamp": prev.get("timestamp", ""),
                })

        return findings
