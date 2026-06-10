"""Scan diff engine — compares two scan outputs and highlights changes.

Usage:
    diff = ScanDiffEngine.diff(new_findings, old_findings)
    print(ScanDiffEngine.format_summary(diff))
"""

import json
from dataclasses import dataclass, field
from typing import Any

from models.finding import compute_fingerprint


@dataclass
class DiffResult:
    new_findings: list[dict] = field(default_factory=list)
    fixed_findings: list[dict] = field(default_factory=list)
    regressed_findings: list[dict] = field(default_factory=list)
    changed_findings: list[dict] = field(default_factory=list)
    stats: dict = field(default_factory=dict)


class ScanDiffEngine:
    SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    @staticmethod
    def _fingerprint_dict(f: dict) -> str:
        return compute_fingerprint(
            f.get("type", f.get("vuln_type", "")),
            f.get("url", ""),
            f.get("parameter", ""),
        )

    @staticmethod
    def _severity_score(f: dict) -> int:
        return ScanDiffEngine.SEVERITY_ORDER.get(
            f.get("severity", "info").lower(), 4
        )

    @staticmethod
    def diff(
        new_findings: list[dict], old_findings: list[dict]
    ) -> DiffResult:
        new_by_fp: dict[str, dict] = {}
        for f in new_findings:
            fp = ScanDiffEngine._fingerprint_dict(f)
            new_by_fp[fp] = f

        old_by_fp: dict[str, dict] = {}
        for f in old_findings:
            fp = ScanDiffEngine._fingerprint_dict(f)
            old_by_fp[fp] = f

        new_fps = set(new_by_fp)
        old_fps = set(old_by_fp)

        appeared = new_fps - old_fps
        disappeared = old_fps - new_fps
        common = new_fps & old_fps

        new_list = [new_by_fp[fp] for fp in sorted(appeared)]
        fixed_list: list[dict] = []
        regressed_list: list[dict] = []
        changed_list: list[dict] = []

        for fp in sorted(disappeared):
            fixed_list.append(old_by_fp[fp])

        for fp in sorted(common):
            old_f = old_by_fp[fp]
            new_f = new_by_fp[fp]
            old_sev = ScanDiffEngine._severity_score(old_f)
            new_sev = ScanDiffEngine._severity_score(new_f)

            old_conf = old_f.get("confidence_score", 0) or 0
            new_conf = new_f.get("confidence_score", 0) or 0

            if old_sev != new_sev or abs(old_conf - new_conf) >= 10:
                new_f["_changed_from"] = {
                    "old_severity": old_f.get("severity", "info"),
                    "old_confidence_score": old_conf,
                    "old_verification_stage": old_f.get(
                        "verification_stage", "detected"
                    ),
                }
                changed_list.append(new_f)
            else:
                if old_sev < new_sev:
                    regressed_list.append(new_f)

        new_count = len(new_list)
        fixed_count = len(fixed_list)
        changed_count = len(changed_list)
        regressed_count = len(regressed_list)

        stats: dict[str, Any] = {
            "total_new": len(new_findings),
            "total_old": len(old_findings),
            "new": new_count,
            "fixed": fixed_count,
            "regressed": regressed_count,
            "changed": changed_count,
            "unchanged": len(common) - changed_count,
            "severity_breakdown_new": {},
            "severity_breakdown_fixed": {},
        }

        for f in new_list:
            sev = f.get("severity", "info").lower()
            stats["severity_breakdown_new"][sev] = (
                stats["severity_breakdown_new"].get(sev, 0) + 1
            )
        for f in fixed_list:
            sev = f.get("severity", "info").lower()
            stats["severity_breakdown_fixed"][sev] = (
                stats["severity_breakdown_fixed"].get(sev, 0) + 1
            )

        return DiffResult(
            new_findings=new_list,
            fixed_findings=fixed_list,
            regressed_findings=regressed_list,
            changed_findings=changed_list,
            stats=stats,
        )

    @staticmethod
    def diff_from_files(new_path: str, old_path: str) -> DiffResult:
        with open(new_path) as f:
            new_data = json.load(f)
        with open(old_path) as f:
            old_data = json.load(f)

        new_findings = new_data if isinstance(new_data, list) else new_data.get("findings", [])
        old_findings = old_data if isinstance(old_data, list) else old_data.get("findings", [])
        return ScanDiffEngine.diff(new_findings, old_findings)

    @staticmethod
    def format_github_annotations(diff: DiffResult) -> str:
        lines: list[str] = []
        for f in diff.new_findings:
            sev = f.get("severity", "info").lower()
            level = "error" if sev in ("critical", "high") else "warning"
            url = f.get("url", "")
            title = f.get("title", f.get("type", "Finding"))
            lines.append(
                f"::{level} title=New {sev.upper()} finding,file=scan.json"
                f"::{title} @ {url}"
            )
        for f in diff.regressed_findings:
            url = f.get("url", "")
            title = f.get("title", f.get("type", "Finding"))
            lines.append(
                f"::warning title=Regression,file=scan.json"
                f"::{title} @ {url} (reappeared)"
            )
        return "\n".join(lines)

    @staticmethod
    def format_summary(diff: DiffResult) -> str:
        s = diff.stats
        lines: list[str] = [
            "=== Scan Diff Summary ===",
            f"  Previous scan: {s['total_old']} findings",
            f"  Current scan:  {s['total_new']} findings",
            "",
            f"  New:      {s['new']}",
        ]
        if s.get("severity_breakdown_new"):
            for sev in ("critical", "high", "medium", "low", "info"):
                count = s["severity_breakdown_new"].get(sev, 0)
                if count:
                    lines.append(f"    {sev}: {count}")

        lines.extend(
            [
                f"  Fixed:    {s['fixed']}",
            ]
        )
        if s.get("severity_breakdown_fixed"):
            for sev in ("critical", "high", "medium", "low", "info"):
                count = s["severity_breakdown_fixed"].get(sev, 0)
                if count:
                    lines.append(f"    {sev}: {count}")

        lines.extend(
            [
                f"  Changed:  {s['changed']}",
                f"  Regressed: {s['regressed']}",
                f"  Unchanged: {s['unchanged']}",
            ]
        )
        return "\n".join(lines)
