"""Webhook notifier — posts findings to Slack or Discord webhooks.

Usage:
    notifier = WebhookNotifier({"rate_limit": 2.0})
    notifier.post_finding(finding_dict, "https://hooks.slack.com/...", "slack")
    notifier.post_summary(all_findings, "https://discord.com/api/webhooks/...", "discord")
"""

import json
import time
import threading
from typing import Any

import requests


class WebhookNotifier:
    def __init__(self, config: dict[str, Any] | None = None):
        self.config = config or {}
        self._rate_limit = self.config.get("rate_limit", 2.0)
        self._last_send = 0.0
        self._lock = threading.Lock()

    def _wait_rate_limit(self):
        with self._lock:
            elapsed = time.time() - self._last_send
            if elapsed < self._rate_limit:
                time.sleep(self._rate_limit - elapsed)
            self._last_send = time.time()

    def _build_curl(self, finding: dict) -> str:
        return finding.get("curl_command", "")

    def _slack_payload(self, finding: dict) -> dict:
        title = finding.get("title", finding.get("type", "Finding"))
        url = finding.get("url", "")
        severity = finding.get("severity", "info").upper()
        confidence = finding.get("confidence_score", 25)
        stage = finding.get("verification_stage", "detected")
        curl = self._build_curl(finding)
        details = finding.get("details", "")[:300]

        color_map = {
            "CRITICAL": "#ff0000",
            "HIGH": "#ff6600",
            "MEDIUM": "#ffcc00",
            "LOW": "#33ccff",
            "INFO": "#999999",
        }

        blocks: list[dict] = [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*{title}*\n*Severity:* {severity}  |  *Confidence:* {confidence}/100  |  *Stage:* {stage}",
                },
            },
            {"type": "divider"},
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*URL*\n{url}"},
                    {"type": "mrkdwn", "text": f"*Details*\n{details}"},
                ],
            },
        ]
        if curl:
            blocks.append(
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*cURL*\n```\n{curl[:800]}\n```",
                    },
                }
            )

        return {
            "text": f"[{severity}] {title} @ {url}",
            "attachments": [
                {
                    "color": color_map.get(severity, "#999999"),
                    "blocks": blocks,
                }
            ],
        }

    def _discord_payload(self, finding: dict) -> dict:
        title = finding.get("title", finding.get("type", "Finding"))
        url = finding.get("url", "")
        severity = finding.get("severity", "info").upper()
        confidence = finding.get("confidence_score", 25)
        stage = finding.get("verification_stage", "detected")
        curl = self._build_curl(finding)
        details = finding.get("details", "")[:300]

        color_map = {
            "CRITICAL": 16711680,
            "HIGH": 16744192,
            "MEDIUM": 16766976,
            "LOW": 3381759,
            "INFO": 10066329,
        }

        embed: dict[str, Any] = {
            "title": title[:256],
            "url": url[:2048],
            "color": color_map.get(severity, 10066329),
            "fields": [
                {
                    "name": "Severity",
                    "value": severity,
                    "inline": True,
                },
                {
                    "name": "Confidence",
                    "value": f"{confidence}/100",
                    "inline": True,
                },
                {
                    "name": "Verification Stage",
                    "value": stage,
                    "inline": True,
                },
                {
                    "name": "Details",
                    "value": details[:1024] or "—",
                },
            ],
            "footer": {"text": "BugBounty Hunter"},
        }
        if curl:
            embed["fields"].append(
                {
                    "name": "cURL",
                    "value": f"```\n{curl[:1000]}\n```",
                }
            )

        return {"content": f"[{severity}] New finding discovered", "embeds": [embed]}

    def _build_payload(self, finding: dict, platform: str) -> dict:
        if platform == "discord":
            return self._discord_payload(finding)
        return self._slack_payload(finding)

    def _send(self, payload: dict, webhook_url: str):
        self._wait_rate_limit()
        resp = requests.post(
            webhook_url,
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=15,
        )
        resp.raise_for_status()

    def post_finding(
        self, finding: dict, webhook_url: str, platform: str = "slack"
    ):
        payload = self._build_payload(finding, platform)
        self._send(payload, webhook_url)

    def _build_summary_payload(
        self, findings: list[dict], platform: str
    ) -> dict:
        total = len(findings)
        by_severity: dict[str, int] = {}
        by_stage: dict[str, int] = {}
        avg_confidence = 0.0
        critical_high = 0

        for f in findings:
            sev = f.get("severity", "info").lower()
            by_severity[sev] = by_severity.get(sev, 0) + 1
            stage = f.get("verification_stage", "detected")
            by_stage[stage] = by_stage.get(stage, 0) + 1
            avg_confidence += f.get("confidence_score", 0) or 0
            if sev in ("critical", "high"):
                critical_high += 1

        avg_confidence = avg_confidence / total if total else 0

        if platform == "discord":
            sev_lines = "\n".join(
                f"**{s.capitalize()}:** {c}" for s, c in sorted(by_severity.items())
            )
            stage_lines = "\n".join(
                f"**{s.capitalize()}:** {c}" for s, c in sorted(by_stage.items())
            )
            return {
                "content": f"Scan Complete: {total} finding(s)",
                "embeds": [
                    {
                        "title": "Scan Summary",
                        "color": 16744192 if critical_high else 65280,
                        "fields": [
                            {"name": "Total Findings", "value": str(total), "inline": True},
                            {"name": "Avg Confidence", "value": f"{avg_confidence:.0f}/100", "inline": True},
                            {"name": "Critical/High", "value": str(critical_high), "inline": True},
                            {"name": "By Severity", "value": sev_lines or "—"},
                            {"name": "By Stage", "value": stage_lines or "—"},
                        ],
                        "footer": {"text": "BugBounty Hunter"},
                    }
                ],
            }
        else:
            sev_fields = [
                {"type": "mrkdwn", "text": f"*{s.capitalize()}*: {c}"}
                for s, c in sorted(by_severity.items())
            ]
            stage_fields = [
                {"type": "mrkdwn", "text": f"*{s.capitalize()}*: {c}"}
                for s, c in sorted(by_stage.items())
            ]
            return {
                "text": f"Scan Complete: {total} finding(s) — {critical_high} critical/high",
                "attachments": [
                    {
                        "color": "#ff6600" if critical_high else "#36a64f",
                        "blocks": [
                            {
                                "type": "section",
                                "fields": [
                                    {"type": "mrkdwn", "text": f"*Total Findings*\n{total}"},
                                    {"type": "mrkdwn", "text": f"*Avg Confidence*\n{avg_confidence:.0f}/100"},
                                    {"type": "mrkdwn", "text": f"*Critical/High*\n{critical_high}"},
                                ],
                            },
                            {"type": "divider"},
                            {
                                "type": "section",
                                "fields": sev_fields + stage_fields,
                            },
                        ],
                    }
                ],
            }

    def _send_batch(
        self, payloads: list[dict], webhook_url: str
    ):
        for payload in payloads:
            self._send(payload, webhook_url)

    def post_summary(
        self, findings: list[dict], webhook_url: str, platform: str = "slack"
    ):
        payload = self._build_summary_payload(findings, platform)
        self._send(payload, webhook_url)

    def post_high_confidence(
        self,
        findings: list[dict],
        webhook_url: str,
        platform: str = "slack",
        threshold: int = 60,
    ):
        filtered = [
            f
            for f in findings
            if (f.get("confidence_score", 0) or 0) >= threshold
        ]
        if not filtered:
            return
        payloads = [self._build_payload(f, platform) for f in filtered]
        self._send_batch(payloads, webhook_url)
