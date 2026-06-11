import json
import os
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urljoin

import requests

from modules.h1_client import HackerOneClient, ProgrammeIntel as H1Intel, ScopeAsset, DisclosedReport, HackerOneAPIError, CACHE_DIR

CACHE_TTL = 3600


@dataclass
class BCScopeAsset:
    identifier: str
    asset_type: str
    eligible: bool
    max_severity: str
    instruction: str


@dataclass
class BCSubmission:
    id: str
    title: str
    weakness: str
    severity: str
    asset: str
    submitted_at: str


class BugcrowdClient:
    BASE = "https://api.bugcrowd.com"

    def __init__(self, token: str | None = None):
        self._token = token or os.environ.get("BC_TOKEN", "")
        self._session = requests.Session()
        self._session.headers.update({
            "Accept": "application/json",
            "Authorization": f"Bearer {self._token}",
        })

    def _paginate(self, path: str, params: dict | None = None) -> list[dict]:
        results = []
        url = urljoin(self.BASE, path.lstrip("/"))
        while url:
            try:
                resp = self._session.get(url, params=params, timeout=15)
                if resp.status_code == 429:
                    retry_after = int(resp.headers.get("Retry-After", "5"))
                    time.sleep(retry_after)
                    continue
                if resp.status_code >= 400:
                    print(f"[!] Bugcrowd API error {resp.status_code}: {resp.text[:200]}", file=sys.stderr)
                    return results
                data = resp.json()
            except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
                print(f"[!] Bugcrowd API connection error: {e}", file=sys.stderr)
                return results
            results.extend(data.get("data", []))
            links = data.get("links", {}) or {}
            url = links.get("next")
            params = None
        return results

    def get_programmes(self) -> list[dict]:
        return self._paginate("/programs")

    def get_targets(self, programme_code: str) -> list[BCScopeAsset]:
        """Fetch in-scope targets for a programme."""
        raw = self._paginate(f"/programs/{programme_code}/target_groups")
        assets = []
        for group in raw:
            attrs = group.get("attributes", {}) or {}
            targets = attrs.get("targets", []) or []
            for t in targets:
                identifier = t.get("url", "") or t.get("uri", "") or t.get("name", "")
                eligible = t.get("eligible", True)
                max_sev = t.get("max_severity", "none")
                assets.append(BCScopeAsset(
                    identifier=identifier,
                    asset_type="URL" if identifier.startswith("http") else "WILDCARD" if identifier.startswith("*.") else "OTHER",
                    eligible=eligible,
                    max_severity=max_sev or "none",
                    instruction=t.get("instruction", "") or "",
                ))
        return assets

    def get_submissions(self, programme_code: str) -> list[BCSubmission]:
        """Fetch disclosed submissions for a programme (last 90 days)."""
        ninety_days_ago = datetime.now(timezone.utc).timestamp() - (90 * 86400)
        raw = self._paginate(f"/programs/{programme_code}/submissions")
        subs = []
        for item in raw:
            attrs = item.get("attributes", {}) or {}
            submitted_at = attrs.get("submitted_at", "") or ""
            if not submitted_at:
                continue
            try:
                ts = datetime.fromisoformat(submitted_at.replace("Z", "+00:00")).timestamp()
            except (ValueError, TypeError):
                continue
            if ts < ninety_days_ago:
                continue
            subs.append(BCSubmission(
                id=item.get("id", ""),
                title=attrs.get("title", ""),
                weakness=attrs.get("weakness", "") or attrs.get("cwe", ""),
                severity=attrs.get("priority", "") or attrs.get("severity", "none"),
                asset=attrs.get("target", "") or "",
                submitted_at=submitted_at,
            ))
        return subs


BC_ASSET_MAP = {
    "url": "URL",
    "wildcard": "WILDCARD",
    "api": "API",
    "website": "URL",
    "web_application": "URL",
    "mobile": "OTHER",
    "ip": "OTHER",
    "cidr": "OTHER",
    "other": "OTHER",
}


def _map_bc_asset_type(bc_type: str) -> str:
    return BC_ASSET_MAP.get(bc_type.lower().replace(" ", "_"), "OTHER")


@dataclass
class ProgrammeIntel:
    handle: str
    name: str
    platform: str
    offers_bounties: bool
    max_payout_critical: int = 0
    max_payout_high: int = 0
    max_payout_medium: int = 0
    in_scope_assets: list[ScopeAsset] = field(default_factory=list)
    recently_disclosed_weaknesses: list[str] = field(default_factory=list)
    saturation_score: float = 0.0
    expected_value_score: float = 0.0


def build_programme_intel(handle: str, platform: str = "hackerone",
                          h1_username: str | None = None,
                          h1_token: str | None = None,
                          bc_token: str | None = None) -> ProgrammeIntel | None:
    if platform == "hackerone":
        try:
            client = HackerOneClient(username=h1_username, token=h1_token)
            h1_intel = client.build_programme_intel(handle)
            if h1_intel is None:
                return None
            weakness_names = list(dict.fromkeys(r.weakness for r in h1_intel.disclosed_reports if r.weakness))
            return ProgrammeIntel(
                handle=h1_intel.handle,
                name=h1_intel.name,
                platform="hackerone",
                offers_bounties=h1_intel.offers_bounties,
                max_payout_critical=h1_intel.max_payout_critical,
                max_payout_high=h1_intel.max_payout_high,
                max_payout_medium=h1_intel.max_payout_medium,
                in_scope_assets=h1_intel.in_scope,
                recently_disclosed_weaknesses=weakness_names,
                saturation_score=h1_intel.saturation_score,
                expected_value_score=h1_intel.expected_value_score,
            )
        except HackerOneAPIError as e:
            print(f"[!] HackerOne API error: {e}", file=sys.stderr)
            return None
    elif platform == "bugcrowd":
        try:
            client = BugcrowdClient(token=bc_token)
            programmes = client.get_programmes()
            prog_data = None
            for p in programmes:
                attrs = p.get("attributes", {}) or {}
                if attrs.get("code", "") == handle or attrs.get("slug", "") == handle:
                    prog_data = p
                    break
            if not prog_data:
                print(f"[!] Bugcrowd programme '{handle}' not found", file=sys.stderr)
                return None
            attrs = prog_data.get("attributes", {}) or {}
            name = attrs.get("name", handle)
            targets = client.get_targets(handle)
            in_scope_assets = []
            for t in targets:
                if t.eligible:
                    in_scope_assets.append(ScopeAsset(
                        identifier=t.identifier,
                        asset_type=t.asset_type,
                        eligible=True,
                        max_severity=t.max_severity,
                        instruction=t.instruction,
                    ))
            subs = client.get_submissions(handle)
            weakness_names = list(dict.fromkeys(s.weakness for s in subs if s.weakness))
            sat_score = len(subs) / max(len(in_scope_assets), 1)
            ev_score = 0.0
            # Bugcrowd doesn't expose payouts via the same API, estimate from target count
            ev_score = 1000.0 / max(len(in_scope_assets), 1) / (1 + sat_score)
            return ProgrammeIntel(
                handle=handle,
                name=name,
                platform="bugcrowd",
                offers_bounties=True,
                in_scope_assets=in_scope_assets,
                recently_disclosed_weaknesses=weakness_names,
                saturation_score=sat_score,
                expected_value_score=ev_score,
            )
        except Exception as e:
            print(f"[!] Bugcrowd error: {e}", file=sys.stderr)
            return None
    return None


def list_programmes_ranked(h1_username: str | None = None,
                           h1_token: str | None = None,
                           bc_token: str | None = None) -> list[ProgrammeIntel]:
    ranked = []
    if h1_username and h1_token:
        try:
            from modules.h1_client import HackerOneClient
            client = HackerOneClient(username=h1_username, token=h1_token)
            h1_ranked = client.list_programmes_ranked()
            for h1_intel in h1_ranked:
                weakness_names = list(dict.fromkeys(r.weakness for r in h1_intel.disclosed_reports if r.weakness))
                ranked.append(ProgrammeIntel(
                    handle=h1_intel.handle,
                    name=h1_intel.name,
                    platform="hackerone",
                    offers_bounties=h1_intel.offers_bounties,
                    max_payout_critical=h1_intel.max_payout_critical,
                    max_payout_high=h1_intel.max_payout_high,
                    max_payout_medium=h1_intel.max_payout_medium,
                    in_scope_assets=h1_intel.in_scope,
                    recently_disclosed_weaknesses=weakness_names,
                    saturation_score=h1_intel.saturation_score,
                    expected_value_score=h1_intel.expected_value_score,
                ))
        except Exception as e:
            print(f"[!] HackerOne list error: {e}", file=sys.stderr)
    if bc_token:
        try:
            client = BugcrowdClient(token=bc_token)
            programmes = client.get_programmes()
            for p in programmes:
                attrs = p.get("attributes", {}) or {}
                code = attrs.get("code", "")
                if not code:
                    continue
                targets = client.get_targets(code)
                in_scope = [t for t in targets if t.eligible]
                sat = 0.0
                ev = 1000.0 / max(len(in_scope), 1)
                weakness_names = []
                ranked.append(ProgrammeIntel(
                    handle=code,
                    name=attrs.get("name", code),
                    platform="bugcrowd",
                    offers_bounties=True,
                    in_scope_assets=[ScopeAsset(t.identifier, t.asset_type, True, t.max_severity, t.instruction) for t in in_scope],
                    recently_disclosed_weaknesses=weakness_names,
                    saturation_score=sat,
                    expected_value_score=ev,
                ))
        except Exception as e:
            print(f"[!] Bugcrowd list error: {e}", file=sys.stderr)
    ranked.sort(key=lambda x: x.expected_value_score, reverse=True)
    return ranked


def print_ranked_table(ranked: list[ProgrammeIntel]) -> None:
    print(f"{'Rank':<6} {'Platform':<10} {'Handle':<28} {'Critical':<10} {'High':<10} {'Medium':<10} {'Assets':<8} {'Saturation':<12} {'Score':<10}")
    print("-" * 104)
    for idx, p in enumerate(ranked, 1):
        crit = f"${p.max_payout_critical:,}" if p.max_payout_critical else "$0"
        high = f"${p.max_payout_high:,}" if p.max_payout_high else "$0"
        med = f"${p.max_payout_medium:,}" if p.max_payout_medium else "$0"
        assets = len(p.in_scope_assets)
        sat = f"{p.saturation_score:.2f}"
        score = f"{p.expected_value_score:.1f}"
        print(f"{idx:<6} {p.platform:<10} {p.handle:<28} {crit:<10} {high:<10} {med:<10} {assets:<8} {sat:<12} {score:<10}")
