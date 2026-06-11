import json
import os
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urljoin

import requests


BASE = "https://api.hackerone.com/v1/"
CACHE_DIR = os.path.expanduser("~/.bbh")
CACHE_FILE = os.path.join(CACHE_DIR, "programme_cache.json")
CACHE_TTL = 3600  # 1 hour


class HackerOneAPIError(Exception):
    def __init__(self, status: int, body: str, msg: str = ""):
        self.status = status
        self.body = body
        self.msg = msg or f"HackerOne API error {status}"
        super().__init__(self.msg)


@dataclass
class ScopeAsset:
    identifier: str
    asset_type: str
    eligible: bool
    max_severity: str
    instruction: str


@dataclass
class DisclosedReport:
    id: str
    title: str
    weakness: str
    severity: str
    asset: str
    disclosed_at: str


@dataclass
class ProgrammeIntel:
    handle: str
    name: str
    offers_bounties: bool
    max_payout_critical: int
    max_payout_high: int
    max_payout_medium: int
    in_scope: list[ScopeAsset] = field(default_factory=list)
    out_of_scope: list[ScopeAsset] = field(default_factory=list)
    disclosed_reports: list[DisclosedReport] = field(default_factory=list)
    saturation_score: float = 0.0
    expected_value_score: float = 0.0


def _ensure_cache_dir() -> str:
    try:
        os.makedirs(CACHE_DIR, exist_ok=True)
        return CACHE_DIR
    except OSError:
        import tempfile
        fallback = tempfile.mkdtemp(prefix="bbh_cache_")
        import sys
        print(f"[!] Could not create ~/.bbh/, using {fallback}", file=sys.stderr)
        return fallback


def _load_cache(cache_path: str) -> dict:
    try:
        if os.path.isfile(cache_path):
            with open(cache_path) as f:
                return json.load(f)
    except (json.JSONDecodeError, OSError):
        pass
    return {}


def _save_cache(cache_path: str, data: dict):
    try:
        parent = os.path.dirname(cache_path)
        os.makedirs(parent, exist_ok=True)
        with open(cache_path, "w") as f:
            json.dump(data, f)
    except OSError:
        pass


def _is_cache_stale(entry: dict) -> bool:
    fetched = entry.get("fetched_at", "")
    if not fetched:
        return True
    try:
        dt = datetime.fromisoformat(fetched)
        return (datetime.now(timezone.utc) - dt).total_seconds() > CACHE_TTL
    except (ValueError, TypeError):
        return True


H1_ASSET_MAP = {
    "url": "URL",
    "wildcard": "WILDCARD",
    "api": "API",
    "mobile_url": "URL",
    "other": "OTHER",
    "ip_address": "OTHER",
    "cidr": "OTHER",
}


def _map_asset_type(h1_type: str) -> str:
    return H1_ASSET_MAP.get(h1_type.lower(), "OTHER")


class HackerOneClient:
    def __init__(self, username: str | None = None, token: str | None = None):
        self._username = username or os.environ.get("H1_USERNAME", "")
        self._token = token or os.environ.get("H1_TOKEN", "")
        if not self._username or not self._token:
            h1_api = os.environ.get("H1_API", "")
            if ":" in h1_api:
                parts = h1_api.split(":", 1)
                self._username = self._username or parts[0]
                self._token = self._token or parts[1]
        self._cache_path = CACHE_FILE
        self._session = requests.Session()
        self._session.auth = (self._username, self._token)
        self._session.headers.update({"Accept": "application/json"})
        self._session.timeout = 15

    def _request(self, method: str, path: str, **kwargs) -> Any:
        url = urljoin(BASE, path.lstrip("/"))
        kwargs.setdefault("timeout", 15)
        for attempt in range(3):
            try:
                resp = self._session.request(method, url, **kwargs)
                if resp.status_code == 429:
                    retry_after = int(resp.headers.get("Retry-After", "5"))
                    time.sleep(retry_after)
                    continue
                if resp.status_code >= 400:
                    raise HackerOneAPIError(resp.status_code, resp.text[:500])
                return resp.json()
            except requests.exceptions.ConnectionError:
                if attempt == 2:
                    raise HackerOneAPIError(0, "ConnectionError after 3 retries")
                time.sleep(1 * (2 ** attempt))
            except requests.exceptions.Timeout:
                if attempt == 2:
                    raise HackerOneAPIError(0, "Timeout after 3 retries")
                time.sleep(1 * (2 ** attempt))

    def _paginate(self, path: str, params: dict | None = None) -> list[dict]:
        results = []
        url = urljoin(BASE, path.lstrip("/"))
        while url:
            try:
                resp = self._session.get(url, params=params, timeout=15)
                if resp.status_code == 429:
                    retry_after = int(resp.headers.get("Retry-After", "5"))
                    time.sleep(retry_after)
                    continue
                if resp.status_code >= 400:
                    raise HackerOneAPIError(resp.status_code, resp.text[:500])
                data = resp.json()
            except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
                raise HackerOneAPIError(0, str(e))
            results.extend(data.get("data", []))
            url = None
            links = data.get("links", {}) or {}
            next_url = links.get("next")
            if next_url:
                url = next_url
                params = None
        return results

    def get_programmes(self) -> list[dict]:
        return self._paginate("/hackers/programs")

    def get_scope(self, handle: str) -> list[ScopeAsset]:
        raw = self._paginate(f"/programs/{handle}/structured_scopes")
        assets = []
        for item in raw:
            attrs = item.get("attributes", {}) or {}
            eligible = attrs.get("eligible_for_submission", False)
            identifier = attrs.get("asset_identifier", "")
            h1_type = attrs.get("asset_type", "other")
            max_sev = attrs.get("maximum_severity", "none")
            instruction = attrs.get("instruction", "")
            sa = ScopeAsset(
                identifier=identifier,
                asset_type=_map_asset_type(h1_type),
                eligible=eligible,
                max_severity=max_sev or "none",
                instruction=instruction or "",
            )
            assets.append(sa)
        return assets

    def get_disclosed_reports(self, handle: str, limit: int = 200) -> list[DisclosedReport]:
        ninety_days_ago = datetime.now(timezone.utc).timestamp() - (90 * 86400)
        params = {
            "page[size]": min(limit, 100),
            "filter[program][][]": handle,
        }
        raw = self._paginate("/hackers/me/hacktivity", params=params)
        reports = []
        for item in raw:
            attrs = item.get("attributes", {}) or {}
            disclosed_at = attrs.get("disclosed_at", "") or ""
            if not disclosed_at:
                continue
            try:
                disclosed_ts = datetime.fromisoformat(disclosed_at.replace("Z", "+00:00")).timestamp()
            except (ValueError, TypeError):
                continue
            if disclosed_ts < ninety_days_ago:
                continue
            relationships = item.get("relationships", {}) or {}
            report_rel = relationships.get("report", {}) or {}
            report_data = report_rel.get("data", {}) or {}
            report_id = report_data.get("id", "")
            report_attrs = report_data.get("attributes", {}) or {}
            title = report_attrs.get("title", "")
            weakness = ""
            weakness_rel = report_data.get("relationships", {}).get("weakness", {}) or {}
            weakness_data = weakness_rel.get("data", {}) or {}
            weakness_attrs = weakness_data.get("attributes", {}) or {}
            weakness = weakness_attrs.get("name", "")
            severity = ""
            sev_rel = report_data.get("relationships", {}).get("severity", {}) or {}
            sev_data = sev_rel.get("data", {}) or {}
            sev_attrs = sev_data.get("attributes", {}) or {}
            severity = sev_attrs.get("rating", "") or sev_attrs.get("score", "")
            asset = ""
            scope_rel = report_data.get("relationships", {}).get("structured_scope", {}) or {}
            scope_data = scope_rel.get("data", {}) or {}
            scope_attrs = scope_data.get("attributes", {}) or {}
            asset = scope_attrs.get("asset_identifier", "")
            dr = DisclosedReport(
                id=str(report_id),
                title=title or "",
                weakness=weakness or "",
                severity=str(severity) if severity else "none",
                asset=asset,
                disclosed_at=disclosed_at,
            )
            reports.append(dr)
        return reports

    def build_programme_intel(self, handle: str) -> ProgrammeIntel | None:
        cache_data = _load_cache(self._cache_path)
        cached = cache_data.get(handle)
        if cached and not _is_cache_stale(cached):
            return self._dict_to_intel(cached["intel"])
        try:
            programmes = self.get_programmes()
        except HackerOneAPIError as e:
            print(f"[!] HackerOne API error fetching programmes: {e}")
            return None
        prog_data = None
        for p in programmes:
            attrs = p.get("attributes", {}) or {}
            if attrs.get("handle", "") == handle:
                prog_data = p
                break
        if not prog_data:
            print(f"[!] Programme '{handle}' not found in accessible programmes")
            return None
        attrs = prog_data.get("attributes", {}) or {}
        name = attrs.get("name", handle)
        offers_bounties = attrs.get("offers_bounties", False) or attrs.get("bounty", False)
        payout = attrs.get("payout", {}) or {}
        raw_max = attrs.get("maximum_bounty", {}) or payout
        max_crit = raw_max.get("critical", 0) if isinstance(raw_max, dict) else 0
        max_high = raw_max.get("high", 0) if isinstance(raw_max, dict) else 0
        max_med = raw_max.get("medium", 0) if isinstance(raw_max, dict) else 0
        try:
            scope = self.get_scope(handle)
        except HackerOneAPIError as e:
            print(f"[!] HackerOne API error fetching scope: {e}")
            scope = []
        in_scope = [s for s in scope if s.eligible]
        out_of_scope = [s for s in scope if not s.eligible]
        try:
            reports = self.get_disclosed_reports(handle)
        except HackerOneAPIError as e:
            print(f"[!] HackerOne API error fetching disclosed reports: {e}")
            reports = []
        sat_score = len(reports) / max(len(in_scope), 1)
        ev_score = (
            (int(max_crit) * 0.05 + int(max_high) * 0.15 + int(max_med) * 0.30)
            / max(len(in_scope), 1)
            / (1 + sat_score)
        )
        intel = ProgrammeIntel(
            handle=handle,
            name=name,
            offers_bounties=bool(offers_bounties),
            max_payout_critical=int(max_crit),
            max_payout_high=int(max_high),
            max_payout_medium=int(max_med),
            in_scope=in_scope,
            out_of_scope=out_of_scope,
            disclosed_reports=reports,
            saturation_score=sat_score,
            expected_value_score=ev_score,
        )
        self._cache_intel(handle, intel)
        return intel

    def _cache_intel(self, handle: str, intel: ProgrammeIntel):
        cache_data = _load_cache(self._cache_path)
        cache_data[handle] = {
            "fetched_at": datetime.now(timezone.utc).isoformat(),
            "intel": self._intel_to_dict(intel),
        }
        _save_cache(self._cache_path, cache_data)

    def _intel_to_dict(self, intel: ProgrammeIntel) -> dict:
        return {
            "handle": intel.handle,
            "name": intel.name,
            "offers_bounties": intel.offers_bounties,
            "max_payout_critical": intel.max_payout_critical,
            "max_payout_high": intel.max_payout_high,
            "max_payout_medium": intel.max_payout_medium,
            "in_scope": [asdict(s) for s in intel.in_scope],
            "out_of_scope": [asdict(s) for s in intel.out_of_scope],
            "disclosed_reports": [asdict(r) for r in intel.disclosed_reports],
            "saturation_score": intel.saturation_score,
            "expected_value_score": intel.expected_value_score,
        }

    def _dict_to_intel(self, d: dict) -> ProgrammeIntel:
        return ProgrammeIntel(
            handle=d.get("handle", ""),
            name=d.get("name", ""),
            offers_bounties=d.get("offers_bounties", False),
            max_payout_critical=d.get("max_payout_critical", 0),
            max_payout_high=d.get("max_payout_high", 0),
            max_payout_medium=d.get("max_payout_medium", 0),
            in_scope=[ScopeAsset(**s) for s in d.get("in_scope", [])],
            out_of_scope=[ScopeAsset(**s) for s in d.get("out_of_scope", [])],
            disclosed_reports=[DisclosedReport(**r) for r in d.get("disclosed_reports", [])],
            saturation_score=d.get("saturation_score", 0.0),
            expected_value_score=d.get("expected_value_score", 0.0),
        )

    @staticmethod
    def _provisional_score(attrs: dict) -> float:
        """Quick score from list data — no extra API calls."""
        payout = attrs.get("payout", {}) or {}
        raw_max = attrs.get("maximum_bounty", {}) or payout
        crit = int(raw_max.get("critical", 0) if isinstance(raw_max, dict) else raw_max.get("maximum", 0) or 0)
        high = int(raw_max.get("high", 0) if isinstance(raw_max, dict) else 0)
        med = int(raw_max.get("medium", 0) if isinstance(raw_max, dict) else 0)
        total = crit * 0.05 + high * 0.15 + med * 0.30
        if attrs.get("offers_bounties", False) or attrs.get("bounty", False):
            total += 10
        return total

    def list_programmes_ranked(self, top_n: int = 20) -> list[ProgrammeIntel]:
        cache_data = _load_cache(self._cache_path)
        try:
            programmes = self.get_programmes()
        except HackerOneAPIError as e:
            print(f"[!] HackerOne API error: {e}")
            return []
        # Score provisionally from list data, pick top candidates
        scored = []
        for p in programmes:
            attrs = p.get("attributes", {}) or {}
            handle = attrs.get("handle", "")
            if not handle:
                continue
            score = self._provisional_score(attrs)
            scored.append((score, handle, attrs))
        scored.sort(key=lambda x: x[0], reverse=True)
        candidates = scored[:top_n]
        # Build detailed intel only for the top candidates
        ranked: list[ProgrammeIntel] = []
        for _, handle, attrs in candidates:
            cached = cache_data.get(handle)
            if cached and not _is_cache_stale(cached):
                intel = self._dict_to_intel(cached["intel"])
            else:
                intel = self.build_programme_intel(handle)
            if intel:
                ranked.append(intel)
        ranked.sort(key=lambda x: x.expected_value_score, reverse=True)
        return ranked
