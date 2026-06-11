import json
import os
import re
import sys
import threading
from datetime import datetime
from typing import Any
from urllib.parse import urlparse, urljoin

import requests

from modules.utils import log, Colors, make_session


def load_session_file(path: str) -> dict:
    """Load a session from a JSON file, Burp cookie jar, or cookie string format."""
    if not path or not os.path.isfile(path):
        log(f"[!] Session file not found: {path}", Colors.RED)
        sys.exit(1)
    with open(path) as f:
        content = f.read().strip()
    # Try JSON
    try:
        data = json.loads(content)
        if isinstance(data, dict):
            return data
    except json.JSONDecodeError:
        pass
    # Try Burp cookie jar format (one cookie per line, name=value)
    if "=" in content and "\n" in content:
        cookies = {}
        for line in content.splitlines():
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                k, v = line.split("=", 1)
                cookies[k.strip()] = v.strip()
        if cookies:
            return {"cookies": cookies}
    # Try browser document.cookie string
    if "=" in content and ";" in content:
        cookies = {}
        for part in content.split(";"):
            part = part.strip()
            if "=" in part:
                k, v = part.split("=", 1)
                cookies[k.strip()] = v.strip()
        if cookies:
            return {"cookies": cookies}
    log(f"[!] Unrecognised session format in {path}", Colors.RED)
    sys.exit(1)


def _apply_session_to_session(session: requests.Session, session_data: dict):
    """Apply cookies and headers from a session data dict to a requests.Session."""
    cookies = session_data.get("cookies", {})
    for name, value in cookies.items():
        session.cookies.set(name, value)
    headers = session_data.get("headers", {})
    for name, value in headers.items():
        session.headers[name] = value


def _extract_resources(url: str, response: requests.Response, label: str) -> list[dict]:
    """Extract resource IDs and types from a URL and response body."""
    resources = []
    parsed = urlparse(url)
    path = parsed.path.rstrip("/")
    segments = [s for s in path.split("/") if s]

    # Resource type from URL path structure: /api/users/123 -> type=users, id=123
    for i, seg in enumerate(segments):
        if re.match(r'^[a-f0-9\-]{36}$', seg, re.I):
            resource_type = segments[i - 1] if i > 0 else "unknown"
            resources.append({"type": resource_type, "id": seg, "url": url, "source": label})
        elif seg.isdigit() and len(seg) >= 3:
            resource_type = segments[i - 1] if i > 0 else "unknown"
            resources.append({"type": resource_type, "id": seg, "url": url, "source": label})

    # Extract from JSON response body
    if response.text and "application/json" in response.headers.get("Content-Type", ""):
        try:
            body = response.json()
            _extract_ids_from_json(body, url, label, resources)
        except (json.JSONDecodeError, ValueError):
            pass

    return resources


def _extract_ids_from_json(obj: Any, url: str, label: str, resources: list[dict], prefix: str = ""):
    """Recursively extract resource IDs from a parsed JSON object."""
    if isinstance(obj, dict):
        for key, value in obj.items():
            key_lower = key.lower()
            current_prefix = f"{prefix}.{key}" if prefix else key
            if key_lower in ("id", "uuid", "user_id", "account_id", "owner_id",
                              "customer_id", "order_id", "organisation_id",
                              "team_id", "profile_id") and isinstance(value, (str, int)):
                resources.append({"type": prefix.split(".")[-1] if prefix else key, "id": str(value), "url": url, "source": label})
            elif key_lower in ("email",) and isinstance(value, str) and "@" in value:
                resources.append({"type": "email", "id": value, "url": url, "source": label})
            elif key_lower in ("username", "handle", "login") and isinstance(value, str):
                resources.append({"type": "username", "id": value, "url": url, "source": label})
            else:
                _extract_ids_from_json(value, url, label, resources, current_prefix)
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            _extract_ids_from_json(item, url, label, resources, f"{prefix}[{i}]")


def _compare_responses(resp_a: requests.Response, resp_b: requests.Response) -> dict | None:
    """Compare two responses for semantic content matches (IDOR detection)."""
    if resp_a.status_code != resp_b.status_code:
        return None
    if resp_a.status_code >= 400:
        return None
    if not resp_a.text or not resp_b.text:
        return None
    if "application/json" in resp_a.headers.get("Content-Type", ""):
        try:
            data_a = resp_a.json()
            data_b = resp_b.json()
        except (json.JSONDecodeError, ValueError):
            return None
        diffs = _find_semantic_matches(data_a, data_b)
        if diffs:
            return {
                "status_a": resp_a.status_code,
                "status_b": resp_b.status_code,
                "matches": diffs,
                "body_a_preview": resp_a.text[:500],
                "body_b_preview": resp_b.text[:500],
            }
    else:
        # Non-JSON: check if bodies are similar (same length, same content)
        if resp_a.text == resp_b.text:
            return {
                "status_a": resp_a.status_code,
                "status_b": resp_b.status_code,
                "matches": [{"field": "full_body", "value_a": "(same)", "value_b": "(same)"}],
                "body_a_preview": resp_a.text[:500],
                "body_b_preview": resp_b.text[:500],
            }
    return None


_SENSITIVE_FIELDS = {"email", "username", "name", "phone", "address", "ssn",
                     "credit_card", "iban", "role", "permissions", "admin",
                     "private", "internal", "secret", "token", "key"}


def _find_semantic_matches(a: Any, b: Any, path: str = "") -> list[dict]:
    """Recursive comparison finding fields where b exposes a's data (same values in sensitive fields)."""
    diffs = []
    if isinstance(a, dict) and isinstance(b, dict):
        all_keys = set(a.keys()) | set(b.keys())
        for key in all_keys:
            current_path = f"{path}.{key}" if path else key
            if key not in b:
                continue
            if key not in a:
                continue
            val_a = a[key]
            val_b = b[key]
            key_lower = key.lower()
            is_sensitive = any(s in key_lower for s in _SENSITIVE_FIELDS)
            if isinstance(val_a, (dict, list)) and isinstance(val_b, (dict, list)):
                diffs.extend(_find_semantic_matches(val_a, val_b, current_path))
            elif is_sensitive and val_a == val_b and val_a is not None and val_a != "":
                diffs.append({"field": current_path, "value_a": str(val_a), "value_b": str(val_b)})
    elif isinstance(a, list) and isinstance(b, list):
        for i in range(min(len(a), len(b))):
            diffs.extend(_find_semantic_matches(a[i], b[i], f"{path}[{i}]"))
    return diffs


def _build_idor_finding(resource: dict, comparison: dict,
                        session_a_label: str, session_b_label: str,
                        base_url: str, test_type: str = "access") -> dict:
    """Build a finding dict for an IDOR vulnerability."""
    title = f"IDOR: {session_a_label}'s {resource['type']} accessible by {session_b_label}"
    if test_type == "write":
        title = f"IDOR Write: {session_b_label} can modify {session_a_label}'s {resource['type']}"
    elif test_type == "mass_assignment":
        title = f"Mass Assignment: {session_b_label} creates resource owned by {session_a_label}"

    details = (
        f"Resource type: {resource['type']}\n"
        f"Resource ID: {resource['id']}\n"
        f"URL: {resource['url']}\n"
        f"Session A ({session_a_label}): Resource owner\n"
        f"Session B ({session_b_label}): Unauthorised accessor\n"
        f"Test type: {test_type}\n"
    )
    if comparison:
        matches_str = "\n".join(f"  {m['field']}: {m['value_a']}" for m in comparison.get("matches", []))
        details += f"Matched fields:\n{matches_str}\n"

    evidence_html = _build_side_by_side_html(comparison, resource, session_a_label, session_b_label, test_type) if comparison else ""

    steps = [
        f"1. Authenticate as {session_a_label} and access the resource at {resource['url']}",
        f"2. Extract the {resource['type']} ID from the response: {resource['id']}",
        f"3. Switch to {session_b_label}'s session",
        f"4. Request the same resource URL: {resource['url']}",
        f"5. Observe that {session_b_label} receives {session_a_label}'s data",
    ]
    if test_type == "write":
        steps = [
            f"1. Authenticate as {session_a_label} at the target",
            f"2. Identify a writable resource at {resource['url']}",
            f"3. Switch to {session_b_label}'s session",
            f"4. Send PUT/PATCH request to modify the resource owned by {session_a_label}",
            f"5. Observe that the modification succeeds — {session_b_label} can alter {session_a_label}'s data",
        ]
    elif test_type == "mass_assignment":
        steps = [
            f"1. Authenticate as {session_a_label} and note your user ID",
            f"2. Switch to {session_b_label}'s session",
            f"3. Send a POST request to create a new resource, including 'owner_id={resource['id']}'",
            f"4. Switch back to {session_a_label}'s session",
            f"5. Fetch the created resource — observe that it is owned by {session_a_label}",
        ]

    return {
        "title": title,
        "vuln_type": "idor",
        "severity": "high" if test_type == "write" else "medium",
        "url": resource["url"],
        "description": details,
        "details": details,
        "evidence": evidence_html,
        "steps_to_reproduce": steps,
        "verification_stage": "validated",
        "confidence_score": 80,
        "session_a_label": session_a_label,
        "session_b_label": session_b_label,
        "resource_type": resource["type"],
        "resource_id": resource["id"],
        "test_type": test_type,
        "comparison": comparison,
    }


def _build_side_by_side_html(comparison: dict, resource: dict,
                               session_a_label: str, session_b_label: str,
                               test_type: str) -> str:
    """Generate a self-contained HTML page with side-by-side response comparison."""
    matches = comparison.get("matches", [])
    body_a = comparison.get("body_a_preview", "")
    body_b = comparison.get("body_b_preview", "")

    highlighted_body_a = body_a
    highlighted_body_b = body_b
    for m in matches:
        val = m.get("value_a", "")
        if val:
            highlighted_body_a = highlighted_body_a.replace(val, f'<span class="match">{val}</span>')
            highlighted_body_b = highlighted_body_b.replace(val, f'<span class="match">{val}</span>')

    match_rows = "".join(
        f"<tr><td>{m['field']}</td><td class='match'>{m['value_a']}</td><td class='match'>{m['value_b']}</td></tr>"
        for m in matches
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>IDOR Evidence — {resource['type']} #{resource['id']}</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 20px; background: #f5f5f5; }}
.container {{ max-width: 1200px; margin: 0 auto; }}
.header {{ background: #fff; padding: 20px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
.header h1 {{ margin: 0 0 10px; color: #d00; }}
.header .meta {{ color: #666; font-size: 14px; }}
.comparison {{ display: flex; gap: 20px; margin-bottom: 20px; }}
.panel {{ flex: 1; background: #fff; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); overflow: hidden; }}
.panel h2 {{ margin: 0; padding: 12px 16px; font-size: 14px; }}
.panel.a h2 {{ background: #e3f2fd; color: #1565c0; }}
.panel.b h2 {{ background: #fff3e0; color: #e65100; }}
.panel pre {{ padding: 12px 16px; font-size: 12px; overflow-x: auto; white-space: pre-wrap; word-break: break-all; }}
.match {{ background: #ffebee !important; color: #c62828 !important; font-weight: bold; }}
table {{ width: 100%; border-collapse: collapse; margin-bottom: 20px; background: #fff; border-radius: 8px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
th, td {{ padding: 10px 16px; text-align: left; border-bottom: 1px solid #eee; }}
th {{ background: #f5f5f5; font-size: 13px; }}
td {{ font-size: 13px; font-family: monospace; }}
.steps {{ background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
.steps ol {{ margin: 0; padding-left: 20px; }}
.steps li {{ margin-bottom: 8px; font-size: 14px; }}
</style>
</head>
<body>
<div class="container">
<div class="header">
<h1>⚠ IDOR Vulnerability — {resource['type']} #{resource['id']}</h1>
<p class="meta">
  <strong>Test Type:</strong> {test_type}<br>
  <strong>Session A ({session_a_label}):</strong> Resource owner<br>
  <strong>Session B ({session_b_label}):</strong> Unauthorised accessor<br>
  <strong>URL:</strong> <code>{resource['url']}</code><br>
  <strong>Resource ID:</strong> <code>{resource['id']}</code>
</p>
</div>

<h3>Matched Sensitive Fields</h3>
<table>
<tr><th>Field</th><th>{session_a_label}</th><th>{session_b_label}</th></tr>
{match_rows}
</table>

<h3>Response Comparison</h3>
<div class="comparison">
<div class="panel a"><h2>{session_a_label} (Owner)</h2><pre>{highlighted_body_a}</pre></div>
<div class="panel b"><h2>{session_b_label} (Tester)</h2><pre>{highlighted_body_b}</pre></div>
</div>

<h3>Steps to Reproduce</h3>
<div class="steps"><ol>
"""
    for s in ([
        f"Authenticate as {session_a_label} and access {resource['url']}",
        f"Capture the resource ID: {resource['id']}",
        f"Switch to {session_b_label}'s session",
        f"Request the same resource URL with {session_b_label}'s credentials",
        f"{session_b_label} receives {session_a_label}'s data — IDOR confirmed",
    ]):
        html += f"<li>{s}</li>\n"

    html += """</ol></div></div></body></html>"""
    return html


def run_idor_scan(config: dict) -> list[dict]:
    """Run the 4-phase IDOR scan with two sessions."""
    session_a_path = config.get("session_a", "")
    session_b_path = config.get("session_b", "")
    target = config.get("target", "")

    if not session_a_path or not session_b_path:
        log("[!] --session-a and --session-b are required for --mode idor", Colors.RED)
        sys.exit(1)

    if not target:
        log("[!] --target is required for --mode idor", Colors.RED)
        sys.exit(1)

    log("[*] Loading sessions...", Colors.CYAN)
    session_a_data = load_session_file(session_a_path)
    session_b_data = load_session_file(session_b_path)
    label_a = session_a_data.get("account_label", "Account A")
    label_b = session_b_data.get("account_label", "Account B")

    sess_a = make_session(config)
    sess_b = make_session(config)
    _apply_session_to_session(sess_a, session_a_data)
    _apply_session_to_session(sess_b, session_b_data)

    all_findings: list[dict] = []
    resource_map: dict[str, list[dict]] = {}
    discovered_urls: set[str] = set()

    # ── Phase 1: Resource Discovery with session A ──────────────────────
    log(f"[*] Phase 1: Resource discovery as {label_a}...", Colors.CYAN)
    crawl_queue = [target]
    visited: set[str] = set()
    crawl_depth = config.get("crawl_depth", 2)

    for _ in range(crawl_depth):
        next_batch = []
        for url in crawl_queue:
            if url in visited:
                continue
            visited.add(url)
            try:
                resp = sess_a.get(url, timeout=15)
                discovered_urls.add(url)
                resources = _extract_resources(url, resp, label_a)
                for r in resources:
                    resource_map.setdefault(r["type"], []).append(r)
                # Discover more URLs from response
                if "text/html" in resp.headers.get("Content-Type", ""):
                    links = re.findall(r'href=[\'"]?([^\'" >]+)', resp.text)
                    for link in links:
                        full_url = urljoin(url, link)
                        if target.rstrip("/") in full_url and full_url not in visited:
                            next_batch.append(full_url)
                # Discover API URLs from JSON responses
                if "application/json" in resp.headers.get("Content-Type", ""):
                    try:
                        body = resp.json()
                        _discover_urls_from_json(body, target, discovered_urls, next_batch)
                    except (json.JSONDecodeError, ValueError):
                        pass
            except requests.RequestException:
                pass
        crawl_queue = next_batch[:20]  # limit per depth

    log(f"[+] Phase 1 complete: {len(resource_map)} resource type(s), {sum(len(v) for v in resource_map.values())} resource(s) discovered", Colors.GREEN)
    for rtype, resources in resource_map.items():
        log(f"    {rtype}: {len(resources)} IDs", Colors.CYAN)

    # ── Phase 2: Access testing with session B ──────────────────────────
    log(f"[*] Phase 2: Access testing as {label_b}...", Colors.CYAN)
    for url in sorted(discovered_urls):
        try:
            resp_a = sess_a.get(url, timeout=15)
            resp_b = sess_b.get(url, timeout=15)
        except requests.RequestException:
            continue

        comparison = _compare_responses(resp_a, resp_b)
        if comparison and comparison.get("matches"):
            rtype = "unknown"
            rid = ""
            for rt, resources in resource_map.items():
                for r in resources:
                    if r["url"] == url:
                        rtype = rt
                        rid = r["id"]
                        break
            finding = _build_idor_finding(
                resource={"type": rtype, "id": rid, "url": url},
                comparison=comparison,
                session_a_label=label_a,
                session_b_label=label_b,
                base_url=target,
            )
            all_findings.append(finding)
            log(f"[FOUND] [MEDIUM] {finding['title']} @ {url}", Colors.GREEN)

    # ── Phase 3: Write testing (PUT/PATCH) ─────────────────────────────
    log(f"[*] Phase 3: Write testing...", Colors.CYAN)
    for url in sorted(discovered_urls):
        try:
            opts = sess_a.options(url, timeout=15)
            allow = opts.headers.get("Allow", "")
            if "PUT" not in allow and "PATCH" not in allow:
                continue
        except requests.RequestException:
            continue

        try:
            # Fetch Alice's resource
            resp_a_get = sess_a.get(url, timeout=15)
        except requests.RequestException:
            continue

        if "application/json" in resp_a_get.headers.get("Content-Type", ""):
            try:
                body = resp_a_get.json()
            except (json.JSONDecodeError, ValueError):
                continue
        else:
            continue

        try:
            resp_b_put = sess_b.put(url, json=body, timeout=15)
            if resp_b_put.status_code < 400:
                rtype = "unknown"
                rid = ""
                for rt, resources in resource_map.items():
                    for r in resources:
                        if r["url"] == url:
                            rtype = rt
                            rid = r["id"]
                            break
                finding = _build_idor_finding(
                    resource={"type": rtype, "id": rid, "url": url},
                    comparison=_compare_responses(resp_a_get, resp_b_put),
                    session_a_label=label_a,
                    session_b_label=label_b,
                    base_url=target,
                    test_type="write",
                )
                all_findings.append(finding)
                log(f"[FOUND] [HIGH] {finding['title']} @ {url}", Colors.GREEN)
        except requests.RequestException:
            pass

    # ── Phase 4: Mass assignment testing ────────────────────────────────
    log(f"[*] Phase 4: Mass assignment testing...", Colors.CYAN)
    collected_ids = set()
    for rt, resources in resource_map.items():
        for r in resources:
            if r["id"] not in collected_ids:
                collected_ids.add(r["id"])

    # Identify POST endpoints from discovered URLs that create resources
    post_endpoints = set()
    for url in sorted(discovered_urls):
        path = urlparse(url).path.rstrip("/")
        segs = [s for s in path.split("/") if s]
        # Endpoints ending in a plural noun without a trailing ID are likely creation endpoints
        if segs and not segs[-1].isdigit() and not re.match(r'^[a-f0-9\-]{36}$', segs[-1], re.I):
            # Check if the last segment is plural
            if segs[-1].endswith("s"):
                post_endpoints.add(url)

    for endpoint in post_endpoints:
        for owner_id in list(collected_ids)[:5]:  # Try first 5 discovered IDs
            for field_name in ("owner_id", "user_id", "account_id", "created_by"):
                try:
                    payload = {field_name: owner_id, "name": "test_resource", "data": "test"}
                    resp_b = sess_b.post(endpoint, json=payload, timeout=15)
                    if resp_b.status_code < 400:
                        finding = _build_idor_finding(
                            resource={"type": urlparse(endpoint).path.split("/")[-1], "id": owner_id, "url": endpoint},
                            comparison=None,
                            session_a_label=label_a,
                            session_b_label=label_b,
                            base_url=target,
                            test_type="mass_assignment",
                        )
                        all_findings.append(finding)
                        # Only one report per endpoint
                        break
                except requests.RequestException:
                    pass

    log(f"[+] IDOR scan complete: {len(all_findings)} finding(s)", Colors.GREEN)
    return all_findings


def _discover_urls_from_json(obj: Any, base_url: str, discovered: set, queue: list):
    """Recursively discover API URLs from JSON response bodies."""
    if isinstance(obj, dict):
        for key, value in obj.items():
            key_lower = key.lower()
            if key_lower in ("url", "link", "self", "href", "endpoint") and isinstance(value, str):
                if value.startswith("/") or value.startswith("http"):
                    full = urljoin(base_url, value)
                    if base_url.rstrip("/") in full and full not in discovered:
                        discovered.add(full)
                        queue.append(full)
            else:
                _discover_urls_from_json(value, base_url, discovered, queue)
    elif isinstance(obj, list):
        for item in obj:
            _discover_urls_from_json(item, base_url, discovered, queue)
