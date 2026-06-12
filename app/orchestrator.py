import json
import os
import re
import threading
from typing import Any

from modules.scanner import VulnScanner
from modules.api_scanner import ApiScanner
from modules.utils import (
    log, Colors, classify_endpoint, compute_endpoint_score,
    prioritize_findings, ScanProgress,
)
from models.finding import Finding, FindingState
from models.evidence import ResponseExcerptEvidence
from engines.dedup import DeduplicationEngine


def _run_module_with_timeout(mod_fn, module_timeout):
    """Run a module function with a wall-clock timeout using a watchdog thread."""
    result = []
    exception = []
    done = threading.Event()

    def worker():
        try:
            r = mod_fn()
            if r is not None:
                result.extend(r if isinstance(r, list) else [r])
        except Exception as e:
            exception.append(e)
        finally:
            done.set()

    t = threading.Thread(target=worker, daemon=True)
    t.start()
    if not done.wait(timeout=module_timeout):
        log(f"  [!] Module timed out after {module_timeout}s — skipping", Colors.RED)
        return []
    if exception:
        raise exception[0]
    return result


def _selected_module_names(config: dict, run_all: bool, disabled_modules: set, candidates: list[str]) -> list[str]:
    selected = []
    requested = set(config.get("modules", []))
    for name in candidates:
        if name in disabled_modules:
            continue
        if run_all or name in requested:
            selected.append(name)
    return selected


def _collect_module_findings(modules, config, run_all, disabled_modules, all_findings, lock, prog=None):
    module_timeout = int(config.get("module_timeout", 120))
    total = len(modules)
    for i, (mod_name, mod_fn) in enumerate(modules.items(), 1):
        if mod_name in disabled_modules:
            log(f"[-] Skipping disabled module {mod_name.upper()}", Colors.CYAN)
            continue
        if not (run_all or mod_name in config["modules"]):
            continue
        if prog:
            prog.update(f"[{i}/{total}] {mod_name.upper()}...")
        else:
            log(f"[{i}/{total}] Running {mod_name.upper()}...", Colors.CYAN)
        findings = _run_module_with_timeout(mod_fn, module_timeout)
        if findings:
            log(f"[!] {len(findings)} finding(s) from {mod_name.upper()}", Colors.RED)
            with lock:
                all_findings.extend(findings)
        else:
            log(f"[+] {mod_name.upper()} — nothing found", Colors.GREEN)
    if prog:
        prog.stop()


def _run_passive_scans(config, recon_data, run_all, disabled_modules, all_findings, lock, container=None):
    """Run modules that do not send exploit/fuzz payloads.

    Passive mode should still produce useful default reports. Keep this list
    limited to GET/header/body analysis and already-collected form metadata.
    """
    scanner = VulnScanner(config, recon_data, container=container)
    passive_modules: dict[str, Any] = {
        "headers": scanner.scan_headers,
        "clickjacking": scanner.scan_clickjacking,
        "sensitive": scanner.scan_sensitive_data,
        "insecure_forms": scanner.scan_insecure_forms,
    }
    passive_order = ["headers", "clickjacking", "sensitive", "insecure_forms"]
    selected = _selected_module_names(config, run_all, disabled_modules, passive_order)

    requested_active = [
        name for name in config.get("modules", [])
        if name not in ("all", *passive_order) and name not in disabled_modules
    ]
    if requested_active and not run_all:
        log(
            f"[-] Passive mode skipped active module(s): {', '.join(requested_active)}",
            Colors.YELLOW,
        )

    if not selected:
        log("[*] Passive mode selected no runnable passive modules.", Colors.YELLOW)
        return

    total = len(selected)
    for i, mod_name in enumerate(selected, 1):
        before = len(scanner._get_findings())
        log(f"[{i}/{total}] Running {mod_name.upper()}...", Colors.CYAN)
        try:
            if mod_name in ("sensitive", "insecure_forms"):
                passive_modules[mod_name](target_urls=recon_data.get("urls", []))
            else:
                passive_modules[mod_name]()
        except Exception as e:
            log(f"  [!] {mod_name} error: {e}", Colors.RED, verbose_only=True, verbose=config.get("verbose", False))
            continue

        after_findings = scanner._get_findings()
        delta = len(after_findings) - before
        if delta > 0:
            log(f"[!] {delta} finding(s) from {mod_name.upper()}", Colors.RED)
        else:
            log(f"[+] {mod_name.upper()} — nothing found", Colors.GREEN)

    with lock:
        all_findings.clear()
        all_findings.extend(scanner._get_findings())


def _exec_tech_specific(config: dict, recon_data: dict, session) -> list[dict]:
    try:
        from scanners.tech_specific import TechSpecificScannerRegistry
        tech_registry = TechSpecificScannerRegistry()
        detected_frameworks = recon_data.get("technology", {})
        return tech_registry.scan_all(
            base_urls=recon_data.get("urls", []),
            detected_frameworks=detected_frameworks,
            session=session,
        )
    except Exception as e:
        log(f"[!] TECH_SPECIFIC error: {e}", Colors.YELLOW)
        return []


def _exec_business_logic(config: dict, recon_data: dict, session) -> list[dict]:
    try:
        from scanners.business_logic import BusinessLogicScanner
        bl_scanner = BusinessLogicScanner(config, session=session, recon=recon_data)
        return bl_scanner.run_all(
            urls=recon_data.get("urls", []),
            forms=recon_data.get("forms", []),
        )
    except Exception as e:
        log(f"[!] BUSINESS_LOGIC error: {e}", Colors.YELLOW)
        return []


def run_scans(config, recon_data, recon, run_all, disabled_modules, all_findings, lock, container=None, capabilities=None):
    # ── TARGET_LEVEL: modules that run once per target, not per URL ──
    TARGET_LEVEL: set[str] = {
        "headers", "dirb", "exposed_files", "clickjacking",
        "subdomain_takeover", "graphql", "blind_xss", "api", "openapi",
        "http_methods", "authorization",
        "cors", "jwt", "cms",
        "rate_limiting",
        "tech_specific", "business_logic",
        "auth_bypass", "smuggling",
        "recon",
    }

    if config["passive"]:
        log("[*] Passive mode — skipping active fuzzing.", Colors.YELLOW)
        _run_passive_scans(config, recon_data, run_all, disabled_modules, all_findings, lock, container=container)
        return

    scanner = VulnScanner(config, recon_data, container=container)
    # ── Inject audit logger into config for safe_get/safe_post ─────────
    if container and hasattr(container, 'audit_logger'):
        config["_audit_logger"] = container.audit_logger
    all_findings_local: list[dict] = []

    # ── Pre-scan object harvesting (feed recon data into DiscoveryStore before TARGET_LEVEL modules) ──
    if container and hasattr(container, 'object_harvester') and hasattr(container, 'discovery_store'):
        try:
            harvester = container.object_harvester
            pre_harvest_count = 0
            # Harvest from form HTML
            for form in recon_data.get("forms", []):
                form_html = form.get("html", "") or form.get("action", "")
                if form_html and len(form_html) > 50:
                    pre_harvest_count += len(harvester.harvest(
                        url=form.get("action", ""), response_text=str(form_html)))
            # Harvest from JS response excerpts in js_data
            js_data = recon_data.get("js_data", {})
            for js_key in ("js_urls", "js_content", "endpoints"):
                js_items = js_data.get(js_key, []) if isinstance(js_data, dict) else []
                if isinstance(js_items, list):
                    for item in js_items:
                        if isinstance(item, str) and len(item) > 100:
                            pre_harvest_count += len(harvester.harvest(
                                url=item, response_text=item[:2000]))
                        elif isinstance(item, dict):
                            content = item.get("content", "") or item.get("response", "")
                            if content and len(content) > 100:
                                pre_harvest_count += len(harvester.harvest(
                                    url=item.get("url", ""), response_text=str(content)[:2000]))
            if pre_harvest_count:
                log(f"[+] Pre-scan harvest: {pre_harvest_count} objects from recon data",
                    Colors.GREEN, verbose_only=True, verbose=config.get("verbose", False))
            # Rebuild discovery hints after early harvest
            if hasattr(container, 'discovery_store'):
                ds = container.discovery_store
                ownership_urls: list[str] = []
                for cat in ("ownership_hint", "ownership_relationship"):
                    for rec in ds.get_by_category(cat):
                        src = rec.get("source_url", "")
                        if src and src not in ownership_urls:
                            ownership_urls.append(src)
                if hasattr(container, 'relationship_graph'):
                    graph = container.relationship_graph
                    boundaries = graph.get_ownership_boundaries()
                    for pattern in boundaries:
                        if pattern not in ownership_urls:
                            ownership_urls.append(pattern)
                recon_data.setdefault("_discovery_hints", {})["ownership_urls"] = ownership_urls
                recon_data.setdefault("_discovery_hints", {})["auth_patterns"] = ownership_urls
        except Exception as e:
            log(f"[!] Pre-scan harvest failed: {e}", Colors.YELLOW,
                verbose_only=True, verbose=config.get("verbose", False))

    # ── GraphQL response URL injection (consume graphql_response signals) ──
    if container and hasattr(container, 'discovery_store'):
        try:
            ds = container.discovery_store
            gql_response_urls = ds.get_by_category("graphql_response")
            gql_urls_added = 0
            for rec in gql_response_urls:
                gql_url = rec.get("value", "") or rec.get("source_url", "")
                if gql_url and gql_url not in recon_data.get("urls", []):
                    recon_data.setdefault("urls", []).append(gql_url)
                    gql_urls_added += 1
            if gql_urls_added:
                log(f"[+] GQL response signals: {gql_urls_added} URL(s) injected into scan pool",
                    Colors.GREEN, verbose_only=True, verbose=config.get("verbose", False))
        except Exception as e:
            log(f"[!] GQL URL injection failed: {e}", Colors.YELLOW,
                verbose_only=True, verbose=config.get("verbose", False))

    # ── OOB Background Poller (Phase 3) ───────────────────────────────
    oob_poller = None
    if scanner.oob and scanner.oob.oob_host:
        from engines.oob_poller import OOBBackgroundPoller
        oob_poller = OOBBackgroundPoller(
            scanner.oob,
            scanner._promote_finding_by_oob,
            interval=config.get("oob_poll_interval", 4.0),
            max_duration=config.get("oob_poll_max_duration", 300.0),
            max_polls=config.get("oob_poll_max_polls", 0),
            initial_interval=config.get("oob_poll_initial_interval", 2.0),
            max_interval=config.get("oob_poll_max_interval", 30.0),
        )
        oob_poller.start()
        log(f"[*] OOB background poller started (interval={oob_poller.interval}s, max_duration={oob_poller.max_duration}s, max_polls={oob_poller.max_polls})", Colors.CYAN)

    # ── Step 1: Build module map (same keys as original _active_module_map) ──
    _run_tech = lambda: _exec_tech_specific(config, recon_data, scanner.session)
    _run_bl = lambda: _exec_business_logic(config, recon_data, scanner.session)
    module_map: dict[str, Any] = {
        "xss": scanner.scan_xss, "sqli": scanner.scan_sqli,
        "lfi": scanner.scan_lfi, "ssrf": scanner.scan_ssrf,
        "xxe": scanner.scan_xxe,
        "ssti": scanner.scan_ssti,
        "cmd_injection": scanner.scan_command_injection,
        "blind_xss": scanner.scan_blind_xss,
        "open_redirect": scanner.scan_open_redirect,
        "headers": scanner.scan_headers, "csrf": scanner.scan_csrf,
        "dirb": scanner.scan_directory_fuzz,
        "sensitive": scanner.scan_sensitive_data,
        "exposed_files": scanner.scan_exposed_files,
        "clickjacking": scanner.scan_clickjacking,
        "http_methods": scanner.scan_http_methods,
        "insecure_forms": scanner.scan_insecure_forms,
        "subdomain_takeover": scanner.scan_subdomain_takeover,
        "graphql": scanner.scan_graphql,
        "rate_limiting": scanner.scan_rate_limiting,
        "openapi": scanner.scan_openapi,
        "cors": scanner.scan_cors,
        "jwt": scanner.scan_jwt,
        "cms": scanner.scan_cms_checks,
        "tech_specific": _run_tech,
        "business_logic": _run_bl,
        "auth_bypass": scanner.scan_auth_bypass,
        "smuggling": scanner.scan_smuggling,
        "recon": lambda: [],
    }
    _api_scanner = ApiScanner(scanner.config, scanner.recon, container=container)
    module_map["api"] = _api_scanner.run_all
    module_map["idor"] = scanner.scan_idor
    module_map["authorization"] = scanner.scan_authorization

    # ── Step 2: Run TARGET_LEVEL modules first ───────────────────────────
    target_modules = {k: v for k, v in module_map.items() if k in TARGET_LEVEL}
    from modules.utils import ModuleProgress
    with ModuleProgress(config, "Running target-level modules") as mp:
        _collect_module_findings(target_modules, config, run_all, disabled_modules, all_findings_local, lock, prog=mp)
    config.setdefault("status", {})["modules_completed"] = list(target_modules.keys())

    # ── Consume html_comments: extract URLs and params, feed into URL pool ──
    html_comments = recon_data.get("html_comments", [])
    if html_comments:
        from urllib.parse import urlparse
        comment_urls_added = 0
        for hc in html_comments:
            comment_text = hc.get("comment", "")
            source_url = hc.get("source", "")
            if not comment_text:
                continue
            # Extract URLs from HTML comments
            for match in re.findall(r'(https?://[^\s<>"\']+)', comment_text):
                u = match.split("#")[0].rstrip("/")
                if u not in recon_data.get("urls", []):
                    recon_data.setdefault("urls", []).append(u)
                    comment_urls_added += 1
            # Extract params from comments (e.g., parameter names, field names)
            param_matches = re.findall(r'(?:param|parameter|field|var|variable)[:\s]+(\w+)', comment_text, re.IGNORECASE)
            for p in param_matches:
                if p not in recon_data.get("params", []):
                    recon_data.setdefault("params", []).append(p)
        log(f"[*] HTML comments: extracted {comment_urls_added} URL(s) to scan pool",
            Colors.CYAN, verbose_only=True, verbose=config.get("verbose", False))

    # ── Populate discovery hints from DiscoveryStore for priority scoring ──
    if container and hasattr(container, 'discovery_store'):
        try:
            store = container.discovery_store
            ownership_urls: list[str] = []
            for cat in ("ownership_hint", "ownership_relationship"):
                for rec in store.get_by_category(cat):
                    src = rec.get("source_url", "")
                    if src and src not in ownership_urls:
                        ownership_urls.append(src)
            if hasattr(container, 'relationship_graph'):
                graph = container.relationship_graph
                boundaries = graph.get_ownership_boundaries()
                for pattern in boundaries:
                    if pattern not in ownership_urls:
                        ownership_urls.append(pattern)
            recon_data.setdefault("_discovery_hints", {})["ownership_urls"] = ownership_urls
            recon_data.setdefault("_discovery_hints", {})["auth_patterns"] = ownership_urls
        except Exception as e:
            log(f"[!] Discovery hints population failed: {e}", Colors.YELLOW,
                verbose_only=True, verbose=config.get("verbose", False))

    # ── Step 3: Score and sort URLs ──────────────────────────────────────
    urls = recon_data.get("urls", [])
    forms = recon_data.get("forms", [])
    disabled_engines = config.get("disabled_engines", set())
    if "scan_budget" not in disabled_engines and container:
        budget_engine = container.scan_budget_engine if hasattr(container, 'scan_budget_engine') else None
        if budget_engine:
            scores = budget_engine.compute_scores(urls)
            sorted_urls = budget_engine.sorted_urls()
            top_n = scores[:10]
            log("\n[*] Top 10 scored endpoints (budget-aware):", Colors.BOLD)
            for rank, s in enumerate(top_n, 1):
                log(f"    {rank:>2}. [{s.score:>3}] budget={s.allocated_budget} {s.url}", Colors.CYAN)
        else:
            scored = [(compute_endpoint_score(u, forms, recon_data), u) for u in urls]
            scored.sort(key=lambda x: -x[0])
            sorted_urls = [u for _, u in scored]
            top_n = scored[:10]
            log("\n[*] Top 10 scored endpoints:", Colors.BOLD)
            for rank, (score, url) in enumerate(top_n, 1):
                log(f"    {rank:>2}. [{score:>3}] {url}", Colors.CYAN)
    else:
        scored = [(compute_endpoint_score(u, forms, recon_data), u) for u in urls]
        scored.sort(key=lambda x: -x[0])
        sorted_urls = [u for _, u in scored]
        top_n = scored[:10]
        log("\n[*] Top 10 scored endpoints:", Colors.BOLD)
        for rank, (score, url) in enumerate(top_n, 1):
            log(f"    {rank:>2}. [{score:>3}] {url}", Colors.CYAN)

    # ── Step 4: Per-URL intelligent module selection ─────────────────────
    per_url_modules = {k: v for k, v in module_map.items() if k not in TARGET_LEVEL}

    # Resume support: load completed URLs + dedup state from scan state
    resume_file = os.path.join(config.get("output_dir", "reports"), ".scan_state.json")
    completed_urls: set[str] = set()
    saved_findings: list[dict] = []
    if config.get("resume"):
        try:
            with open(resume_file, "r") as f:
                state = json.load(f)
            completed_urls = set(state.get("completed_urls", []))
            saved_findings = state.get("findings", [])
            # Restore dedup state if findings were saved
            if saved_findings and hasattr(scanner, 'dedup'):
                scanner.dedup = DeduplicationEngine.from_dict(
                    {f["fingerprint"]: f for f in saved_findings}
                )
                log(f"[*] Resume mode: {len(completed_urls)} URLs skipped, {len(saved_findings)} previous findings restored", Colors.CYAN)
            else:
                log(f"[*] Resume mode: {len(completed_urls)} URLs already scanned, skipping", Colors.CYAN)
        except (FileNotFoundError, json.JSONDecodeError):
            log("[*] No scan state found, starting fresh", Colors.CYAN)

    with ScanProgress(len(sorted_urls), config, "Scanning URLs") as prog:
        status = config.setdefault("status", {})
        status["total_urls"] = len(sorted_urls)
        status["phase"] = "scanning"
        for idx, url in enumerate(sorted_urls):
            status["urls_scanned"] = idx + 1
            status["current_url"] = url

            # Periodic status print (every 25 URLs)
            if config.get("status_print", False) and idx > 0 and idx % 25 == 0:
                from modules.utils import log as _log
                _log(f"[STATUS] {idx}/{len(sorted_urls)} URLs scanned, "
                     f"{len(all_findings_local)} findings so far", Colors.CYAN)

            # Periodic session health check (every 25 URLs)
            if idx > 0 and idx % 25 == 0:
                try:
                    from modules.utils import check_session_health
                    check_session_health(scanner.session, config, log)
                except Exception as e:
                    log(f"[!] Session health check failed: {e}", Colors.YELLOW,
                        verbose_only=True, verbose=config.get("verbose", False))

            if url in completed_urls:
                prog.advance()
                continue

            applicable = classify_endpoint(url, forms, recon_data)
            # Respect --modules filter
            if not run_all:
                applicable &= set(config["modules"])
            # Remove disabled modules
            applicable -= disabled_modules
            # Keep only modules available in the per-URL map
            applicable &= per_url_modules.keys()

            if not applicable:
                completed_urls.add(url)
                prog.advance(url, len(all_findings_local))
                continue

            if config.get("verbose", False):
                log(f"[*] {url} → {len(applicable)} modules selected: {sorted(applicable)}", Colors.YELLOW)

            for mod_name in applicable:
                try:
                    mod_fn = per_url_modules[mod_name]
                    mod_fn(target_urls=[url])  # findings written via self._add() to scanner.dedup
                except Exception as e:
                    log(f"  [!] {mod_name} error on {url}: {e}", Colors.RED, verbose_only=True, verbose=config.get("verbose", False))

            completed_urls.add(url)
            # Persist scan state after each URL
            try:
                os.makedirs(os.path.dirname(resume_file), exist_ok=True)
                state = {
                    "completed_urls": list(completed_urls),
                    "target": config.get("target"),
                    "findings": list(scanner.dedup.to_dict().values()) if hasattr(scanner, 'dedup') else [],
                }
                with open(resume_file, "w") as f:
                    json.dump(state, f)
            except Exception as e:
                log(f"[!] Scan state save failed: {e}", Colors.YELLOW,
                    verbose_only=True, verbose=config.get("verbose", False))

            prog.advance(url, len(all_findings_local))

    # ── Step 5: Post-scan triage pipeline ───────────────────────────────
    # NOTE: _run_reverification_loop() is deprecated — VerificationEngine handles all verification.
    updated = scanner._get_findings()

    log("[*] Running verification engine...", Colors.CYAN)

    log("[*] Running chain analysis...", Colors.CYAN)
    updated = VulnScanner.chain_analysis(updated)
    if container and hasattr(container, 'attack_chain_engine') and "attack_chains" not in disabled_engines:
        try:
            ace = container.attack_chain_engine
            asset_graph = config.get("asset_graph")
            chains = ace.analyze(updated, rdc_noise=config.get("rdc_noise", False), asset_graph=asset_graph)
            if chains:
                from engines.attack_chain import AttackChainEngine
                updated = AttackChainEngine.annotate_findings(updated, chains)
                log(f"[+] Attack chain engine: {len(chains)} chain(s) identified", Colors.GREEN)
                for c in chains:
                    log(f"    Chain: {c.description} (confidence: {c.overall_confidence:.0f})", Colors.CYAN)
        except Exception as e:
            log(f"[!] Attack chain engine error: {e}", Colors.YELLOW)

    log("[*] Checking self-halting conditions...", Colors.CYAN)
    updated = VulnScanner.check_self_halt(updated)

    log("[*] Enriching findings with engine evidence...", Colors.CYAN)
    evidence_engine = getattr(container, 'evidence_engine', None) if container else None
    enriched: list[Finding] = []
    for f in updated:
        obj = f
        if evidence_engine is not None:
            fp = obj.fingerprint or obj.get("fingerprint", "")
            if fp:
                linked = evidence_engine.get_evidence(fp)
                if linked:
                    obj_evidence = obj.evidence if isinstance(obj.evidence, list) else []
                    existing_ids = {id(e) for e in obj_evidence}
                    for ev in linked:
                        if id(ev) not in existing_ids:
                            obj_evidence.append(ev)
                    obj.evidence = obj_evidence
        enriched.append(obj)

    # ── Semantic response classification (auto PII/credential detection) ──
    if "semantic_analyzer" not in disabled_engines and container and hasattr(container, 'semantic_analyzer'):
        try:
            sa = container.semantic_analyzer
            for obj in enriched:
                excerpt = obj.get("response_excerpt", "") or getattr(obj, "response_excerpt", "")
                if excerpt and len(excerpt) > 50:
                    result = sa.classify_response(excerpt, url=obj.url)
                    if result and result.matched_patterns:
                        object.__setattr__(obj, "_semantic_classification", result)
                        leak_types = {p["category"] for p in result.matched_patterns}
                        object.__setattr__(obj, "_data_leak_categories", list(leak_types))
                        log(f"  [DataLeak] {obj.url}: {', '.join(sorted(leak_types))}",
                            Colors.YELLOW, verbose_only=True, verbose=config.get("verbose", False))
        except Exception as e:
            log(f"[!] Semantic classification failed: {e}", Colors.YELLOW,
                verbose_only=True, verbose=config.get("verbose", False))

    # ── Object Harvesting (extract IDs/emails/roles from responses) ─────
    if container and hasattr(container, 'object_harvester'):
        try:
            harvester = container.object_harvester
            harvest_count = 0
            for obj in enriched:
                excerpt = obj.get("response_excerpt", "") or getattr(obj, "response_excerpt", "")
                if excerpt and len(excerpt) > 50:
                    harvested = harvester.harvest(url=obj.url, response_text=excerpt)
                    harvest_count += len(harvested)
            if harvest_count:
                log(f"[+] Object harvester: {harvest_count} objects extracted across {len(enriched)} findings",
                    Colors.GREEN)
            # Log DiscoveryStore stats
            if hasattr(container, 'discovery_store'):
                ds_stats = container.discovery_store.get_stats()
                if ds_stats["total_records"]:
                    log(f"[*] Discovery store: {ds_stats['total_records']} records in "
                        f"{ds_stats['num_categories']} categories",
                        Colors.CYAN, verbose_only=True, verbose=config.get("verbose", False))
        except Exception as e:
            log(f"[!] Object harvesting failed: {e}", Colors.YELLOW,
                verbose_only=True, verbose=config.get("verbose", False))

    # ── Discovery Artifact Findings (consume unused discovery signals) ─────────
    if container and hasattr(container, 'discovery_store'):
        try:
            ds = container.discovery_store
            seen_artifact_ips: set[str] = set()
            for rec in ds.get_by_category("private_ip"):
                ip_val = rec.get("value", "")
                src_url = rec.get("source_url", "") or config.get("target", "")
                if ip_val and ip_val not in seen_artifact_ips:
                    seen_artifact_ips.add(ip_val)
                    ip_finding = Finding(
                        vuln_type="Internal IP Disclosure",
                        url=src_url,
                        severity="medium",
                        details=f"Internal/private IP address disclosed: {ip_val}",
                        evidence=f"Source: {src_url} — IP: {ip_val}",
                        verification_stage="detected",
                        confidence_score=40,
                        response_excerpt=f"Private IP found: {ip_val}",
                        reproduction_steps=[
                            f"Request the URL {src_url}",
                            "Observe the response contains a private/internal IP address",
                            f"Private IP: {ip_val}",
                        ],
                    )
                    ip_finding.finding_state = FindingState.from_verification_stage("detected").value
                    ip_finding.evidence_strength = "moderate"
                    ip_finding.false_positive_risk = "medium"
                    ip_evidence = ResponseExcerptEvidence(
                        excerpt=f"Private IP found: {ip_val}",
                        context=f"Source URL: {src_url}",
                        description=f"Internal IP {ip_val} disclosed in response from {src_url}",
                    )
                    ip_finding.evidence.append(ip_evidence)
                    if evidence_engine is not None:
                        evidence_engine.link_to_finding(ip_evidence, ip_finding.fingerprint)
                    enriched.append(ip_finding)
                    log(f"  [Disclosure] Internal IP: {ip_val} @ {src_url}",
                        Colors.YELLOW, verbose_only=True, verbose=config.get("verbose", False))

            seen_artifact_keys: set[str] = set()
            for rec in ds.get_by_category("api_key"):
                key_val = rec.get("value", "")
                src_url = rec.get("source_url", "") or config.get("target", "")
                if key_val and key_val not in seen_artifact_keys:
                    seen_artifact_keys.add(key_val)
                    key_finding = Finding(
                        vuln_type="Exposed API Key",
                        url=src_url,
                        severity="high",
                        details=f"API key or secret exposed in response body: {key_val[:20]}...",
                        evidence=f"Source: {src_url} — Key snippet: {key_val[:30]}...",
                        verification_stage="detected",
                        confidence_score=40,
                        response_excerpt=f"API key pattern found: {key_val[:40]}",
                        reproduction_steps=[
                            f"Request the URL {src_url}",
                            "Inspect the response for API key / secret patterns",
                            f"Key found (truncated): {key_val[:30]}...",
                        ],
                    )
                    key_finding.finding_state = FindingState.from_verification_stage("detected").value
                    key_finding.evidence_strength = "moderate"
                    key_finding.false_positive_risk = "medium"
                    key_evidence = ResponseExcerptEvidence(
                        excerpt=f"API key pattern found: {key_val[:80]}",
                        context=f"Source URL: {src_url}",
                        description=f"API key/secret pattern disclosed in response from {src_url}",
                    )
                    key_finding.evidence.append(key_evidence)
                    if evidence_engine is not None:
                        evidence_engine.link_to_finding(key_evidence, key_finding.fingerprint)
                    enriched.append(key_finding)
                    log(f"  [Disclosure] API Key: {key_val[:20]}... @ {src_url}",
                        Colors.YELLOW, verbose_only=True, verbose=config.get("verbose", False))

            n_artifact = len(seen_artifact_ips) + len(seen_artifact_keys)
            if n_artifact:
                log(f"[+] Artifact findings: {n_artifact} disclosure(s) from discovery store",
                    Colors.GREEN, verbose_only=True, verbose=config.get("verbose", False))
        except Exception as e:
            log(f"[!] Discovery artifact findings failed: {e}", Colors.YELLOW,
                verbose_only=True, verbose=config.get("verbose", False))

    # ── Ownership Discovery (proactive ownership inference from all signals) ──
    if container and hasattr(container, 'discovery_store'):
        try:
            from engines.ownership_discovery import OwnershipDiscoveryEngine
            ode = OwnershipDiscoveryEngine(container.discovery_store)
            # Build known_ids from store for URL pattern matching
            known_ids: dict[str, list[str]] = {}
            for cat in ("numeric_id", "uuid", "email"):
                for rec in container.discovery_store.get_by_category(cat):
                    known_ids.setdefault(cat, []).append(rec["value"])

            # Build response_bodies from findings
            response_bodies: dict[str, str] = {}
            for obj in enriched:
                excerpt = obj.get("response_excerpt", "") or getattr(obj, "response_excerpt", "") or ""
                if excerpt and len(excerpt) > 50:
                    response_bodies[obj.url] = excerpt[:5000]

            discovered = ode.discover_all(
                urls=list(known_ids.get("numeric_id", [])) if known_ids else None,
                response_bodies=response_bodies or None,
                known_ids=known_ids or None,
            )
            if discovered:
                log(f"[+] Ownership discovery: {len(discovered)} relationships inferred",
                    Colors.GREEN, verbose_only=True, verbose=config.get("verbose", False))
        except Exception as e:
            log(f"[!] Ownership discovery failed: {e}", Colors.YELLOW,
                verbose_only=True, verbose=config.get("verbose", False))

    # ── Business Logic Discovery (workflow identification + abuse candidate generation) ──
    if container and hasattr(container, 'discovery_store'):
        try:
            from engines.business_discovery import BusinessLogicDiscoveryEngine
            blde = BusinessLogicDiscoveryEngine(
                discovery_store=container.discovery_store,
                relationship_graph=getattr(container, 'relationship_graph', None),
            )
            blde_urls = recon_data.get("urls", [])
            blde_forms = recon_data.get("forms", [])
            blde_role_sessions = config.get("_role_sessions", {})
            candidates = blde.run(
                urls=blde_urls,
                forms=blde_forms,
                role_sessions=blde_role_sessions if len(blde_role_sessions) >= 2 else None,
                recon_data=recon_data,
            )
            config["_business_logic_candidates"] = candidates
            if candidates:
                log(f"[+] Business logic discovery: {len(candidates)} abuse candidate(s) "
                    f"across {len({c.workflow.name for c in candidates})} workflows",
                    Colors.GREEN)
                top_candidates = sorted(candidates, key=lambda c: -c.yield_rank)[:5]
                for c in top_candidates:
                    log(f"    [{c.yield_rank:.2f}] {c.workflow.category.value}: "
                        f"{c.abuse_url or c.workflow.name} "
                        f"→ {', '.join(c.suggested_strategies[:2])}",
                        Colors.CYAN, verbose_only=True, verbose=config.get("verbose", False))
            else:
                config["_business_logic_candidates"] = []
                log("[+] Business logic discovery — no abuse candidates found",
                    Colors.GREEN, verbose_only=True, verbose=config.get("verbose", False))
        except Exception as e:
            log(f"[!] Business logic discovery failed: {e}", Colors.YELLOW,
                verbose_only=True, verbose=config.get("verbose", False))

    # ── Business Logic Candidate Exploitation (route candidates to BL scanner testers) ──
    bl_candidates = config.get("_business_logic_candidates", [])
    if bl_candidates and not config.get("passive", False):
        try:
            from scanners.business_logic import (
                BusinessLogicScanner, RaceConditionTester, PriceManipulationTester,
                FlowBypassTester,
            )
            from models.business_flow import AbusePattern
            bl_candidate_session = getattr(scanner, 'session', None)
            if bl_candidate_session:
                bl_for_candidates = BusinessLogicScanner(
                    config, session=bl_candidate_session, recon=recon_data)
                race_tester = RaceConditionTester(bl_candidate_session, timeout=10)
                price_tester = PriceManipulationTester(bl_candidate_session, timeout=10)
                # Build a form-lookup map for resolving abuse URLs to form data
                forms_by_action: dict[str, dict] = {}
                for form in recon_data.get("forms", []):
                    action = form.get("action", "")
                    if action:
                        from urllib.parse import urljoin
                        base = (recon_data.get("urls") or [""])[0]
                        resolved = urljoin(base, action) if not action.startswith("http") else action
                        forms_by_action[resolved] = form

                candidate_findings: list[dict] = []
                for c in bl_candidates[:10]:  # Top 10 candidates
                    abuse_url = c.abuse_url or (c.workflow.source_urls or [""])[0]
                    abuse_param = c.abuse_parameter or ""
                    patterns = c.risk_model.likely_patterns if c.risk_model else []

                    for pattern in patterns:
                        if pattern in (AbusePattern.RACE_CONDITION,):
                            # Look up form data for race condition testing
                            form_data = None
                            for action_url, form in forms_by_action.items():
                                if action_url == abuse_url or abuse_url.endswith(action_url):
                                    form_data = {f.get("name", ""): f.get("value", "")
                                                 for f in form.get("fields", []) if f.get("name")}
                                    break
                            race_result = race_tester.test_race_condition(
                                abuse_url, data=form_data, session=bl_candidate_session)
                            f = BusinessLogicScanner._race_to_finding(race_result)
                            if f:
                                f["_from_candidate"] = c.workflow.name
                                candidate_findings.append(f)

                        elif pattern in (AbusePattern.PRICE_OVERRIDE,):
                            if abuse_param:
                                found = price_tester.test_price_override(abuse_url, abuse_param, bl_candidate_session)
                            else:
                                # Try all price fields
                                for pf in PriceManipulationTester.PRICE_FIELDS:
                                    if price_tester.test_price_override(abuse_url, pf, bl_candidate_session):
                                        found = True
                                        break
                                else:
                                    found = False
                            if found:
                                f = BusinessLogicScanner._price_finding(
                                    "Price Override", abuse_url, {abuse_param or "price": "0"})
                                if f:
                                    f["_from_candidate"] = c.workflow.name
                                    candidate_findings.append(f)

                        elif pattern in (AbusePattern.NEGATIVE_QUANTITY,):
                            for action_url, form in forms_by_action.items():
                                if action_url == abuse_url or abuse_url.endswith(action_url):
                                    form_data = {f.get("name", ""): f.get("value", "")
                                                 for f in form.get("fields", []) if f.get("name")}
                                    if form_data and price_tester.test_negative_quantity(abuse_url, form_data, bl_candidate_session):
                                        f = BusinessLogicScanner._price_finding(
                                            "Negative Quantity", abuse_url, form_data)
                                        if f:
                                            f["_from_candidate"] = c.workflow.name
                                            candidate_findings.append(f)
                                    break

                        elif pattern in (AbusePattern.COUPON_STACKING,):
                            for action_url, form in forms_by_action.items():
                                if action_url == abuse_url or abuse_url.endswith(action_url):
                                    form_data = {f.get("name", ""): f.get("value", "")
                                                 for f in form.get("fields", []) if f.get("name")}
                                    if form_data and price_tester.test_coupon_stacking(abuse_url, form_data, bl_candidate_session):
                                        f = BusinessLogicScanner._price_finding(
                                            "Coupon Stacking", abuse_url, form_data)
                                        if f:
                                            f["_from_candidate"] = c.workflow.name
                                            candidate_findings.append(f)
                                    break

                if candidate_findings:
                    log(f"[!] {len(candidate_findings)} finding(s) from CANDIDATE_EXPLOITATION",
                        Colors.RED)
                    with lock:
                        all_findings_local.extend(candidate_findings)

                    # ── Candidate yield feedback (update yield_rank based on exploitation outcomes) ──
                    if container and hasattr(container, 'discovery_store'):
                        try:
                            store = container.discovery_store
                            for f in candidate_findings:
                                wf_name = f.get("_from_candidate")
                                if not wf_name:
                                    continue
                                for c in bl_candidates:
                                    if c.workflow.name != wf_name:
                                        continue
                                    stage = f.get("verification_stage", "detected")
                                    if stage in ("verified", "exploitable"):
                                        boost = 0.3
                                    elif stage == "validated":
                                        boost = 0.2
                                    else:
                                        boost = 0.1
                                    c.priority_score = min(1.0, c.priority_score + boost)
                                    break
                            for c in bl_candidates:
                                store.record("candidate_yield", c.workflow.name,
                                             source_url=c.abuse_url or "",
                                             extra={"yield_rank": round(c.yield_rank, 3),
                                                    "priority_score": round(c.priority_score, 3),
                                                    "risk": round(c.risk_model.overall_risk, 3)})
                        except Exception as e:
                            log(f"[!] Candidate yield feedback failed: {e}", Colors.YELLOW,
                                verbose_only=True, verbose=config.get("verbose", False))
        except Exception as e:
            log(f"[!] Candidate exploitation failed: {e}", Colors.YELLOW,
                verbose_only=True, verbose=config.get("verbose", False))

    # ── GQL Authorization Intelligence (relationship inference + ownership discovery + auth mapping) ──
    if container and hasattr(container, 'discovery_store'):
        try:
            store = container.discovery_store
            gql_types = store.get_by_category("gql_type")
            if gql_types:
                # Phase 1: Infer domain relationships from GQL schema types/fields
                from engines.gql_relationships import GraphQLRelationshipEngine
                rel_engine = GraphQLRelationshipEngine(store)
                rel_stats = rel_engine.run_all()
                rel_engine.store_relationships(store)
                n_classified = rel_stats.get("classified_relationships", 0)

                # Phase 2: Cross-reference with recon data for ownership discovery
                from engines.gql_ownership import GraphQLOwnershipDiscovery
                own_engine = GraphQLOwnershipDiscovery(store, rel_engine)
                own_urls = recon_data.get("urls", []) if isinstance(recon_data, dict) else []
                own_stats = own_engine.run_all(recon_data=recon_data, urls=own_urls, store=store)
                own_engine.store_hints(store)
                n_hints = own_stats.get("ownership_hints", 0)

                # Phase 3: Generate authorization investigation plans
                from engines.gql_auth_mapper import GraphQLAuthorizationMapper
                mapper = GraphQLAuthorizationMapper(store, rel_engine, own_engine)
                map_stats = mapper.run_all(store)
                mapper.store_plans(store)
                n_plans = map_stats.get("total_plans", 0)

                if n_classified or n_hints or n_plans:
                    log(f"[+] GQL auth intelligence: {n_classified} relationships, "
                        f"{n_hints} ownership hints, {n_plans} auth plans",
                        Colors.GREEN, verbose_only=True, verbose=config.get("verbose", False))
        except Exception as e:
            log(f"[!] GQL auth intelligence failed: {e}", Colors.YELLOW,
                verbose_only=True, verbose=config.get("verbose", False))

    # ── GQL Auth Plan Execution ──────────────────────────────────────────
    if container and hasattr(container, 'discovery_store'):
        try:
            store = container.discovery_store
            plan_records = store.get_by_category("gql_auth_plan")
            if plan_records:
                from engines.gql_auth_tester import GraphQLAuthTester
                role_sessions = config.get("_role_sessions", {})
                if len(role_sessions) >= 2:
                    tester = GraphQLAuthTester(config, role_sessions=role_sessions)
                    gql_findings = tester.execute_from_store(store=store)
                    if gql_findings:
                        log(f"[!] GQL auth tester: {len(gql_findings)} finding(s)", Colors.RED)
                        with lock:
                            all_findings.extend(gql_findings)
        except Exception as e:
            log(f"[!] GQL auth tester failed: {e}", Colors.YELLOW,
                verbose_only=True, verbose=config.get("verbose", False))

    log("[*] Validating evidence completeness...", Colors.CYAN)
    evidence_completeness = getattr(container, 'evidence_completeness', None) if container else None
    if evidence_completeness is None:
        from engines.evidence_validator import EvidenceCompletenessValidator as ECV
        evidence_completeness = ECV
    evidence_validated = []
    for obj in enriched:
        evidence_validated.append(evidence_completeness.validate(obj))
    updated = evidence_validated

    # ── Ownership Validation ──────────────────────────────────────────────
    if "ownership" not in disabled_engines and container:
        try:
            log("[*] Validating ownership...", Colors.CYAN)
            ownership_validator = container.ownership_validator
            for obj in updated:
                ownership_ev = ownership_validator.validate(obj)
                if ownership_ev:
                    obj_evidence = obj.evidence if isinstance(obj.evidence, list) else []
                    obj_evidence.append(ownership_ev)
                    obj.evidence = obj_evidence
                    if evidence_engine is not None:
                        fp = obj.fingerprint or ""
                        if fp:
                            evidence_engine.link_to_finding(ownership_ev, fp)
            log(f"[+] Ownership validated for {len(updated)} findings", Colors.GREEN)
        except Exception as e:
            log(f"[!] Ownership validation failed: {e}", Colors.YELLOW)

    # ── Impact Validation ────────────────────────────────────────────────
    if "impact" not in disabled_engines and container:
        try:
            log("[*] Validating impact...", Colors.CYAN)
            impact_validator = container.impact_validator
            for obj in updated:
                impact_ev = impact_validator.validate(obj)
                if impact_ev:
                    obj_evidence = obj.evidence if isinstance(obj.evidence, list) else []
                    obj_evidence.append(impact_ev)
                    obj.evidence = obj_evidence
                    if evidence_engine is not None:
                        fp = obj.fingerprint or ""
                        if fp:
                            evidence_engine.link_to_finding(impact_ev, fp)
            log(f"[+] Impact validated for {len(updated)} findings", Colors.GREEN)
        except Exception as e:
            log(f"[!] Impact validation failed: {e}", Colors.YELLOW)

    # ── Evidence Bundle ──────────────────────────────────────────────────
    log("[*] Building evidence bundles...", Colors.CYAN)
    from models.evidence_bundle import EvidenceBundle
    bundle_count = 0
    for obj in updated:
        bundle = EvidenceBundle.from_finding(obj)
        object.__setattr__(obj, "_evidence_bundle", bundle)
        object.__setattr__(obj, "submission_ready", bundle.submission_ready)
        object.__setattr__(obj, "evidence_bundle_strength", bundle.overall_strength)
        object.__setattr__(obj, "evidence_bundle_completeness", bundle.completeness_score)
        object.__setattr__(obj, "_pipeline_validation_complete", True)
        bundle_count += 1
    log(f"[+] Evidence bundles built for {bundle_count} findings", Colors.GREEN)

    # ── Validation Consensus (now affects confidence/priority/readiness) ──
    consensus_results: dict[str, Any] = {}
    if "consensus" not in disabled_engines and container:
        try:
            log("[*] Computing validation consensus...", Colors.CYAN)
            consensus_engine = container.validation_consensus_engine
            consensus_for = 0
            for obj in updated:
                result = consensus_engine.evaluate(obj)
                object.__setattr__(obj, "consensus_result", result.to_dict())
                consensus_results[obj.fingerprint] = result
                if result.consensus_level in ("strong", "moderate"):
                    consensus_for += 1
            log(f"[+] Consensus: {consensus_for}/{len(updated)} findings meet threshold",
                Colors.GREEN)
        except Exception as e:
            log(f"[!] Validation consensus failed: {e}", Colors.YELLOW)

    # ── Unified Confidence Scoring (Initiative 2 + 7) ────────────────────
    if "confidence" not in disabled_engines and container:
        try:
            log("[*] Computing unified confidence scores...", Colors.CYAN)
            confidence_engine = container.confidence_engine
            for obj in updated:
                consensus = consensus_results.get(obj.fingerprint)
                result = confidence_engine.evaluate(obj, consensus_result=consensus)
                confidence_engine.apply(obj, result)
            log(f"[+] Confidence scored for {len(updated)} findings", Colors.GREEN)
        except Exception as e:
            log(f"[!] Confidence scoring failed: {e}", Colors.YELLOW)

    # ── Outcome Recording (record every finding for future feedback loop) ──
    if config.get("record_outcome", False) and container and hasattr(container, 'outcome_feedback_engine'):
        try:
            ofe = container.outcome_feedback_engine
            recorded = 0
            for obj in updated:
                fp = obj.fingerprint or ""
                if fp:
                    cs = obj.confidence_score or 0
                    ofe.record_outcome(
                        finding_fingerprint=fp,
                        outcome="detected",
                        notes=f"{obj.vuln_type} @ {obj.url} | confidence={cs}",
                    )
                    recorded += 1
            if recorded:
                log(f"[*] Recorded {recorded} outcome(s) to outcomes.jsonl", Colors.CYAN,
                    verbose_only=True, verbose=config.get("verbose", False))
        except Exception as e:
            log(f"[!] Outcome recording failed: {e}", Colors.YELLOW,
                verbose_only=True, verbose=config.get("verbose", False))

    # ── Impact Escalation Analysis (Initiative 4) ────────────────────────
    if "impact_escalation" not in disabled_engines and container:
        try:
            log("[*] Analyzing impact escalation paths...", Colors.CYAN)
            escalation = container.impact_escalation_analyzer
            asset_graph = config.get("asset_graph")
            for obj in updated:
                er = escalation.analyze(obj, asset_graph=asset_graph)
                object.__setattr__(obj, "_escalation_result", er.to_dict())
                if er.escalation_paths:
                    best_path = max(er.escalation_paths, key=lambda p: p.confidence_gain)
                    object.__setattr__(obj, "_best_escalation_path", best_path.to_dict())
            log(f"[+] Impact escalation analyzed for {len(updated)} findings", Colors.GREEN)
        except Exception as e:
            log(f"[!] Impact escalation analysis failed: {e}", Colors.YELLOW)

    # ── Submission Readiness (consensus-aware) ─────────────────────────
    if "submission_readiness" not in disabled_engines and container:
        try:
            log("[*] Assessing submission readiness (consensus-aware)...", Colors.CYAN)
            readiness = container.submission_readiness_engine
            readiness.assess_all(updated)
            log(f"[+] Submission readiness assessed for {len(updated)} findings", Colors.GREEN)
        except Exception as e:
            log(f"[!] Submission readiness assessment failed: {e}", Colors.YELLOW)

    # ── Payload Intelligence stats (auto-printed) ─────────────────────────
    if container and hasattr(container, 'payload_intelligence'):
        try:
            stats = container.payload_intelligence.get_stats()
            if stats and stats.get("total_records", 0) > 0:
                log(f"[*] Payload intelligence: {stats['total_records']} records, "
                    f"{stats.get('unique_payloads', 0)} unique payloads across "
                    f"{len(stats.get('by_type', {}))} vuln types", Colors.CYAN)
        except Exception as e:
            log(f"[!] Payload intelligence stats failed: {e}", Colors.YELLOW,
                verbose_only=True, verbose=config.get("verbose", False))

    # ── Outcome Feedback (historical outcomes check + confidence calibration) ──
    if container and hasattr(container, 'outcome_feedback_engine'):
        try:
            ofe = container.outcome_feedback_engine
            stats = ofe.get_stats()
            if stats.get("total_records", 0) > 0:
                log(f"[*] Outcome feedback: {stats['total_records']} historical outcome(s), "
                    f"${stats.get('total_bounty', 0):.2f} total bounty", Colors.CYAN)
                # Compute per-vuln-type positive-outcome rate
                vuln_stats: dict[str, dict[str, int]] = {}
                all_records = ofe.get_all()
                for recs in all_records.values():
                    for r in recs:
                        vt = r.notes.split(" @ ")[0] if " @ " in r.notes else ""
                        if vt:
                            vuln_stats.setdefault(vt, {"total": 0, "positive": 0})
                            vuln_stats[vt]["total"] += 1
                            if r.outcome in ("accepted", "bounty_paid"):
                                vuln_stats[vt]["positive"] += 1

                for obj in updated:
                    fp = obj.fingerprint or ""
                    if fp and ofe.has_positive_outcome(fp):
                        object.__setattr__(obj, "_historical_outcome", "positive")
                        log(f"    {obj.vuln_type} @ {obj.url}: previously accepted/bounty paid",
                            Colors.GREEN, verbose_only=True, verbose=config.get("verbose", False))
                    # Confidence calibration: boost findings whose vuln_type has high positive rate
                    vt = (obj.vuln_type or "").lower()
                    if vt in vuln_stats:
                        vs = vuln_stats[vt]
                        rate = vs["positive"] / max(vs["total"], 1)
                        if rate >= 0.5 and vt in vuln_stats:
                            multiplier = 1.0 + (rate * 0.15)
                            new_score = min(100, int((obj.confidence_score or 25) * multiplier))
                            if new_score > (obj.confidence_score or 0):
                                old = obj.confidence_score or 25
                                object.__setattr__(obj, "confidence_score", new_score)
                                from models.finding import ConfidenceLevel
                                object.__setattr__(obj, "confidence_label",
                                    ConfidenceLevel.from_score(new_score).value)
                                reasons = list(getattr(obj, "confidence_reasons", []) or [])
                                delta = new_score - old
                                reason = f"+{delta} via outcome_calibration: {vt} has {rate:.0%} positive-outcome rate"
                                if reason not in reasons:
                                    reasons.append(reason)
                                    object.__setattr__(obj, "confidence_reasons", reasons)
        except Exception as e:
            log(f"[!] Outcome feedback check failed: {e}", Colors.YELLOW,
                verbose_only=True, verbose=config.get("verbose", False))

    # ── Priority scoring (consensus-aware) ───────────────────────────────
    updated = prioritize_findings(updated)

    # Merge TARGET_LEVEL findings (ApiScanner/IdorScanner don't use self._add())
    # by fingerprint to avoid duplicating VulnScanner entries already in dedup.
    seen_fingerprints = {f.fingerprint for f in updated if f.fingerprint}
    seen_urls_types: set[tuple] = {
        (f.url, f.vuln_type) for f in updated
    }
    for f in all_findings_local:
        fp = f.fingerprint
        if fp:
            if fp not in seen_fingerprints:
                seen_fingerprints.add(fp)
                updated.append(f)
        else:
            key = (f.url, f.vuln_type)
            if key not in seen_urls_types:
                seen_urls_types.add(key)
                updated.append(f)

    with lock:
        all_findings.clear()
        all_findings.extend(updated)

    # ── CrossScan persistence: record new scan + findings ───────────────
    cross_scan_id_val = None
    if container and hasattr(container, 'cross_scan_database'):
        try:
            csdb = container.cross_scan_database
            if csdb is not None:
                import uuid as _uuid
                cross_scan_id_val = str(_uuid.uuid4())
                target_url = config.get("target", "")
                csdb.start_scan(cross_scan_id_val, target_url, config)
                for f in all_findings:
                    fp = getattr(f, "fingerprint", None) or ""
                    if fp:
                        history = csdb.get_scan_history(fp)
                        if history:
                            object.__setattr__(f, "_cross_scan_history", history)
                        if csdb.is_fixed(fp):
                            object.__setattr__(f, "_was_fixed", True)
                regressed = csdb.record_findings(all_findings, cross_scan_id_val)
                if regressed:
                    log(f"[!] CrossScan: {len(regressed)} regression(s) detected",
                        Colors.YELLOW)
        except Exception as e:
            log(f"[!] CrossScanDatabase failed: {e}", Colors.YELLOW,
                verbose_only=True, verbose=config.get("verbose", False))

    # ── Evidence orphan detection ──
    if evidence_engine is not None:
        orphaned = evidence_engine.get_orphaned_evidence()
        log(f"[*] Evidence engine: {len(orphaned)} orphaned evidence items (not linked to any finding)",
            Colors.CYAN, verbose_only=True, verbose=config.get("verbose", False))

    if oob_poller:
        cbs = oob_poller.callback_count
        oob_poller.stop()
        reason = oob_poller.termination_reason or "stopped"
        log(f"[*] OOB background poller stopped: {reason} ({cbs} callback(s))", Colors.CYAN)

    # ── CrossScan: end scan ─────────────────────────────────────────────
    if cross_scan_id_val and container and hasattr(container, 'cross_scan_database'):
        try:
            csdb = container.cross_scan_database
            if csdb is not None:
                csdb.end_scan(cross_scan_id_val, len(all_findings))
        except Exception as e:
            log(f"[!] CrossScan end_scan failed: {e}", Colors.YELLOW,
                verbose_only=True, verbose=config.get("verbose", False))

    # ── Audit log cleanup ──────────────────────────────────────────────────
    auditor = config.pop("_audit_logger", None)
    if auditor is not None:
        try:
            report_path = auditor.save()
            if report_path:
                log(f"[+] Audit log saved: {report_path}", Colors.GREEN)
            auditor.close()
        except Exception as e:
            log(f"[!] Audit log save failed: {e}", Colors.YELLOW,
                verbose_only=True, verbose=config.get("verbose", False))
