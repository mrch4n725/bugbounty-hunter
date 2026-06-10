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
from models.finding import Finding
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


def run_scans(config, recon_data, recon, run_all, disabled_modules, all_findings, lock, container=None, capabilities=None):
    # ── TARGET_LEVEL: modules that run once per target, not per URL ──
    TARGET_LEVEL: set[str] = {
        "headers", "dirb", "exposed_files", "clickjacking",
        "subdomain_takeover", "graphql", "blind_xss", "api", "openapi",
        "http_methods", "authorization",
        "cors", "jwt", "cms",
        "rate_limiting",
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

    # ── Tech-Specific Scanner Registry (runs after target-level, before per-URL) ──
    if not run_all or "tech_specific" not in disabled_modules:
        try:
            log("[*] Running tech-specific framework probes...", Colors.CYAN)
            from scanners.tech_specific import TechSpecificScannerRegistry
            tech_registry = TechSpecificScannerRegistry()
            detected_frameworks = recon_data.get("technology", {})
            tech_findings = tech_registry.scan_all(
                base_urls=recon_data.get("urls", []),
                detected_frameworks=detected_frameworks,
                session=scanner.session,
            )
            if tech_findings:
                log(f"[!] {len(tech_findings)} finding(s) from TECH_SPECIFIC", Colors.RED)
                with lock:
                    all_findings_local.extend(tech_findings)
            else:
                log("[+] TECH_SPECIFIC — nothing found", Colors.GREEN)
        except Exception as e:
            log(f"[!] TECH_SPECIFIC error: {e}", Colors.YELLOW)

    # ── Business Logic Scanner ──────────────────────────────────────────────
    if not run_all or "business_logic" not in disabled_modules:
        try:
            log("[*] Running business logic scanner...", Colors.CYAN)
            from scanners.business_logic import BusinessLogicScanner
            bl_scanner = BusinessLogicScanner(config, session=scanner.session, recon=recon_data)
            bl_findings = bl_scanner.run_all(
                urls=recon_data.get("urls", []),
                forms=recon_data.get("forms", []),
            )
            if bl_findings:
                log(f"[!] {len(bl_findings)} finding(s) from BUSINESS_LOGIC", Colors.RED)
                with lock:
                    all_findings_local.extend(bl_findings)
            else:
                log("[+] BUSINESS_LOGIC — nothing found", Colors.GREEN)
        except Exception as e:
            log(f"[!] BUSINESS_LOGIC error: {e}", Colors.YELLOW)

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
        except Exception:
            pass

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
                except Exception:
                    pass

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
            except Exception:
                pass

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

    # ── GQL Authorization Intelligence (feed stored GQL types into discovery) ──
    if container and hasattr(container, 'discovery_store'):
        try:
            store = container.discovery_store
            gql_types = store.get_by_category("gql_type")
            if gql_types:
                from engines.gql_auth import GqlAuthorizationEngine
                gql_engine = GqlAuthorizationEngine(store)
                # Feed GQL-derived ownership hints back into DiscoveryStore
                for hint in gql_engine.build_ownership_hints():
                    store.record(
                        category="ownership_hint",
                        value=hint["value"],
                        source_url=hint["source_url"],
                        extra=hint["extra"],
                    )
                for rel in gql_engine.build_relationships():
                    store.record(
                        category="ownership_relationship",
                        value=rel["value"],
                        source_url=rel["source_url"],
                        extra=rel["extra"],
                    )
                gql_role_types = gql_engine.get_privilege_level_types()
                for rt in gql_role_types:
                    store.record("role", rt, source_url="gql_schema")
                n_ownership = len(gql_engine.get_ownership_fields())
                n_roles = len(gql_role_types)
                if n_ownership or n_roles:
                    log(f"[+] GQL auth intelligence: {n_ownership} ownership fields, "
                        f"{n_roles} privilege types consumed",
                        Colors.GREEN, verbose_only=True, verbose=config.get("verbose", False))
        except Exception as e:
            log(f"[!] GQL auth intelligence failed: {e}", Colors.YELLOW,
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
            consensus_engine = container.validation_consensus_engine.create_default()
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
        except Exception:
            pass

    # ── Outcome Feedback (historical outcomes check) ───────────────────────
    if container and hasattr(container, 'outcome_feedback_engine'):
        try:
            ofe = container.outcome_feedback_engine
            stats = ofe.get_stats()
            if stats.get("total_records", 0) > 0:
                log(f"[*] Outcome feedback: {stats['total_records']} historical outcome(s), "
                    f"${stats.get('total_bounty', 0):.2f} total bounty", Colors.CYAN)
                for obj in updated:
                    fp = obj.fingerprint or ""
                    if fp and ofe.has_positive_outcome(fp):
                        object.__setattr__(obj, "_historical_outcome", "positive")
                        log(f"    {obj.vuln_type} @ {obj.url}: previously accepted/bounty paid",
                            Colors.GREEN, verbose_only=True, verbose=config.get("verbose", False))
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

    # ── Audit log cleanup ──────────────────────────────────────────────────
    auditor = config.pop("_audit_logger", None)
    if auditor is not None:
        try:
            report_path = auditor.save()
            if report_path:
                log(f"[+] Audit log saved: {report_path}", Colors.GREEN)
            auditor.close()
        except Exception:
            pass
