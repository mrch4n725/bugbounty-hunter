#!/usr/bin/env python3
"""
BugBounty Hunter - Automated vulnerability scanner for bug bounty programs.
Usage: python main.py --target https://example.com [options]
"""

import argparse
import sys
import os
import threading
import yaml
from datetime import datetime
from typing import Any

from modules.recon import Recon
from modules.scanner import VulnScanner
from modules.api_scanner import ApiScanner
from modules.idor import IdorScanner
from modules.reporter import Reporter
from modules.js_intelligence import JSIntelligence
from modules.utils import banner, log, Colors, ScopeEnforcer, safe_get, same_domain, finding, make_session, classify_endpoint, compute_endpoint_score


def parse_args():
    parser = argparse.ArgumentParser(
        description="BugBounty Hunter - Automated vulnerability detector",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--config", "-C", help="Path to YAML configuration file")
    parser.add_argument("--target", "-t", help="Target URL (e.g. https://example.com)")
    parser.add_argument("--modules", "-m", nargs="+",
        choices=["recon", "xss", "sqli", "lfi", "ssrf", "xxe", "cmd_injection", "blind_xss", "open_redirect", "headers", "csrf", "dirb", "sensitive", "exposed_files", "clickjacking", "http_methods", "insecure_forms", "subdomain_takeover", "graphql", "idor", "js_secrets", "api", "rate_limiting", "all"],
        default=["all"])
    parser.add_argument("--output", "-o", default="reports")
    parser.add_argument("--format", "-f", choices=["json", "html", "txt", "markdown-report", "hackerone", "bugcrowd"], default="html")
    parser.add_argument("--threads", type=int, default=10)
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--cookies", "-c", default=None)
    parser.add_argument("--cookies-alt", default=None,
        help="Second account's session cookies for horizontal IDOR testing (e.g. 'session=xyz')")
    parser.add_argument("--headers", "-H", nargs="+", default=[])
    parser.add_argument("--auth", help="Basic auth credentials username:password")
    parser.add_argument("--proxy", help="Proxy URL for outgoing requests")
    parser.add_argument("--no-verify-ssl", action="store_false", dest="verify_ssl",
        help="Disable SSL certificate verification")
    parser.add_argument("--crawl-depth", type=int, default=2)
    parser.add_argument("--max-urls", type=int, default=200,
        help="Maximum number of URLs to discover during reconnaissance")
    parser.add_argument("--delay", type=float, default=0.0,
        help="Delay between requests in seconds")
    parser.add_argument("--oob-host", default=None,
        help="Out-of-band callback host for SSRF and SQLi OOB verification (e.g. Burp Collaborator or interactsh URL)")
    parser.add_argument("--wordlist", help="Optional directory fuzzing wordlist path")
    parser.add_argument("--disable-modules", nargs="+",
        choices=["recon", "xss", "sqli", "lfi", "ssrf", "xxe", "cmd_injection", "blind_xss", "open_redirect", "headers", "csrf", "dirb", "sensitive", "exposed_files", "clickjacking", "http_methods", "insecure_forms", "subdomain_takeover", "graphql", "idor", "js_secrets", "api", "rate_limiting"],
        default=[], help="Disable specific modules when scanning all or default modules")
    parser.add_argument("--module-param", action="append", default=[],
        help="Override module settings using module.key=value")
    parser.add_argument("--retries", type=int, default=3,
        help="HTTP retry attempts for transient failures")
    parser.add_argument("--autosave-interval", type=int, default=0,
        help="Autosave interim report every N seconds (0 = disabled)")
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("--passive", action="store_true")
    parser.add_argument("--headless", action="store_true",
        help="Use Playwright headless browser for JS-rendered crawling (network intercept, SPA route discovery)")
    parser.add_argument("--verify-only", "-V",
        help="Re-verify unconfirmed findings from a previous JSON report. Path to report file.")
    parser.add_argument("--triage-assist", action="store_true",
        help="Use OpenAI to enhance impact narrative in markdown reports (requires OPENAI_API_KEY env var)")
    parser.add_argument("--rps", type=float, default=5.0,
        help="Requests per second (default: 5). Halved on 429, restored after 20 OK.")
    parser.add_argument("--stealth", action="store_true",
        help="Stealth mode: rotate 20 User-Agent strings, random 0.5-2s delay, shuffle POST params.")
    parser.add_argument("--scope",
        help="Path to scope file (one domain/IP/CIDR per line). Out-of-scope URLs are rejected & logged.")
    parser.add_argument("--exclude-patterns", nargs="*", default=[],
        help="Regex patterns for URL exclusions (e.g. '/admin' '/logout')")
    parser.add_argument("--include-paths", nargs="*", default=[],
        help="Regex patterns for URL inclusion (e.g. '/api' '/graphql'). All others excluded.")
    return parser.parse_args()


def load_config_file(config_path: str) -> dict:
    """
    Load configuration from a YAML file.
    
    Args:
        config_path: Path to YAML configuration file
    
    Returns:
        Dictionary with configuration options
    """
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
            return config if config else {}
    except FileNotFoundError:
        log(f"[!] Config file not found: {config_path}", Colors.RED)
        sys.exit(1)
    except yaml.YAMLError as e:
        log(f"[!] Error parsing YAML config: {e}", Colors.RED)
        sys.exit(1)
    except Exception as e:
        log(f"[!] Error loading config file: {e}", Colors.RED)
        sys.exit(1)


def _apply_scalar_config(cli_args, config_file: dict) -> None:
    yaml_to_arg = {
        'target': 'target', 'output': 'output', 'format': 'format',
        'threads': 'threads', 'timeout': 'timeout', 'cookies': 'cookies',
        'cookies_alt': 'cookies_alt',
        'auth': 'auth', 'proxy': 'proxy', 'verify_ssl': 'verify_ssl',
        'crawl_depth': 'crawl_depth', 'max_urls': 'max_urls',
        'delay': 'delay', 'oob_host': 'oob_host', 'wordlist': 'wordlist',
        'retries': 'retries', 'verbose': 'verbose', 'passive': 'passive',
        'headless': 'headless',
        'verify_only': 'verify_only',
        'triage_assist': 'triage_assist',
        'rps': 'rps',
        'stealth': 'stealth',
        'scope': 'scope',
        'exclude_patterns': 'exclude_patterns',
        'include_paths': 'include_paths',
        'autosave_interval': 'autosave_interval',
    }
    defaulted = {'threads', 'timeout', 'retries', 'crawl_depth', 'autosave_interval', 'rps'}
    for yaml_key, arg_key in yaml_to_arg.items():
        if yaml_key not in config_file:
            continue
        cli_value = getattr(cli_args, arg_key, None)
        if cli_value is None or (arg_key in defaulted and cli_value in (10, 2, 3, 0, 5.0)):
            setattr(cli_args, arg_key, config_file[yaml_key])


def _apply_list_config(cli_args, config_file: dict) -> None:
    if isinstance(config_file.get('modules'), list):
        cli_args.modules = config_file['modules']
    if isinstance(config_file.get('disable_modules'), list):
        cli_args.disable_modules = config_file['disable_modules']


def _apply_header_config(cli_args, config_file: dict) -> None:
    if not isinstance(config_file.get('headers'), dict):
        return
    config_headers = [f"{k}:{v}" for k, v in config_file['headers'].items()]
    cli_args.headers.extend(config_headers) if cli_args.headers else setattr(cli_args, "headers", config_headers)


def _apply_module_params(cli_args, config_file: dict) -> None:
    if not isinstance(config_file.get('module_params'), dict):
        return
    for module_name, params in config_file['module_params'].items():
        if isinstance(params, dict):
            for param_key, param_value in params.items():
                cli_args.module_param.append(f"{module_name}.{param_key}={param_value}")


def merge_configs(cli_args, config_file: dict) -> argparse.Namespace:
    """
    Merge YAML config file with CLI arguments.
    CLI arguments take precedence over config file values.
    
    Args:
        cli_args: Parsed CLI arguments
        config_file: Dictionary from YAML config file
    
    Returns:
        Updated argparse.Namespace with merged values
    """
    if not config_file:
        return cli_args
    _apply_scalar_config(cli_args, config_file)
    _apply_list_config(cli_args, config_file)
    _apply_header_config(cli_args, config_file)
    _apply_module_params(cli_args, config_file)
    return cli_args


def _parse_param_value(value: str):
    normalized = value.strip()
    if normalized.lower() in ("true", "yes", "on"):
        return True
    if normalized.lower() in ("false", "no", "off"):
        return False
    if "," in normalized:
        return [item.strip() for item in normalized.split(",") if item.strip()]
    if normalized.isdigit():
        return int(normalized)
    try:
        return float(normalized)
    except ValueError:
        return normalized


def build_config(args):
    custom_headers = {}
    for h in args.headers:
        if ":" in h:
            k, v = h.split(":", 1)
            custom_headers[k.strip()] = v.strip()

    cookies = {}
    if args.cookies:
        for part in args.cookies.split(";"):
            part = part.strip()
            if "=" in part:
                k, v = part.split("=", 1)
                cookies[k.strip()] = v.strip()

    module_params = {}
    for param in args.module_param:
        if "=" not in param:
            continue
        key, value = param.split("=", 1)
        if "." in key:
            module_name, param_name = key.split(".", 1)
            module_params.setdefault(module_name, {})[param_name] = _parse_param_value(value)

    return {
        "target": args.target.rstrip("/"),
        "modules": args.modules,
        "disable_modules": args.disable_modules,
        "output_dir": args.output,
        "report_format": args.format,
        "threads": args.threads,
        "timeout": args.timeout,
        "cookies": cookies,
        "cookies_alt": args.cookies_alt or "",
        "headers": custom_headers,
        "auth": args.auth,
        "proxy": args.proxy,
        "verify_ssl": getattr(args, "verify_ssl", True),
        "crawl_depth": args.crawl_depth,
        "max_urls": args.max_urls,
        "delay": args.delay,
        "oob_host": args.oob_host,
        "wordlist": args.wordlist,
        "retries": args.retries,
        "autosave_interval": args.autosave_interval,
        "module_params": module_params,
        "verbose": args.verbose,
        "passive": args.passive,
        "headless": getattr(args, "headless", False),
        "verify_only": getattr(args, "verify_only", None),
        "triage_assist": getattr(args, "triage_assist", False),
        "rps": args.rps,
        "stealth": args.stealth,
        "scope": args.scope or "",
        "scope_enforcer": ScopeEnforcer(args.scope, args.output) if args.scope else None,
        "exclude_patterns": args.exclude_patterns or [],
        "include_paths": args.include_paths or [],
        "timestamp": datetime.now().strftime("%Y%m%d_%H%M%S"),
    }


def _log_startup(config: dict) -> None:
    modules = ['all'] if 'all' in config['modules'] else config['modules']
    log(f"Target      : {config['target']}", Colors.CYAN)
    log(f"Modules     : {', '.join(modules)}", Colors.CYAN)
    if config.get('disable_modules'):
        log(f"Disabled    : {', '.join(config['disable_modules'])}", Colors.CYAN)
    log(f"Threads     : {config['threads']}", Colors.CYAN)
    log(f"Max URLs    : {config['max_urls']}", Colors.CYAN)
    log(f"RPS         : {config.get('rps', 5.0)}", Colors.CYAN)
    log(f"Delay       : {config['delay']}s", Colors.CYAN)
    mode_parts = ['Passive' if config['passive'] else 'Active']
    if config.get('headless'):
        mode_parts.append('Headless')
    if config.get('stealth'):
        mode_parts.append('Stealth')
    log(f"Mode        : {' + '.join(mode_parts)}", Colors.CYAN)
    if config.get('scope'):
        log(f"Scope       : {config['scope']}", Colors.CYAN)
    log(f"Report      : {config['report_format'].upper()}\n", Colors.CYAN)


def _should_run_recon(config: dict, run_all: bool, disabled_modules: set) -> bool:
    return (
        (run_all and "recon" not in disabled_modules)
        or "recon" in config["modules"]
        or "js_secrets" in config["modules"]
    )


def _run_recon_if_needed(config: dict, run_recon: bool):
    if not run_recon:
        return None, {"urls": [config["target"]], "subdomains": [], "forms": [], "js_urls": [], "authenticated": False}
    log("[*] Starting Recon...", Colors.YELLOW)
    recon = Recon(config)
    recon_data = recon.run()
    if not recon.authenticated:
        print("[!] Scanning unauthenticated. Pass --cookies or --headers for full coverage of authenticated attack surface.")
    log(f"[+] Discovered {len(recon_data.get('urls', []))} URLs, "
        f"{len(recon_data.get('subdomains', []))} subdomains", Colors.GREEN)
    return recon, recon_data


def _start_autosave(config, recon_data, all_findings, all_findings_lock):
    interval = config.get("autosave_interval", 0)
    stop_event = threading.Event()
    if interval <= 0:
        return stop_event, None

    def worker():
        reporter = Reporter(config, [], recon_data, js_data=js_data)
        while not stop_event.wait(interval):
            with all_findings_lock:
                reporter.findings = list(all_findings)
            try:
                reporter.generate(suffix="partial")
                log(f"[✓] Interim report autosaved", Colors.GREEN)
            except Exception as e:
                log(f"[!] Autosave failed: {e}", Colors.YELLOW)

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    return stop_event, thread


def _collect_module_findings(modules, config, run_all, disabled_modules, all_findings, lock):
    for mod_name, mod_fn in modules.items():
        if mod_name in disabled_modules:
            log(f"[-] Skipping disabled module {mod_name.upper()}", Colors.CYAN)
            continue
        if not (run_all or mod_name in config["modules"]):
            continue
        log(f"[*] Running {mod_name.upper()} scan...", Colors.YELLOW)
        findings = mod_fn()
        if findings:
            log(f"[!] {len(findings)} finding(s) from {mod_name.upper()}", Colors.RED)
            with lock:
                all_findings.extend(findings)
        else:
            log(f"[+] {mod_name.upper()} — nothing found", Colors.GREEN)


def _run_scans(config, recon_data, recon, run_all, disabled_modules, all_findings, lock):
    # ── TARGET_LEVEL: modules that run once per target, not per URL ──
    TARGET_LEVEL: set[str] = {
        "headers", "dirb", "exposed_files", "clickjacking",
        "subdomain_takeover", "graphql", "blind_xss", "js_secrets", "api",
    }

    if config["passive"]:
        log("[*] Passive mode — skipping active fuzzing.", Colors.YELLOW)
        scanner = VulnScanner(config, recon_data)
        modules = {"headers": scanner.scan_headers}
        _collect_module_findings(modules, config, run_all, disabled_modules, all_findings, lock)
        return

    scanner = VulnScanner(config, recon_data)
    all_findings_local: list[dict] = []

    # ── Step 1: Build module map (same keys as original _active_module_map) ──
    module_map: dict[str, Any] = {
        "openapi": scanner.scan_openapi,
        "xss": scanner.scan_xss, "sqli": scanner.scan_sqli,
        "lfi": scanner.scan_lfi, "ssrf": scanner.scan_ssrf,
        "xxe": scanner.scan_xxe,
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
        "idor": scanner.scan_idor,
        "rate_limiting": scanner.scan_rate_limiting,
    }
    _api_scanner = ApiScanner(scanner.config, scanner.recon)
    module_map["api"] = _api_scanner.run_all
    _idor_scanner = IdorScanner(scanner.config, scanner.recon)
    module_map["idor"] = _idor_scanner.run_all

    # ── Step 2: Run TARGET_LEVEL modules first ───────────────────────────
    target_modules = {k: v for k, v in module_map.items() if k in TARGET_LEVEL}
    _collect_module_findings(target_modules, config, run_all, disabled_modules, all_findings_local, lock)

    # ── Step 3: Score and sort URLs ──────────────────────────────────────
    urls = recon_data.get("urls", [])
    forms = recon_data.get("forms", [])
    scored = [(compute_endpoint_score(u, forms, recon_data), u) for u in urls]
    scored.sort(key=lambda x: -x[0])
    sorted_urls = [u for _, u in scored]

    top_n = scored[:10]
    log("\n[*] Top 10 scored endpoints (highest attack surface first):", Colors.BOLD)
    for rank, (score, url) in enumerate(top_n, 1):
        log(f"    {rank:>2}. [{score:>3}] {url}", Colors.CYAN)

    # ── Step 4: Per-URL intelligent module selection ─────────────────────
    per_url_modules = {k: v for k, v in module_map.items() if k not in TARGET_LEVEL}

    for url in sorted_urls:
        applicable = classify_endpoint(url, forms, recon_data)
        # Respect --modules filter
        if not run_all:
            applicable &= set(config["modules"])
        # Remove disabled modules
        applicable -= disabled_modules
        # Keep only modules available in the per-URL map
        applicable &= per_url_modules.keys()

        if not applicable:
            continue

        log(f"[*] {url} → {len(applicable)} modules selected: {sorted(applicable)}", Colors.YELLOW, verbose_only=True, verbose=config.get("verbose", False))

        for mod_name in applicable:
            try:
                mod_fn = per_url_modules[mod_name]
                findings = mod_fn(target_urls=[url])
                if findings:
                    with lock:
                        all_findings_local.extend(findings)
            except Exception as e:
                log(f"  [!] {mod_name} error on {url}: {e}", Colors.RED, verbose_only=True, verbose=config.get("verbose", False))

    # ── Step 5: Post-scan triage pipeline ───────────────────────────────
    log("[*] Running re-verification loop...", Colors.CYAN)
    scanner._run_reverification_loop()

    updated = scanner._get_findings()

    log("[*] Running chain analysis...", Colors.CYAN)
    updated = VulnScanner.chain_analysis(updated)

    log("[*] Checking self-halting conditions...", Colors.CYAN)
    updated = VulnScanner.check_self_halt(updated)

    from modules.utils import prioritize_findings
    updated = prioritize_findings(updated)

    with lock:
        all_findings.clear()
        all_findings.extend(updated)


def _write_report_and_summary(config, all_findings, recon_data, js_data=None) -> int:
    try:
        report_path = Reporter(config, all_findings, recon_data, js_data=js_data).generate()
        log(f"\n[✓] Report saved → {report_path}", Colors.GREEN)
    except Exception as e:
        log(f"\n[✗] Failed to save report: {e}", Colors.RED)
        return 1
    critical = [f for f in all_findings if f.get("severity") == "critical"]
    high = [f for f in all_findings if f.get("severity") == "high"]
    medium = [f for f in all_findings if f.get("severity") == "medium"]
    low = [f for f in all_findings if f.get("severity") == "low"]
    confirmed = [f for f in all_findings if f.get("confidence_score", 0) >= 86]
    validated = [f for f in all_findings if f.get("verification_stage") == "validated"]
    exploitable = [f for f in all_findings if f.get("verification_stage") == "exploitable"]
    log(f"\n{'─'*50}", Colors.CYAN)
    log("  SCAN SUMMARY", Colors.BOLD)
    log(f"{'─'*50}", Colors.CYAN)
    log(f"  Critical    : {len(critical)}", Colors.RED if critical else Colors.WHITE)
    log(f"  High        : {len(high)}", Colors.RED if high else Colors.WHITE)
    log(f"  Medium      : {len(medium)}", Colors.YELLOW if medium else Colors.WHITE)
    log(f"  Low         : {len(low)}", Colors.CYAN if low else Colors.WHITE)
    log(f"  Confirmed   : {len(confirmed)}", Colors.GREEN if confirmed else Colors.WHITE)
    log(f"  Validated   : {len(validated)}", Colors.GREEN if validated else Colors.WHITE)
    log(f"  Exploitable : {len(exploitable)}", Colors.RED if exploitable else Colors.WHITE)
    log(f"  Total       : {len(all_findings)}", Colors.BOLD)
    log(f"{'─'*50}\n", Colors.CYAN)
    return 0 if not critical and not high else 1


def main():
    banner()
    args = parse_args()
    if args.config:
        log(f"Loading configuration from {args.config}", Colors.CYAN)
        args = merge_configs(args, load_config_file(args.config))
    if not args.target:
        log("[!] Error: --target is required (or specify via --config file)", Colors.RED)
        sys.exit(1)

    config = build_config(args)
    verify_path = config.get("verify_only")
    if verify_path:
        from modules.scanner import VulnScanner
        log(f"[*] Verify-only mode: re-checking findings from {verify_path}", Colors.CYAN)
        verified = VulnScanner.verify_report(verify_path, config)
        if not verified:
            log("[!] No findings to verify; exiting.", Colors.YELLOW)
            return 0
        out_path = verify_path.replace(".json", "_verified.json")
        import json
        with open(out_path, "w") as f:
            json.dump({"findings": verified, "verification": {
                "total": len(verified),
                "confirmed": sum(1 for v in verified if v.get("confirmed")),
                "report_date": config.get("timestamp"),
            }}, f, indent=2)
        log(f"[+] Verified report saved to {out_path}", Colors.GREEN)
        return 0

    os.makedirs(config["output_dir"], exist_ok=True)
    _log_startup(config)

    all_findings = []
    run_all = "all" in config["modules"]
    disabled_modules = set(config.get("disable_modules", []))
    recon, recon_data = _run_recon_if_needed(
        config, _should_run_recon(config, run_all, disabled_modules)
    )

    # ── JS Intelligence scan ─────────────────────────────────────────────
    js_data: dict = {
        "secrets": [], "endpoints": [], "hidden_endpoints": [],
        "routes": [], "env_vars": [], "hardcoded_values": [],
    }
    js_urls = recon_data.get("js_urls", [])
    run_js = (
        "all" in config["modules"] or "js_secrets" in config["modules"]
    ) and bool(js_urls) and not config.get("passive", False)

    if run_js:
        log("[*] Running JS Intelligence scan...", Colors.YELLOW)
        js_intel = JSIntelligence(base_url=config["target"], config=config)
        js_session = make_session(config)
        max_js = 50
        urls_to_scan = js_urls[:max_js]
        if len(js_urls) > max_js:
            log(f"[!] {len(js_urls)} JS bundles found, scanning first {max_js} (--max-urls to increase)",
                Colors.YELLOW)

        for url in urls_to_scan:
            resp = safe_get(js_session, url, timeout=config.get("timeout", 10), raise_for_status=False)
            if resp is None or resp.status_code >= 400:
                continue
            result = js_intel.analyze(resp.text, source_url=url)
            for key in ("secrets", "endpoints", "hidden_endpoints", "routes", "env_vars", "hardcoded_values"):
                js_data.setdefault(key, []).extend(result.get(key, []))

        # Add discovered same-domain URLs to scan target list
        for ep in js_data.get("endpoints", []):
            ep_url = ep.get("url", "")
            if ep_url and same_domain(config["target"], ep_url):
                if ep_url not in recon_data["urls"]:
                    recon_data["urls"].append(ep_url)
        for ep in js_data.get("hidden_endpoints", []):
            ep_url = ep.get("url", "")
            if ep_url and same_domain(config["target"], ep_url):
                if ep_url not in recon_data["urls"]:
                    recon_data["urls"].append(ep_url)

        # Generate findings from secrets
        for entry in js_data.get("secrets", []):
            if entry.get("confidence") == "none":
                continue
            f = finding(
                vuln_type=f"Exposed JS Secret ({entry['type']})",
                url=entry.get("source_url", ""),
                severity="critical" if entry.get("validated") else "high",
                details=f"Secret type '{entry['type']}' found in JS file",
                evidence=f"Match: {entry['value'][:40]}... Source: {entry.get('source_url', '')}",
            )
            if f:
                all_findings.append(f)

        secret_count = len(js_data.get("secrets", []))
        endpoint_count = len(js_data.get("endpoints", [])) + len(js_data.get("hidden_endpoints", []))
        log(f"[+] JS Intelligence scan complete: {secret_count} secrets, {endpoint_count} endpoints",
            Colors.GREEN)

    all_findings_lock = threading.Lock()
    stop_autosave, autosave_thread = _start_autosave(
        config, recon_data, all_findings, all_findings_lock
    )
    _run_scans(config, recon_data, recon, run_all, disabled_modules, all_findings, all_findings_lock)
    if autosave_thread:
        stop_autosave.set()
        autosave_thread.join(timeout=2)
    return _write_report_and_summary(config, all_findings, recon_data, js_data=js_data)


if __name__ == "__main__":
    sys.exit(main())
