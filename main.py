#!/usr/bin/env python3
"""
BugBounty Hunter - Automated vulnerability scanner for bug bounty programs.
Usage: python main.py --target https://example.com [options]
"""

import argparse
import glob
import json
import sys
import os
import threading
import time
import yaml
from datetime import datetime
from typing import Any

from modules.recon import Recon
from modules.scanner import VulnScanner
from modules.api_scanner import ApiScanner
from modules.reporter import Reporter
from modules.js_intelligence import JSIntelligence
from modules.utils import banner, log, Colors, ScopeEnforcer, safe_get, same_domain, finding, make_session, classify_endpoint, compute_endpoint_score, prioritize_findings, reset_seen_findings, _build_curl, set_mask_sensitive_default, ScanProgress, safe_cookies_dict
from models.finding import Finding
from app.bootstrap import bootstrap, auto_upgrade_config, print_startup_summary
from engines.history import correlate_findings
from app.orchestrator import run_scans


def parse_args():
    parser = argparse.ArgumentParser(
        description="BugBounty Hunter - Automated vulnerability detector\n"
                    "  bugbounty-hunter scan https://target.com   (preferred CLI)",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--config", "-C", help="Path to YAML configuration file")
    parser.add_argument("--target", "-t", help="Target URL (e.g. https://example.com)")
    parser.add_argument("--modules", "-m", nargs="+",
        choices=["recon", "xss", "sqli", "lfi", "ssrf", "xxe", "ssti", "cmd_injection", "blind_xss", "open_redirect", "headers", "csrf", "dirb", "sensitive", "exposed_files", "clickjacking", "http_methods", "insecure_forms", "subdomain_takeover", "graphql", "idor", "js_secrets", "api", "rate_limiting", "openapi", "authorization", "cors", "jwt", "cms", "all"],
        default=["all"])
    parser.add_argument("--output", "-o", default="reports")
    parser.add_argument("--format", "-f", choices=["json", "html", "txt", "markdown-report", "hackerone", "bugcrowd", "chatgpt"], default="chatgpt")
    parser.add_argument("--threads", type=int, default=5)
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
    parser.add_argument("--delay", type=float, default=0.1,
        help="Delay between requests in seconds (default: 0.1)")
    parser.add_argument("--oob-host", default=None,
        help="Out-of-band callback host for SSRF and SQLi OOB verification (e.g. Burp Collaborator or interactsh URL)")
    parser.add_argument("--allow-auto-oob", action="store_true",
        help="Allow automatic OOB service discovery (contacts dnslog.cn / interactsh at startup). Off by default.")
    parser.add_argument("--wordlist", help="Optional directory fuzzing wordlist path")
    parser.add_argument("--disable-modules", nargs="+",
        choices=["recon", "xss", "sqli", "lfi", "ssrf", "xxe", "ssti", "cmd_injection", "blind_xss", "open_redirect", "headers", "csrf", "dirb", "sensitive", "exposed_files", "clickjacking", "http_methods", "insecure_forms", "subdomain_takeover", "graphql", "idor", "js_secrets", "api", "rate_limiting", "openapi", "authorization", "cors", "jwt", "cms"],
        default=[], help="Disable specific modules when scanning all or default modules")
    parser.add_argument("--module-param", action="append", default=[],
        help="Override module settings using module.key=value")
    parser.add_argument("--retries", type=int, default=3,
        help="HTTP retry attempts for transient failures")
    parser.add_argument("--autosave-interval", type=int, default=60,
        help="Autosave interim report every N seconds (0 = disabled)")
    parser.add_argument("--module-timeout", type=int, default=120,
        help="Per-module timeout in seconds (default: 120)")
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("--passive", action="store_true")
    parser.add_argument("--headless", action="store_true",
        help="Use Playwright headless browser for JS-rendered crawling (network intercept, SPA route discovery)")
    parser.add_argument("--verify-only", "-V",
        help="Re-verify unconfirmed findings from a previous JSON report. Path to report file.")
    parser.add_argument("--resume", action="store_true",
        help="Resume a previous scan from .scan_state.json (skips completed URLs)")
    parser.add_argument("--rps", type=float, default=3.0,
        help="Requests per second (default: 3). Halved on 429, restored after 20 OK.")
    parser.add_argument("--legacy-scanners", action="store_false", dest="new_scanners",
        help="Use legacy inline scan methods instead of ScannerBase subclasses.")
    parser.add_argument("--stealth", action="store_true",
        help="Stealth mode: rotate 20 User-Agent strings, random 0.5-2s delay, shuffle POST params.")
    parser.add_argument("--scope",
        help="Path to scope file (one domain/IP/CIDR per line). Out-of-scope URLs are rejected & logged.")
    parser.add_argument("--exclude-patterns", nargs="*", default=[],
        help="Regex patterns for URL exclusions (e.g. '/admin' '/logout')")
    parser.add_argument("--include-paths", nargs="*", default=[],
        help="Regex patterns for URL inclusion (e.g. '/api' '/graphql'). All others excluded.")
    parser.add_argument("--no-rich", action="store_true",
        help="Disable Rich terminal output (plain text, good for CI/pipe)")
    parser.add_argument("--max-js-files", type=int, default=50,
        help="Maximum number of JS files to scan for secrets/endpoints (default: 50)")
    parser.add_argument("--no-mask-curl", action="store_true",
        help="Disable sensitive header masking in curl commands within reports (shows Authorization, Cookie, etc.)")
    parser.add_argument("--no-history", action="store_true",
        help="Disable historical finding correlation (scan history tracking)")
    parser.add_argument("--history-file", default="scan_history.json",
        help="Path to scan history file for finding correlation (default: scan_history.json in output dir)")
    parser.add_argument("--status", action="store_true",
        help="Show real-time scan status: modules completed, findings, URLs, and progress summary.")
    parser.add_argument("--disable-engine", nargs="+", default=[],
        choices=["attack_chains", "investigation", "impact", "evidence_quality",
                 "scan_budget", "asset_graph", "promotion", "replay",
                 "duplicate_risk", "consensus", "metrics"],
        help="Disable specific analysis engines")
    parser.add_argument("--rdc-noise", action="store_true",
        help="Reduce attack-chain noise by filtering same-root-cause / low-value chains.")
    parser.add_argument("--auto", action="store_true",
        help="Auto mode (default): sensible defaults for a quick scan.")
    parser.add_argument("--dry-run", action="store_true",
        help="Run recon and JS intelligence only, then print attack-surface summary and exit. Skips all active fuzzing.")
    parser.add_argument("--role", default=None,
        help="Current user role name for authorization testing (e.g. 'user_a', 'admin')")
    parser.add_argument("--auth-header", action="append", default=[],
        help="Auth header for a role in format 'role_name:HeaderName:HeaderValue'. "
             "Can be specified multiple times. "
             "E.g. --auth-header user_b:Authorization:'Bearer tok_b'")
    parser.add_argument("--do-login", default=None,
        help="Login URL — use Playwright to authenticate before scanning. "
             "Provide a full URL (e.g. 'https://example.com/login'). "
             "Requires --login-username and --login-password.")
    parser.add_argument("--login-username", default=None,
        help="Username or email for --do-login")
    parser.add_argument("--login-password", default=None,
        help="Password for --do-login")
    parser.add_argument("--login-username-field", default="username",
        help="Name attribute of the username/email input field (default: 'username')")
    parser.add_argument("--login-password-field", default="password",
        help="Name attribute of the password input field (default: 'password')")
    parser.add_argument("--login-extra-fields", nargs="*", default=[],
        help="Extra form fields in 'name=value' format (e.g. 'tenant=acme'). "
             "Can be specified multiple times.")
    parser.add_argument("--check-default-creds", action="store_true",
        help="Explicitly force default-credential check even when "
             "--no-default-creds is set or --do-login is being used.")
    parser.add_argument("--login-verify-url", default=None,
        help="URL to probe after login to verify session validity "
             "(e.g. '/api/v1/user'). Default: checks if page URL changed.")
    parser.add_argument("--no-default-creds", action="store_true",
        help="Disable automatic default-credential detection against "
             "discovered login pages (enabled by default).")

    # ── New features (v1.0.0) ────────────────────────────────────────────
    parser.add_argument("--footprint", choices=["stealth", "normal", "aggressive"], default=None,
        help="Scan footprint profile: stealth (0.5rps, UA rotation, jitter), normal (default), aggressive (10rps)")
    parser.add_argument("--spa-recon", action="store_true",
        help="Enable headless browser SPA recon (Playwright-based XHR/fetch/route capture)")
    parser.add_argument("--intel-sources", nargs="*", default=[],
        choices=["shodan", "crtsh", "wayback", "github"],
        help="External intelligence sources for passive recon (requires API keys configured)")
    parser.add_argument("--shodan-key",
        help="Shodan API key for external intelligence gathering")
    parser.add_argument("--github-token",
        help="GitHub token for code leak search")
    parser.add_argument("--waf-evasion", action="store_true",
        help="Enable WAF fingerprinting and payload evasion (encoding/fragmentation)")
    parser.add_argument("--smuggling", action="store_true",
        help="Enable HTTP request smuggling detection (CL.TE, TE.CL, TE.TE)")
    parser.add_argument("--business-logic", action="store_true",
        help="Enable business logic flaw testing (workflow bypass, race conditions, price manipulation)")
    parser.add_argument("--prioritize-submissions", action="store_true",
        help="Generate submission prioritisation queue (ranked by severity/confidence/evidence/validation-rate)")
    parser.add_argument("--per-finding-export", action="store_true",
        help="Export each finding as a standalone HTML page with all evidence")
    parser.add_argument("--cross-scan-db",
        help="Path to cross-scan finding database (SQLite) for dedup across runs")
    parser.add_argument("--scan-id", default=None,
        help="Unique scan identifier for cross-scan tracking (auto-generated if not set)")
    parser.add_argument("--webhook-url",
        help="Slack/Discord webhook URL for real-time finding alerts")
    parser.add_argument("--webhook-threshold", type=int, default=60,
        help="Minimum confidence score for webhook alerts (default: 60)")
    parser.add_argument("--passive-import",
        help="Path to HAR file or Burp XML export for passive analysis mode (skips active recon)")
    parser.add_argument("--mobile-import",
        help="Path to Burp/Charles export for mobile API mode")
    parser.add_argument("--diff-scan",
        help="Path to previous scan JSON output for diff/regression comparison")
    parser.add_argument("--audit-log", action="store_true",
        help="Enable per-request audit log (CSV) in output directory")
    parser.add_argument("--payload-db",
        help="Path to payload intelligence database (JSON)")
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
        'resume': 'resume',
        'rps': 'rps',
        'stealth': 'stealth',
        'scope': 'scope',
        'exclude_patterns': 'exclude_patterns',
        'include_paths': 'include_paths',
        'autosave_interval': 'autosave_interval',
        'max_js_files': 'max_js_files',
        'role': 'role',
        'auth_header': 'auth_header',
        'new_scanners': 'new_scanners',
        'auto': 'auto',
    }
    arg_defaults = {
        'threads': 10, 'timeout': 10, 'retries': 3,
        'crawl_depth': 2, 'autosave_interval': 0, 'rps': 5.0,
    }
    BOOL_FLAGS = {'verbose', 'passive', 'headless', 'stealth', 'resume', 'verify_only', 'new_scanners'}
    for yaml_key, arg_key in yaml_to_arg.items():
        if yaml_key not in config_file:
            continue
        cli_value = getattr(cli_args, arg_key, None)
        is_bool_flag = arg_key in BOOL_FLAGS
        is_default = (
            cli_value is None
            or (is_bool_flag and cli_value is False)
            or (not is_bool_flag and cli_value == arg_defaults.get(arg_key))
        )
        if is_default:
            setattr(cli_args, arg_key, config_file[yaml_key])


def _apply_list_config(cli_args, config_file: dict) -> None:
    if isinstance(config_file.get('modules'), list) and config_file['modules']:
        existing = set(cli_args.modules or [])
        merged = existing | set(config_file['modules'])
        cli_args.modules = list(merged)
    if isinstance(config_file.get('disable_modules'), list) and config_file['disable_modules']:
        existing = set(cli_args.disable_modules or [])
        merged = existing | set(config_file['disable_modules'])
        cli_args.disable_modules = list(merged)


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
        "auto": getattr(args, "auto", False),
        "modules": args.modules,
        "disable_modules": args.disable_modules,
        "output_dir": args.output,
        "report_format": args.format,
        "threads": args.threads,
        "timeout": args.timeout,
        "module_timeout": getattr(args, "module_timeout", 120),
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
        "allow_auto_oob": getattr(args, "allow_auto_oob", False),
        "wordlist": args.wordlist,
        "retries": args.retries,
        "autosave_interval": args.autosave_interval,
        "module_params": module_params,
        "verbose": args.verbose,
        "passive": args.passive,
        "headless": getattr(args, "headless", False),
        "verify_only": getattr(args, "verify_only", None),
        "resume": getattr(args, "resume", False),
        "use_new_scanners": getattr(args, "new_scanners", True),
        "dry_run": getattr(args, "dry_run", False),
        "no_mask_curl": getattr(args, "no_mask_curl", False),
        "no_history": getattr(args, "no_history", False),
        "history_file": getattr(args, "history_file", "scan_history.json"),
        "passive_import": getattr(args, "passive_import", ""),
        "rps": args.rps,
        "stealth": args.stealth,
        "max_js_files": args.max_js_files,
        "scope": args.scope or "",
        "scope_enforcer": ScopeEnforcer(args.scope, args.output) if args.scope else None,
        "exclude_patterns": args.exclude_patterns or [],
        "include_paths": args.include_paths or [],
        "timestamp": datetime.now().strftime("%Y%m%d_%H%M%S"),
        "role": getattr(args, "role", None),
        "auth_header": getattr(args, "auth_header", []),
        "disabled_engines": set(getattr(args, "disable_engine", [])),
        "rdc_noise": getattr(args, "rdc_noise", False),
        "do_login": getattr(args, "do_login", None),
        "login_username": getattr(args, "login_username", None),
        "login_password": getattr(args, "login_password", None),
        "login_username_field": getattr(args, "login_username_field", "username"),
        "login_password_field": getattr(args, "login_password_field", "password"),
        "login_extra_fields": getattr(args, "login_extra_fields", []),
        "check_default_creds": getattr(args, "check_default_creds", False),
        "login_verify_url": getattr(args, "login_verify_url", None),
        "no_default_creds": getattr(args, "no_default_creds", False),
        "status": {
            "phase": "initialized",
            "findings_count": 0,
            "urls_scanned": 0,
            "total_urls": 0,
            "modules_completed": [],
        },
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
    if config.get('auto'):
        mode_parts.append('Auto')
    log(f"Mode        : {' + '.join(mode_parts)}", Colors.CYAN)
    if config.get('scope'):
        log(f"Scope       : {config['scope']}", Colors.CYAN)
    log(f"Report      : {config['report_format'].upper()}", Colors.CYAN)
    if config.get("do_login"):
        log(f"Auto-login  : {config['do_login']}", Colors.CYAN)
    if config.get("no_default_creds"):
        log(f"Default-creds: disabled (--no-default-creds)", Colors.YELLOW)
    else:
        log(f"Default-creds: auto-detect login pages", Colors.CYAN)
    log("", Colors.CYAN)


def _should_run_recon(config: dict, run_all: bool, disabled_modules: set) -> bool:
    if "recon" in disabled_modules:
        return False
    return (
        (run_all and "recon" not in disabled_modules)
        or "recon" in config["modules"]
        or "js_secrets" in config["modules"]
    )


def _detect_login_pages(forms: list[dict], target: str) -> list[tuple[str, str]]:
    """Scan recon form data for login forms (those with a password field).

    Returns ``[(page_url, action_url), ...]`` sorted by most specific
    action URL first (longest path = most likely the actual login form).
    Deduplicates by action URL.
    """
    seen: set[str] = set()
    results: list[tuple[str, str, int]] = []
    for form in forms:
        for field in form.get("fields", []):
            if field.get("type") == "password":
                action = form.get("action", "").rstrip("/")
                if action and action not in seen:
                    seen.add(action)
                    page_url = form.get("url", target)
                    results.append((page_url, action, len(action)))
                break
    # Sort by action path specificity (longest first)
    results.sort(key=lambda x: -x[2])
    return [(p, a) for p, a, _ in results]


def _run_recon_if_needed(config: dict, run_recon: bool, container=None):
    if not run_recon:
        return None, {"urls": [config["target"]], "subdomains": [], "forms": [], "js_urls": [], "authenticated": False}
    log("[*] Starting Recon...", Colors.YELLOW)
    recon = Recon(config, container=container)
    recon_data = recon.run()
    if not recon.authenticated:
        print("[!] Scanning unauthenticated. Pass --cookies or --headers for full coverage of authenticated attack surface.")
    log(f"[+] Discovered {len(recon_data.get('urls', []))} URLs, "
        f"{len(recon_data.get('subdomains', []))} subdomains", Colors.GREEN)
    return recon, recon_data


def _start_autosave(config, recon_data, all_findings, all_findings_lock, js_data=None, container=None):
    interval = config.get("autosave_interval", 0)
    stop_event = threading.Event()
    _js_data = js_data or {}
    if interval <= 0:
        return stop_event, None

    _live_last = [time.time()]  # mutable box for closure

    def worker():
        while not stop_event.wait(interval):
            # Live counter every 30s
            elapsed = time.time() - _live_last[0]
            if elapsed >= 30:
                with all_findings_lock:
                    findings_copy = list(all_findings)
                confirmed = sum(1 for f in findings_copy if f.get("confirmed"))
                log(f"  [Live] {len(findings_copy)} findings ({confirmed} confirmed)", Colors.CYAN)
                _live_last[0] = time.time()

            with all_findings_lock:
                snapshot = list(all_findings)
            try:
                reporter = Reporter(config, snapshot, recon_data, js_data=_js_data, container=container)
                reporter.generate(suffix="partial")
                log(f"[✓] Interim report autosaved", Colors.GREEN)
            except Exception as e:
                log(f"[!] Autosave failed: {e}", Colors.YELLOW)

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    return stop_event, thread


def _findings_to_finding(config, all_findings, recon_data, js_data):
    """Convert legacy dict findings to canonical Finding instances at the pipeline boundary."""
    converted = []
    for f in all_findings:
        if isinstance(f, Finding):
            converted.append(f)
        elif isinstance(f, dict):
            converted.append(Finding.from_dict(f))
        else:
            converted.append(Finding.from_dict({"type": "unknown", "url": str(f)}))
    return converted


def _write_report_and_summary(config, all_findings, recon_data, js_data=None, container=None) -> int:
    adapted = _findings_to_finding(config, all_findings, recon_data, js_data)
    try:
        report_path = Reporter(config, adapted, recon_data, js_data=js_data, container=container).generate()
        log(f"\n[✓] Report saved → {report_path}", Colors.GREEN)
    except Exception as e:
        log(f"\n[✗] Failed to save report: {e}", Colors.RED)
        return 1

    # Print output file paths clearly
    log("", Colors.WHITE)
    log("=" * 60, Colors.CYAN)
    log(f"  SCAN COMPLETE — {len(all_findings)} finding(s)", Colors.CYAN)
    log("=" * 60, Colors.CYAN)
    log(f"  Report:   {report_path}", Colors.WHITE)
    findings_json_path = config.get("_last_findings_path", "")
    if not findings_json_path:
        json_files = sorted(glob.glob(
            os.path.join(config["output_dir"], f"*_{config.get('timestamp', '')}_findings.json")
        ))
        findings_json_path = json_files[-1] if json_files else ""
    if findings_json_path:
        log(f"  JSON:     {findings_json_path}", Colors.WHITE)
    log(f"  Folder:   {os.path.abspath(config['output_dir'])}", Colors.WHITE)
    log("", Colors.WHITE)
    if config.get("report_format") == "chatgpt":
        log(f"  ChatGPT:  {report_path} — paste this file directly into ChatGPT",
            Colors.WHITE)
    log("  To summarise with AI, open the report or run:", Colors.CYAN)
    log(f"    cat {findings_json_path if findings_json_path else '<findings.json>'} | pbcopy",
        Colors.WHITE)
    log("  Then paste into ChatGPT, Claude, or your preferred AI tool.", Colors.WHITE)
    log("=" * 60, Colors.CYAN)

    critical = [f for f in all_findings if f.severity == "critical"]
    high = [f for f in all_findings if f.severity == "high"]
    medium = [f for f in all_findings if f.severity == "medium"]
    low = [f for f in all_findings if f.severity == "low"]
    confirmed = [f for f in all_findings if (f.confidence_score or 0) >= 86]
    validated = [f for f in all_findings if f.verification_stage == "validated"]
    exploitable = [f for f in all_findings if f.verification_stage == "exploitable"]
    verified = [f for f in all_findings if f.verification_stage == "verified"]

    # Root-cause grouping for terminal summary using proper aggregator.
    # adapted findings already have root_cause set by ReporterBase.
    from engines.root_cause import RootCauseAggregator
    aggregator = RootCauseAggregator(config)
    root_cause_groups = aggregator.aggregate(adapted)
    if root_cause_groups:
        log(f"\n  Root Causes", Colors.BOLD)
        for group in sorted(root_cause_groups, key=lambda g: -g.count):
            log(f"    {group.root_cause}: {group.count} finding(s) [{group.severity}]", Colors.WHITE)

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
    log(f"  Verified    : {len(verified)}", Colors.GREEN if verified else Colors.WHITE)
    log(f"  Total       : {len(all_findings)}", Colors.BOLD)
    log(f"{'─'*50}\n", Colors.CYAN)
    return 0 if not critical and not high else 1


def print_scan_status(config: dict, all_findings: list | None = None,
                       recon_data: dict | None = None,
                       phase: str = "initializing") -> None:
    """Print a detailed status report of the current scan.

    Called when --status is passed or via SIGINFO/SIGUSR1.
    """
    sep = Colors.CYAN + "─" * 50 + Colors.END
    log("", Colors.WHITE)
    log(sep, Colors.CYAN)
    log("  SCAN STATUS", Colors.BOLD)
    log(sep, Colors.CYAN)
    log(f"  Target      : {config.get('target', 'N/A')}", Colors.CYAN)
    log(f"  Phase       : {phase}", Colors.CYAN)
    log(f"  Modules     : {', '.join(config.get('modules', ['all']))}", Colors.CYAN)
    log(f"  Threads     : {config.get('threads', 5)}", Colors.CYAN)
    log(f"  RPS         : {config.get('rps', 3.0)}", Colors.CYAN)
    log(f"  Timeout     : {config.get('timeout', 10)}s", Colors.CYAN)
    log(f"  Crawl depth : {config.get('crawl_depth', 2)}", Colors.CYAN)
    log(f"  Max URLs    : {config.get('max_urls', 200)}", Colors.CYAN)
    log(f"  Delay       : {config.get('delay', 0.1)}s", Colors.CYAN)
    if config.get('oob_host'):
        log(f"  OOB Host    : {config['oob_host']}", Colors.CYAN)
    log(f"  Report      : {config.get('report_format', 'html')}", Colors.CYAN)
    log(f"  Output dir  : {config.get('output_dir', 'reports')}", Colors.CYAN)
    if all_findings is not None:
        confirmed = sum(1 for f in all_findings if f.get("confidence_score", 0) >= 86)
        log(f"  Findings    : {len(all_findings)} total, {confirmed} confirmed", Colors.BOLD)
        if all_findings:
            by_sev: dict[str, int] = {}
            for f in all_findings:
                s = f.get("severity", "unknown")
                by_sev[s] = by_sev.get(s, 0) + 1
            parts = [f"    {s}: {c}" for s, c in sorted(by_sev.items(), key=lambda x: -ord(x[0][0]))]
            for p in parts:
                log(p, Colors.WHITE)
    if recon_data:
        urls = recon_data.get("urls", [])
        subdomains = recon_data.get("subdomains", [])
        forms = recon_data.get("forms", [])
        log(f"  URLs        : {len(urls)}", Colors.CYAN)
        log(f"  Subdomains  : {len(subdomains)}", Colors.CYAN)
        log(f"  Forms       : {len(forms)}", Colors.CYAN)
    log(sep, Colors.CYAN)
    log("", Colors.WHITE)


def main():
    reset_seen_findings()
    banner()
    args = parse_args()

    if getattr(args, "no_rich", False):
        from modules.utils import set_rich_enabled, safe_cookies_dict
        set_rich_enabled(False)
    if args.config:
        log(f"Loading configuration from {args.config}", Colors.CYAN)
        args = merge_configs(args, load_config_file(args.config))
    if getattr(args, 'auto', False):
        log("[*] Auto mode: sensible defaults are now the default (rps=3, threads=5, autosave=60s, format=chatgpt)",
            Colors.CYAN)

    if not args.target:
        log("[!] Error: --target is required (or specify via --config file)", Colors.RED)
        sys.exit(1)

    config = build_config(args)

    # ── Status flag: show config summary before scan, print periodic status during ──
    if getattr(args, "status", False):
        config["status_print"] = True
        print_scan_status(config, phase="pre-scan")

    set_mask_sensitive_default(not config.get("no_mask_curl", False))
    return run(config)


def run(config: dict) -> int:

    # ── Capability-driven startup ────────────────────────────────────────
    # Enable SQLite-backed evidence persistence with WAL mode
    output_dir = config.get("output_dir", "reports")
    config.setdefault("evidence_db_path", os.path.join(output_dir, "evidence.db"))
    capabilities, container = bootstrap(config)
    config = auto_upgrade_config(config, capabilities)
    print_startup_summary(capabilities)

    verify_path = config.get("verify_only")
    if verify_path:
        log(f"[*] Verify-only mode: re-checking findings from {verify_path}", Colors.CYAN)
        verified = VulnScanner.verify_report(verify_path, config)
        if not verified:
            log("[!] No findings to verify; exiting.", Colors.YELLOW)
            return 0
        out_path = verify_path.replace(".json", "_verified.json")
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

    # ── Explicit auto-login (--do-login) — runs BEFORE recon ──────────
    # so that authenticated endpoints are discovered during crawling.
    do_login_url = config.get("do_login")
    if do_login_url and config.get("login_username") and config.get("login_password"):
        from modules.utils import do_playwright_login
        extra_fields = {}
        for item in config.get("login_extra_fields", []):
            if "=" in item:
                k, v = item.split("=", 1)
                extra_fields[k.strip()] = v.strip()
        log(f"[*] Attempting auto-login at {do_login_url} ...", Colors.CYAN)
        session_cookies = do_playwright_login(
            login_url=do_login_url,
            username=config.get("login_username", ""),
            password=config.get("login_password", ""),
            username_field=config.get("login_username_field", "username"),
            password_field=config.get("login_password_field", "password"),
            extra_fields=extra_fields or None,
        )
        if session_cookies:
            existing = config.get("cookies", {})
            existing.update(session_cookies)
            config["cookies"] = existing
            log(f"[+] Login cookies injected — session authenticated "
                f"for {len(session_cookies)} cookies", Colors.GREEN)
        else:
            log("[!] Auto-login failed — continuing without "
                "authentication", Colors.YELLOW)

    all_findings = []
    run_all = "all" in config["modules"]
    disabled_modules = set(config.get("disable_modules", []))

    # ── Passive Import (HAR / Burp XML / Charles) ───────────────────────────
    passive_import_path = config.get("passive_import", "")
    if passive_import_path and os.path.isfile(passive_import_path):
        log(f"[*] Loading passive import: {passive_import_path}", Colors.CYAN)
        try:
            ext = os.path.splitext(passive_import_path)[1].lower()
            from modules.passive_import import BurpXmlImporter, HarImporter, CharlesImporter
            import_result = None
            if ext in (".xml",):
                import_result = BurpXmlImporter.import_xml(passive_import_path)
            elif ext in (".har", ".har.gz"):
                import_result = HarImporter.import_har(passive_import_path)
            elif ext in (".chls", ".chlsj"):
                import_result = CharlesImporter.import_session(passive_import_path)
            if import_result:
                imported = import_result.to_recon_dict()
                log(f"  [+] Imported {len(imported.get('urls', []))} URLs, "
                     f"{len(imported.get('forms', []))} forms, "
                     f"{len(imported.get('parameters', []))} params", Colors.GREEN)
                # Pre-populate recon_data so recon step can skip active crawling
                for key, val in imported.items():
                    if val:
                        if isinstance(val, list):
                            existing = set(recon_data.get(key, []))
                            recon_data[key] = list(existing | set(val))
                        elif isinstance(val, dict):
                            recon_data.setdefault(key, {}).update(val)
                        else:
                            recon_data.setdefault(key, val)
        except Exception as e:
            log(f"[!] Passive import failed: {e}", Colors.YELLOW)

    recon, recon_data = _run_recon_if_needed(
        config, _should_run_recon(config, run_all, disabled_modules), container=container
    )

    # ── External Intelligence Gathering (after recon, enriches recon_data) ──
    if not config.get("passive", False) and container and hasattr(container, 'external_intel'):
        try:
            log("[*] Gathering external intelligence...", Colors.CYAN)
            intel_data = container.external_intel.gather(config["target"], config)
            if intel_data:
                for key in ("subdomains", "urls", "js_urls"):
                    existing = set(recon_data.get(key, []))
                    new = set(intel_data.get(key, []))
                    if new:
                        recon_data[key] = list(existing | new)
                        log(f"  [+] {len(new)} additional {key} from external intel", Colors.GREEN)
        except Exception as e:
            log(f"[!] External intelligence failed: {e}", Colors.YELLOW)

    # ── Auto default-credential detection (after recon, before scans) ──
    # Enabled by default; opt out with --no-default-creds.
    # Detects login forms from recon data and tries common credentials.
    should_check = (
        config.get("check_default_creds", False)
        or (not config.get("no_default_creds", False)
            and not config.get("login_password"))
    )
    if should_check and not config.get("_default_cred_finding"):
        from modules.utils import try_default_credentials
        login_pages = _detect_login_pages(recon_data.get("forms", []), config["target"])
        if not login_pages and config.get("check_default_creds"):
            login_pages = [(config["target"], config["target"].rstrip("/") + "/login")]
        if login_pages:
            log(f"[*] Detected {len(login_pages)} login page(s) — "
                f"trying default credentials...", Colors.CYAN)
            extra_fields = {}
            for item in config.get("login_extra_fields", []):
                if "=" in item:
                    k, v = item.split("=", 1)
                    extra_fields[k.strip()] = v.strip()
            for li, (page_url, action_url) in enumerate(login_pages):
                log(f"  [{li+1}/{len(login_pages)}] {action_url}", Colors.CYAN)
                dcookies, duser, dpass = try_default_credentials(
                    login_url=action_url,
                    username_field=config.get("login_username_field", "username"),
                    password_field=config.get("login_password_field", "password"),
                    extra_fields=extra_fields or None,
                    verify_url=config.get("login_verify_url") or None,
                )
                if dcookies and duser and dpass:
                    existing = config.get("cookies", {})
                    existing.update(dcookies)
                    config["cookies"] = existing
                    config["_default_cred_finding"] = (duser, dpass)
                    log(f"[!] Default credentials WORK on {action_url}: "
                        f"{duser}:{dpass} — session injected, "
                        f"finding will be reported", Colors.RED)
                    break  # one working session is enough
            else:
                log("[*] No default credentials worked on any login page",
                    Colors.YELLOW)

    # ── JS Intelligence scan ─────────────────────────────────────────────
    js_data: dict = {
        "secrets": [], "endpoints": [], "hidden_endpoints": [],
        "routes": [], "env_vars": [], "hardcoded_values": [],
    }
    js_urls = recon_data.get("js_urls", [])
    run_js = (
        "all" in config["modules"] or "js_secrets" in config["modules"]
    ) and "js_secrets" not in disabled_modules and bool(js_urls) and not config.get("passive", False)

    js_findings: list[dict] = []
    if run_js:
        log("[*] Running JS Intelligence scan...", Colors.YELLOW)
        js_intel = JSIntelligence(base_url=config["target"], config=config, container=container)
        js_session = make_session(config)
        max_js = config.get("max_js_files", 50)
        urls_to_scan = js_urls[:max_js]
        if len(js_urls) > max_js:
            log(f"[!] {len(js_urls)} JS bundles found, scanning first {max_js} (--max-js-files to increase)",
                Colors.YELLOW)

        for url in urls_to_scan:
            resp = safe_get(js_session, url, timeout=config.get("timeout", 10), raise_for_status=False)
            if resp is None or resp.status_code >= 400:
                continue
            result = js_intel.analyze(resp.text, source_url=url)
            for key in ("secrets", "endpoints", "hidden_endpoints", "routes", "env_vars", "hardcoded_values"):
                js_data.setdefault(key, []).extend(result.get(key, []))

            # Generate findings from secrets found in this URL immediately
            for entry in result.get("secrets", []):
                if entry.get("confidence") == "none":
                    continue
                sev = entry.get("severity", "high")
                validated = entry.get("validated")
                if validated:
                    sev = "critical"
                f = finding(
                    vuln_type=f"Exposed JS Secret ({entry['type']})",
                    url=url,
                    severity=sev,
                    details=f"Secret type '{entry['type']}' found in JS file",
                    evidence=f"Match: {entry['value'][:40]}... Source: {url}",
                    verification_stage="verified" if validated else "detected",
                    request=_build_curl("GET", url, dict(js_session.headers), cookies=safe_cookies_dict(js_session.cookies)),
                    response_excerpt=resp.text[:1000],
                    steps_to_reproduce=[
                        f"Fetch the JS file at {url}",
                        f"Search the response for '{entry['type']}' patterns",
                        "Observe the exposed secret value",
                    ],
                )
                if f:
                    js_findings.append(f)

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

        secret_count = len(js_data.get("secrets", []))
        endpoint_count = len(js_data.get("endpoints", [])) + len(js_data.get("hidden_endpoints", []))
        log(f"[+] JS Intelligence scan complete: {secret_count} secrets, {endpoint_count} endpoints",
            Colors.GREEN)

    if config.get("dry_run"):
        secret_count = len(js_data.get("secrets", []))
        ep_count = len(recon_data.get("urls", []))
        form_count = len(recon_data.get("forms", []))
        subdomain_count = len(recon_data.get("subdomains", []))
        js_ep_count = len(js_data.get("endpoints", [])) + len(js_data.get("hidden_endpoints", []))
        log(f"\n{'─'*50}", Colors.CYAN)
        log("  DRY-RUN SUMMARY", Colors.BOLD)
        log(f"{'─'*50}", Colors.CYAN)
        log(f"  URLs:              {ep_count}", Colors.WHITE)
        log(f"  Forms:             {form_count}", Colors.WHITE)
        log(f"  Subdomains:        {subdomain_count}", Colors.WHITE)
        log(f"  JS Endpoints:      {js_ep_count}", Colors.WHITE)
        log(f"  JS Secrets:        {secret_count}", Colors.YELLOW if secret_count else Colors.WHITE)
        log(f"{'─'*50}\n", Colors.CYAN)
        return 0

    disabled_engines = config.get("disabled_engines", set())

    # ── Asset Graph (Initiative 6) ────────────────────────────────────────
    if "asset_graph" not in disabled_engines:
        try:
            log("[*] Building asset relationship graph...", Colors.CYAN)
            from engines.asset_graph import build_asset_graph
            api_endpoints = js_data.get("endpoints", []) + js_data.get("hidden_endpoints", [])
            api_urls = [ep.get("url", "") if isinstance(ep, dict) else str(ep) for ep in api_endpoints]
            asset_graph = build_asset_graph(
                target=config["target"],
                urls=recon_data.get("urls", []),
                subdomains=recon_data.get("subdomains", []),
                forms=recon_data.get("forms", []),
                js_urls=recon_data.get("js_urls", []),
                api_endpoints=api_urls,
            )
            config["asset_graph"] = asset_graph
            log(f"[+] Asset graph: {len(asset_graph.nodes)} nodes, {len(asset_graph.edges)} edges", Colors.GREEN)
        except Exception as e:
            log(f"[!] Asset graph build failed: {e}", Colors.YELLOW)

    # ── Scan Budget Engine (Initiative 5) ────────────────────────────────-
    if "scan_budget" not in disabled_engines and container:
        try:
            log("[*] Computing scan budget...", Colors.CYAN)
            budget = container.scan_budget_engine.build_budget(
                recon_data.get("urls", []),
                historical_data=None,
                capabilities=capabilities,
                asset_graph=config.get("asset_graph"),
            )
            config["scan_budget"] = budget
            log(f"[+] Budget: {budget.total_requests} total requests across {len(budget.allocation)} URLs, load={budget.system_load:.0%}", Colors.GREEN)
        except Exception as e:
            log(f"[!] Scan budget failed: {e}", Colors.YELLOW)

    all_findings_lock = threading.Lock()
    stop_autosave, autosave_thread = _start_autosave(
        config, recon_data, all_findings, all_findings_lock, js_data=js_data, container=container
    )
    try:
        run_scans(config, recon_data, recon, run_all, disabled_modules, all_findings, all_findings_lock, container=container, capabilities=capabilities)
    except KeyboardInterrupt:
        log("\n[!] Scan interrupted — saving partial report...", Colors.YELLOW)

    # Merge JS secret findings AFTER run_scans (so they appear after scanner findings)
    all_findings.extend(js_findings)

    # ── Convert to Finding instances for engine processing ───────────────
    all_findings = _findings_to_finding(config, all_findings, recon_data, js_data)

    # ── Default-credential finding ──────────────────────────────────────
    default_cred = config.pop("_default_cred_finding", None)
    if default_cred:
        duser, dpass = default_cred
        from modules.utils import finding
        dc_url = login_url or config["target"]
        df = finding(
            vuln_type="Default Credentials",
            url=dc_url,
            severity="critical",
            details=(
                f"The application accepts default / weak credentials: "
                f"**{duser}** / **{dpass}**. An attacker can use these "
                f"to gain authenticated access to the application."
            ),
            evidence=f"Working credentials: {duser}:{dpass}",
            verification_stage="verified",
            steps_to_reproduce=[
                f"Navigate to {dc_url}",
                f"Enter username: {duser}",
                f"Enter password: {dpass}",
                "Submit the form and observe successful login",
            ],
        )
        if df and not isinstance(df, Finding):
            df = Finding(df)
        if df:
            all_findings = [df] + all_findings  # prepend — most critical
            log(f"  [FOUND] [CRITICAL] Default Credentials @ {dc_url} "
                f"({duser}:{dpass})", Colors.RED)

    # ── Evidence Quality Scoring (Initiative 4) ──────────────────────────
    if "evidence_quality" not in disabled_engines and container:
        try:
            log("[*] Scoring evidence quality...", Colors.CYAN)
            for f in all_findings:
                quality_scores = container.evidence_quality_engine.assess_finding_evidence(f)
                from engines.evidence_quality import EvidenceQualityEngine
                q_reasons = EvidenceQualityEngine.quality_reasons(quality_scores)
                if q_reasons and f.finding_state != "submission_ready":
                    existing_reasons = getattr(f, "confidence_reasons", [])
                    if not isinstance(existing_reasons, list):
                        existing_reasons = []
                    for r in q_reasons:
                        if r not in existing_reasons:
                            existing_reasons.append(r)
                    object.__setattr__(f, "confidence_reasons", existing_reasons)
            log(f"[+] Evidence quality assessed for {len(all_findings)} findings", Colors.GREEN)
        except Exception as e:
            log(f"[!] Evidence quality scoring failed: {e}", Colors.YELLOW)

    # ── Historical finding correlation ───────────────────────────────────
    if not config.get("no_history", False) and all_findings:
        try:
            log("[*] Correlating findings against scan history...", Colors.CYAN)
            container_ev = container.evidence_engine if container else None
            correlate_findings(all_findings, config, evidence_engine=container_ev)
            log(f"[+] Historical correlation complete", Colors.GREEN)
        except Exception as e:
            log(f"[!] Historical correlation failed: {e}", Colors.YELLOW)

    # ── Replay cross-scan comparison ───────────────────────────────────
    if "replay" not in disabled_engines and container:
        try:
            # Build replay bundles for all findings so compare_across_scans has data
            for f in all_findings:
                container.replay_engine.build_bundle(f)
            history_filename = config.get("history_file", "scan_history.json")
            output_dir = config.get("output_dir", "reports")
            history_path = os.path.join(output_dir, history_filename) if not os.path.isabs(history_filename) else history_filename
            regressions = []
            if os.path.isfile(history_path):
                container.replay_engine.compare_across_scans(
                    all_findings, history_path, config.get("target", ""),
                )
                for f in all_findings:
                    rr = getattr(f, "replay_regression", None)
                    if rr and rr.get("changed"):
                        regressions.append({
                            "fingerprint": f.fingerprint,
                            "title": f.title,
                            "url": f.url,
                            "previous_scan": rr.get("previous_scan", ""),
                            "previous_timestamp": rr.get("previous_timestamp", ""),
                        })
            if regressions:
                log(f"[!] {len(regressions)} regression(s) detected — findings changed since last scan", Colors.RED)
                config["_regressions"] = regressions
            elif os.path.isfile(history_path):
                log("[*] No regressions detected", Colors.GREEN)
        except Exception as e:
            log(f"[!] Replay cross-scan comparison failed: {e}", Colors.YELLOW)

    # ── Investigation Engine (Initiative 2) ──────────────────────────────
    if "investigation" not in disabled_engines and container:
        try:
            low_conf = [f for f in all_findings if (f.confidence_score or 0) < 60]
            if low_conf:
                log(f"[*] Autonomous investigation: {len(low_conf)} findings below confidence threshold...", Colors.CYAN)
                results = container.investigation_engine.investigate_all(
                    all_findings,
                    budget_per_finding=10,
                    max_findings=15,
                )
                n_promoted = sum(
                    1 for rlist in results.values()
                    for r in rlist if r.success
                )
                if n_promoted:
                    log(f"[+] Investigation promoted {n_promoted} signals", Colors.GREEN)
        except Exception as e:
            log(f"[!] Investigation engine failed: {e}", Colors.YELLOW)

    # ── Attack Chain Detection (Initiative 1) ────────────────────────────
    if "attack_chains" not in disabled_engines and container:
        try:
            log("[*] Detecting attack chains...", Colors.CYAN)
            chain_engine = container.attack_chain_engine
            chains = chain_engine.analyze(
                all_findings,
                rdc_noise=config.get("rdc_noise", False),
                asset_graph=config.get("asset_graph"),
            )
            if chains:
                all_findings = chain_engine.annotate_findings(all_findings, chains)
                log(f"[+] Found {len(chains)} attack chains", Colors.GREEN)
                for c in chains:
                    log(f"  Chain: {c.description} (confidence: {c.overall_confidence:.0f}/100)", Colors.CYAN)
            else:
                log("[*] No attack chains detected", Colors.CYAN)
        except Exception as e:
            log(f"[!] Attack chain detection failed: {e}", Colors.YELLOW)

    # ── Finding Promotion Pipeline (Initiative 7) ────────────────────────
    if "promotion" not in disabled_engines:
        try:
            log("[*] Running finding promotion pipeline...", Colors.CYAN)
            from engines.promotion import FindingPromotionEngine
            all_findings = FindingPromotionEngine.promote_all(all_findings)
            pipeline_counts = FindingPromotionEngine.pipeline_stage_counts(all_findings)
            log(f"[+] Pipeline: {pipeline_counts}", Colors.GREEN)
        except Exception as e:
            log(f"[!] Finding promotion failed: {e}", Colors.YELLOW)

    # ── Duplicate Risk Estimation (Initiative 9) ─────────────────────────
    if "duplicate_risk" not in disabled_engines and container:
        try:
            log("[*] Estimating duplicate risk...", Colors.CYAN)
            risks = container.duplicate_risk_engine.estimate_all(all_findings)
            for f in all_findings:
                if f.fingerprint and f.fingerprint in risks:
                    risk = risks[f.fingerprint]
                    object.__setattr__(f, "duplicate_risk", risk.to_dict())
            n_novel = sum(
                1 for r in risks.values()
                if r.likelihood == "potentially_novel"
            )
            log(f"[+] Duplicate risk: {n_novel}/{len(risks)} potentially novel", Colors.GREEN)
        except Exception as e:
            log(f"[!] Duplicate risk estimation failed: {e}", Colors.YELLOW)

    # ── Impact Scoring (Initiative 3) ────────────────────────────────────
    if "impact" not in disabled_engines:
        try:
            log("[*] Assessing impact...", Colors.CYAN)
            from engines.impact import ImpactEngine
            asset_graph = config.get("asset_graph")
            for f in all_findings:
                assessment = ImpactEngine.assess(f, asset_graph=asset_graph)
                object.__setattr__(f, "impact_assessment", assessment.to_dict())
        except Exception as e:
            log(f"[!] Impact scoring failed: {e}", Colors.YELLOW)

    # ── Metrics Collection (Initiative 10) ───────────────────────────────
    if "metrics" not in disabled_engines and container:
        try:
            metrics = container.metrics_collector.collect(all_findings)
            config["_pipeline_metrics"] = metrics
            log(container.metrics_collector.summary_string(), Colors.CYAN)
            log("Per-vuln-type detection/validation breakdown:", Colors.CYAN)
            log(container.metrics_collector.per_vuln_type_table(), Colors.CYAN)
        except Exception as e:
            log(f"[!] Metrics collection failed: {e}", Colors.YELLOW)

    if autosave_thread:
        stop_autosave.set()
        autosave_thread.join(timeout=2)

    # ── Final status print if --status was requested ──────────────────────
    if config.get("status_print", False):
        config.setdefault("status", {})["phase"] = "complete"
        print_scan_status(config, all_findings=all_findings, recon_data=recon_data, phase="complete")

    return _write_report_and_summary(config, all_findings, recon_data, js_data=js_data, container=container)


if __name__ == "__main__":
    sys.exit(main())
