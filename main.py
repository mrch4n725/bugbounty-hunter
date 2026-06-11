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
from modules.utils import banner, log, Colors, ScopeEnforcer, safe_get, safe_post, same_domain, finding, make_session, build_role_sessions, reset_seen_findings, _build_curl, set_mask_sensitive_default, safe_cookies_dict, SecretValidator
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
        choices=["recon", "xss", "sqli", "lfi", "ssrf", "xxe", "ssti", "cmd_injection", "blind_xss", "open_redirect", "headers", "csrf", "dirb", "sensitive", "exposed_files", "clickjacking", "http_methods", "insecure_forms", "subdomain_takeover", "graphql", "idor", "js_secrets", "api", "rate_limiting", "openapi", "authorization", "cors", "jwt", "cms", "tech_specific", "business_logic", "auth_bypass", "smuggling", "all"],
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
        choices=["recon", "xss", "sqli", "lfi", "ssrf", "xxe", "ssti", "cmd_injection", "blind_xss", "open_redirect", "headers", "csrf", "dirb", "sensitive", "exposed_files", "clickjacking", "http_methods", "insecure_forms", "subdomain_takeover", "graphql", "idor", "js_secrets", "api", "rate_limiting", "openapi", "authorization", "cors", "jwt", "cms", "tech_specific", "business_logic", "auth_bypass", "smuggling"],
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
                 "duplicate_risk", "consensus", "metrics", "confidence",
                 "impact_escalation", "multi_account", "semantic_analyzer",
                 "ownership", "submission_readiness"],
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
    parser.add_argument("--audit-log", action="store_true", default=True,
        help="Enable per-request audit log (SQLite) in output directory (default: on)")
    parser.add_argument("--no-audit-log", action="store_false", dest="audit_log",
        help="Disable per-request audit log (SQLite)")
    parser.add_argument("--payload-db",
        help="Path to payload intelligence database (JSON)")

    # ── Programme Intelligence Integration ──────────────────────────────────
    parser.add_argument("--h1-username", default=None,
        help="HackerOne username (or set H1_USERNAME env var)")
    parser.add_argument("--h1-token", default=None,
        help="HackerOne API token (or set H1_TOKEN env var)")
    parser.add_argument("--bc-token", default=None,
        help="Bugcrowd API token (or set BC_TOKEN env var)")
    parser.add_argument("--list-programmes", action="store_true",
        help="Print all accessible programmes ranked by expected value and exit")
    parser.add_argument("--best-programme", action="store_true",
        help="Auto-select highest-scoring programme and set target to its top asset")
    parser.add_argument("--programme", default=None,
        help="Programme handle to pull scope and intel for this scan")
    parser.add_argument("--scope-strict", action="store_true",
        help="Abort if no programme intel available (prevents out-of-scope scanning)")
    parser.add_argument("--skip-likely-duplicates", action="store_true",
        help="Exclude likely duplicate findings from all report output")
    parser.add_argument("--force", action="store_true",
        help="Force scan despite high-saturation warning from programme intel")

    # ── IDOR / Authorisation Mode ───────────────────────────────────────────
    parser.add_argument("--mode", default=None,
        choices=["idor", "full", "recon"],
        help="Scan mode: idor (two-account IDOR only), full (all modules), recon (surface discovery only)")
    parser.add_argument("--session-a", default=None,
        help="Path to JSON session file for account A (the resource owner)")
    parser.add_argument("--session-b", default=None,
        help="Path to JSON session file for account B (the access tester)")
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
        "audit_log": getattr(args, "audit_log", True),
        "diff_scan": getattr(args, "diff_scan", ""),
        "h1_username": getattr(args, "h1_username", None) or os.environ.get("H1_USERNAME", ""),
        "h1_token": getattr(args, "h1_token", None) or os.environ.get("H1_TOKEN", ""),
        "bc_token": getattr(args, "bc_token", None) or os.environ.get("BC_TOKEN", ""),
        "list_programmes": getattr(args, "list_programmes", False),
        "best_programme": getattr(args, "best_programme", False),
        "programme": getattr(args, "programme", None),
        "scope_strict": getattr(args, "scope_strict", False),
        "skip_likely_duplicates": getattr(args, "skip_likely_duplicates", False),
        "force": getattr(args, "force", False),
        "mode": getattr(args, "mode", None),
        "session_a": getattr(args, "session_a", None),
        "session_b": getattr(args, "session_b", None),
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


_SCAN_MODULES = frozenset({
    "xss", "sqli", "lfi", "ssrf", "xxe", "ssti", "cmd_injection",
    "blind_xss", "open_redirect", "headers", "csrf", "dirb", "sensitive",
    "exposed_files", "clickjacking", "http_methods", "insecure_forms",
    "subdomain_takeover", "graphql", "idor", "api",
    "rate_limiting", "openapi", "authorization", "cors", "jwt", "cms",
    "tech_specific", "business_logic", "auth_bypass", "smuggling",
})

def _should_run_recon(config: dict, run_all: bool, disabled_modules: set) -> bool:
    if "recon" in disabled_modules:
        return False
    return (
        (run_all and "recon" not in disabled_modules)
        or "recon" in config["modules"]
        or "js_secrets" in config["modules"]
        or bool(set(config["modules"]) & _SCAN_MODULES)
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

    # SPA recon via Playwright (--spa-recon flag)
    if config.get("spa_recon") and config.get("target"):
        _run_spa_recon(config, recon_data)

    return recon, recon_data


def _run_spa_recon(config: dict, recon_data: dict) -> None:
    """Run headless browser SPA recon to discover JS-rendered routes,
    XHR/fetch API calls, config objects, and client-side parameters.

    Merges results into recon_data in-place.
    """
    try:
        from modules.recon_spa import HeadlessReconBrowser
    except ImportError:
        log("[!] SPA recon unavailable: modules.recon_spa not found", Colors.YELLOW)
        return

    spa_recon = HeadlessReconBrowser(config)
    if not spa_recon.start():
        log("[!] SPA recon unavailable: Playwright not installed or browser failed to launch",
            Colors.YELLOW)
        return

    try:
        target = config["target"]
        log("[*] Starting SPA spider...", Colors.CYAN)

        spider_results = spa_recon.spa_spider(start_url=target, max_clicks=30, max_depth=2)
        if spider_results:
            discovered_urls = spider_results.get("urls", [])
            discovered_forms = spider_results.get("forms", [])
            discovered_xhr = spider_results.get("xhr_calls", [])
            js_endpoints = spider_results.get("js_endpoints", [])
            tech_stack = spider_results.get("tech_stack", [])

            added_urls = 0
            for u in discovered_urls:
                if u not in recon_data.get("urls", []):
                    recon_data.setdefault("urls", []).append(u)
                    added_urls += 1
            for xhr in discovered_xhr:
                ep_url = xhr.get("url", "")
                if ep_url and ep_url not in recon_data.get("urls", []):
                    recon_data.setdefault("urls", []).append(ep_url)
                    added_urls += 1

            added_forms = 0
            for f in discovered_forms:
                if f not in recon_data.get("forms", []):
                    recon_data.setdefault("forms", []).append(f)
                    added_forms += 1

            if js_endpoints:
                for js_ep in js_endpoints:
                    ep_urls = js_ep.get("endpoints", [])
                    for eu in ep_urls:
                        if eu not in recon_data.get("urls", []):
                            recon_data.setdefault("urls", []).append(eu)
                            added_urls += 1

            api_endpoints = spider_results.get("api_endpoints", [])
            for ep in api_endpoints:
                ep_url = ep.get("url", "")
                if ep_url and ep_url not in recon_data.get("urls", []):
                    recon_data.setdefault("urls", []).append(ep_url)
                    added_urls += 1

            if tech_stack:
                recon_data.setdefault("technology", {}).setdefault("framework", []).extend(tech_stack)
                log(f"[+] SPA framework(s): {', '.join(tech_stack)}", Colors.CYAN)

            log(f"[+] SPA recon: {added_urls} URL(s), {added_forms} form(s) discovered",
                Colors.GREEN)

        spa_params = spa_recon.discover_runtime_params(target)
        if spa_params:
            log(f"[+] SPA runtime params: {len(spa_params)} discovered", Colors.CYAN,
                verbose_only=True, verbose=config.get("verbose", False))

    except Exception as e:
        log(f"[!] SPA recon error: {e}", Colors.YELLOW)
    finally:
        spa_recon.close()


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


def _findings_to_finding(config, all_findings, recon_data=None, js_data=None):
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

    # ── Programme Intelligence: --list-programmes / --best-programme ──────
    if config.get("list_programmes") or config.get("best_programme"):
        from modules.programme_intel import list_programmes_ranked, print_ranked_table
        h1_username = config.get("h1_username", "") or os.environ.get("H1_USERNAME", "")
        h1_token = config.get("h1_token", "") or os.environ.get("H1_TOKEN", "")
        bc_token = config.get("bc_token", "") or os.environ.get("BC_TOKEN", "")
        if not h1_username and not h1_token and not bc_token:
            print("Set H1_USERNAME/H1_TOKEN or BC_TOKEN environment variables to use programme intelligence")
            print("Without credentials, the scanner runs in standard mode without programme intel.")
            if config.get("list_programmes"):
                sys.exit(1)
        ranked = list_programmes_ranked(h1_username=h1_username, h1_token=h1_token, bc_token=bc_token)
        if not ranked:
            log("[!] No programmes found or API error", Colors.RED)
            sys.exit(1)
        if config.get("list_programmes"):
            print_ranked_table(ranked)
            sys.exit(0)
        if config.get("best_programme"):
            best = ranked[0]
            config["programme"] = best.handle
            config["programme_platform"] = best.platform
            log(f"[*] Best programme by expected value: {best.name} ({best.handle}, {best.platform})", Colors.GREEN)
            if best.in_scope_assets:
                top_asset = best.in_scope_assets[0].identifier
                if not config.get("target"):
                    config["target"] = top_asset
                    log(f"[*] Target set to top asset: {top_asset}", Colors.GREEN)

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

    # ── Programme Intelligence ────────────────────────────────────────────
    programme_intel = None
    programme_handle = config.get("programme", "")
    h1_username = config.get("h1_username", "") or os.environ.get("H1_USERNAME", "")
    h1_token = config.get("h1_token", "") or os.environ.get("H1_TOKEN", "")
    bc_token = config.get("bc_token", "") or os.environ.get("BC_TOKEN", "")
    scope_strict = config.get("scope_strict", False)
    programme_platform = config.get("programme_platform", "hackerone")

    if programme_handle:
        from modules.programme_intel import build_programme_intel as build_pi
        if programme_platform == "bugcrowd" and not bc_token:
            log("[!] Set BC_TOKEN environment variable to use Bugcrowd integration", Colors.RED)
            if scope_strict:
                sys.exit(1)
        elif programme_platform == "hackerone" and (not h1_username or not h1_token):
            log("[!] Set H1_USERNAME and H1_TOKEN environment variables to use HackerOne integration", Colors.RED)
            if scope_strict:
                sys.exit(1)
        else:
            try:
                programme_intel = build_pi(
                    handle=programme_handle,
                    platform=programme_platform,
                    h1_username=h1_username,
                    h1_token=h1_token,
                    bc_token=bc_token,
                )
            except Exception as e:
                log(f"[!] Programme intel load failed: {e}", Colors.YELLOW)
                if scope_strict:
                    sys.exit(1)
        if programme_intel is None and scope_strict:
            log("[!] --scope-strict set but no programme intel available — aborting", Colors.RED)
            sys.exit(1)
        if programme_intel:
            config["programme_intel"] = programme_intel
            log(f"[{programme_intel.platform.upper()}] Programme: {programme_intel.name}", Colors.CYAN)
            log(f"[{programme_intel.platform.upper()}] In-scope assets: {len(programme_intel.in_scope_assets)}  |  "
                f"Saturation: {programme_intel.saturation_score:.2f}", Colors.CYAN)
            if programme_intel.max_payout_critical or programme_intel.max_payout_high:
                log(f"[{programme_intel.platform.upper()}] Max payouts — "
                    f"Critical: ${programme_intel.max_payout_critical:,}  "
                    f"High: ${programme_intel.max_payout_high:,}  "
                    f"Medium: ${programme_intel.max_payout_medium:,}", Colors.CYAN)
            if programme_intel.recently_disclosed_weaknesses:
                log(f"[{programme_intel.platform.upper()}] Recently disclosed weaknesses: {', '.join(programme_intel.recently_disclosed_weaknesses[:5])}", Colors.CYAN)
            # ── Scope enforcement from programme data ─────────────────
            scope_enforcer = config.get("scope_enforcer")
            if scope_enforcer and hasattr(scope_enforcer, "load_from_programme_intel"):
                scope_enforcer.load_from_programme_intel(programme_intel)

    # ── Audit logger (default on, opt-out via --no-audit-log) ────────
    if config.get("audit_log", True) and container:
        try:
            al = container.audit_logger
            config["_audit_logger"] = al
            log("[*] Audit log enabled (SQLite)", Colors.CYAN)
        except Exception as e:
            log(f"[!] Failed to init audit logger: {e}", Colors.YELLOW)

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

    # ── IDOR Mode Dispatch ───────────────────────────────────────────────
    if config.get("mode") == "idor":
        from modules.idor_mode import run_idor_scan
        log("[*] IDOR mode: two-account authorisation testing", Colors.CYAN)
        config.setdefault("report_format", "html")
        config.setdefault("format", "html")
        all_findings = run_idor_scan(config)
        for f in all_findings:
            if "likely_duplicate" not in f:
                f["likely_duplicate"] = False
        config["status"]["findings_count"] = len(all_findings)
        log(f"\n[✓] IDOR scan complete — {len(all_findings)} finding(s)", Colors.GREEN)
        from modules.reporter import Reporter
        recon_data = {}
        try:
            adapted = [Finding.from_dict(f) if isinstance(f, dict) else f for f in all_findings]
            report_path = Reporter(config, adapted, recon_data).generate()
            log(f"\n[✓] Report: {report_path}", Colors.GREEN)
        except Exception as e:
            log(f"[!] Report generation failed: {e}", Colors.RED)
        return 0 if not all_findings else 1

    all_findings = []
    run_all = "all" in config["modules"]
    disabled_modules = set(config.get("disable_modules", []))

    # ── Passive Import (HAR / Burp XML / Charles) ───────────────────────────
    recon_data: dict = {}
    passive_import_path = config.get("passive_import", "")
    if passive_import_path and os.path.isfile(passive_import_path):
        log(f"[*] Loading passive import: {passive_import_path}", Colors.CYAN)
        try:
            ext = os.path.splitext(passive_import_path)[1].lower()
            from modules.passive_import import BurpXmlImporter, HarImporter, CharlesImporter, PostmanImporter
            import_result = None
            if ext in (".xml",):
                import_result = BurpXmlImporter.import_xml(passive_import_path)
            elif ext in (".har", ".har.gz"):
                import_result = HarImporter.import_har(passive_import_path)
            elif ext in (".chls", ".chlsj"):
                import_result = CharlesImporter.import_session(passive_import_path)
            elif ext in (".json",):
                import_result = PostmanImporter.import_collection(passive_import_path)
            if import_result:
                imported = import_result.to_recon_dict()
                log(f"  [+] Imported {len(imported.get('urls', []))} URLs, "
                     f"{len(imported.get('forms', []))} forms, "
                     f"{len(imported.get('parameters', []))} params", Colors.GREEN)
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

    recon, fresh_data = _run_recon_if_needed(
        config, _should_run_recon(config, run_all, disabled_modules), container=container
    )
    # Merge passive import data into fresh recon data (import URLs supplement, not replace)
    for key in ("urls", "subdomains", "forms", "js_urls"):
        imported_vals = recon_data.get(key, [])
        if imported_vals:
            existing = set(fresh_data.get(key, []))
            fresh_data[key] = list(existing | set(imported_vals))
    recon_data = fresh_data

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
                    config["_default_cred_url"] = action_url
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
        "feature_flags": [], "suspicious_patterns": [],
        "internal_apis": [], "graphql_endpoints": [],
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
            for key in ("secrets", "endpoints", "hidden_endpoints", "routes", "env_vars", "hardcoded_values",
                        "feature_flags", "suspicious_patterns", "internal_apis", "graphql_endpoints"):
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

            # Generate findings from tokens found in this URL
            seen_tokens: set[str] = set()
            for entry in result.get("tokens", []):
                tok_type = entry.get("type", "Token")
                tok_val = entry.get("value", "")[:60]
                tok_key = f"{tok_type}:{tok_val}"
                if tok_key in seen_tokens:
                    continue
                seen_tokens.add(tok_key)
                tok_sev = "high"
                tok_validated = False
                for label, klass in [("AWS Access Key", "aws_access_key"),
                                      ("GitHub Token", "github_token"),
                                      ("Firebase API Key", "firebase_api_key")]:
                    if tok_type.startswith(label):
                        try:
                            r = SecretValidator.validate(klass, tok_val.split()[0] if " " in tok_val else tok_val)
                            if r.get("valid") is True:
                                tok_validated = True
                                tok_sev = "critical"
                        except Exception:
                            pass
                        break
                ft = finding(
                    vuln_type=f"Exposed Token ({tok_type})",
                    url=url,
                    severity=tok_sev,
                    details=f"Token/credential of type '{tok_type}' exposed in JS file",
                    evidence=f"Type: {tok_type}, Value: {tok_val}... Source: {url}",
                    verification_stage="verified" if tok_validated else "detected",
                    request=_build_curl("GET", url, dict(js_session.headers), cookies=safe_cookies_dict(js_session.cookies)),
                    response_excerpt=resp.text[:1000],
                    steps_to_reproduce=[
                        f"Fetch the JS file at {url}",
                        f"Search the response for '{tok_type}' patterns",
                        "Observe the exposed token/credential value",
                    ],
                )
                if ft:
                    js_findings.append(ft)

            # Generate findings from hardcoded_values found in this URL
            for entry in result.get("hardcoded_values", []):
                hv_type = entry.get("type", "unknown")
                hv_match = entry.get("match", "")[:80]
                fhv = finding(
                    vuln_type=f"Hardcoded Sensitive Value ({hv_type})",
                    url=url,
                    severity="medium" if hv_type in ("private_ip", "localhost_ref") else "high",
                    details=f"Hardcoded sensitive value of type '{hv_type}' found in JS file",
                    evidence=f"Match: {hv_match}... Source: {url}",
                    verification_stage="detected",
                    request=_build_curl("GET", url, dict(js_session.headers), cookies=safe_cookies_dict(js_session.cookies)),
                    response_excerpt=resp.text[:1000],
                    steps_to_reproduce=[
                        f"Fetch the JS file at {url}",
                        f"Search the response for '{hv_type}' patterns",
                        "Observe the hardcoded sensitive value",
                    ],
                )
                if fhv:
                    js_findings.append(fhv)

            # Generate findings from suspicious_patterns found in this URL
            for entry in result.get("suspicious_patterns", []):
                sp_type = entry.get("type", "unknown")
                sp_match = entry.get("match", "")[:80]
                fsp = finding(
                    vuln_type=f"Suspicious Pattern ({sp_type})",
                    url=url,
                    severity="low",
                    details=f"Suspicious pattern '{sp_type}' found in JS file",
                    evidence=f"Match: {sp_match}... Source: {url}",
                    verification_stage="detected",
                    request=_build_curl("GET", url, dict(js_session.headers), cookies=safe_cookies_dict(js_session.cookies)),
                    response_excerpt=resp.text[:1000],
                    steps_to_reproduce=[
                        f"Fetch the JS file at {url}",
                        f"Search the response for '{sp_type}' patterns",
                        "Observe the suspicious content",
                    ],
                )
                if fsp:
                    js_findings.append(fsp)

            # Generate findings from feature_flags found in this URL
            for entry in result.get("feature_flags", []):
                ff_type = entry.get("type", "feature_flag")
                ff_match = entry.get("match", "")[:80]
                fff = finding(
                    vuln_type="Feature Flag Exposure",
                    url=url,
                    severity="low",
                    details="Feature flag / toggle reference found in JS file",
                    evidence=f"Type: {ff_type}, Match: {ff_match}... Source: {url}",
                    verification_stage="detected",
                    request=_build_curl("GET", url, dict(js_session.headers), cookies=safe_cookies_dict(js_session.cookies)),
                    response_excerpt=resp.text[:1000],
                    steps_to_reproduce=[
                        f"Fetch the JS file at {url}",
                        "Search the response for feature flag / toggle patterns",
                        "Observe the exposed feature flag",
                    ],
                )
                if fff:
                    js_findings.append(fff)

            # Generate findings from env_vars found in this URL
            for entry in result.get("env_vars", []):
                ev_var = entry.get("variable", "unknown")
                ev_ref = entry.get("reference", "process_env")
                ev_match = entry.get("match", "")[:80]
                fev = finding(
                    vuln_type="Environment Variable Reference",
                    url=url,
                    severity="low",
                    details=f"Environment variable '{ev_var}' referenced in JS file",
                    evidence=f"Variable: {ev_var}, Reference: {ev_ref}, Match: {ev_match}... Source: {url}",
                    verification_stage="detected",
                    request=_build_curl("GET", url, dict(js_session.headers), cookies=safe_cookies_dict(js_session.cookies)),
                    response_excerpt=resp.text[:1000],
                    steps_to_reproduce=[
                        f"Fetch the JS file at {url}",
                        f"Search the response for '{ev_var}' environment variable references",
                        "Observe the exposed env var reference",
                    ],
                )
                if fev:
                    js_findings.append(fev)

            # Inject internal_apis URLs into scan pool (same-domain only)
            for entry in result.get("internal_apis", []):
                ia_url = entry.get("url", "")
                if ia_url and same_domain(config["target"], ia_url):
                    if ia_url not in recon_data["urls"]:
                        recon_data["urls"].append(ia_url)

            # Inject graphql_endpoints URLs into scan pool (same-domain only)
            for entry in result.get("graphql_endpoints", []):
                ge_url = entry.get("url", "")
                if ge_url and same_domain(config["target"], ge_url):
                    if ge_url not in recon_data["urls"]:
                        recon_data["urls"].append(ge_url)

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

        # Inject discovered route paths into scan target list
        for entry in js_data.get("routes", []):
            route_path = entry.get("route", "")
            if route_path and route_path.startswith("/"):
                full_url = config["target"].rstrip("/") + route_path
                if same_domain(config["target"], full_url) and full_url not in recon_data["urls"]:
                    recon_data["urls"].append(full_url)

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

    # Build role sessions for authz testing (consumed by scanners + MultiAccountDiscovery)
    # Apply footprint profile BEFORE making any sessions so rps override takes effect
    if container and container.footprint_manager:
        _fp_profile = container.footprint_manager.get_profile()
        if _fp_profile:
            config["rps"] = _fp_profile.rps
            _fp_parts = []
            if _fp_profile.user_agent_rotation:
                _fp_parts.append("UA rotation")
            if _fp_profile.delay_jitter > 0:
                _fp_parts.append("jitter")
            _fp_suffix = f", {', '.join(_fp_parts)}" if _fp_parts else ""
            log(f"[*] Footprint profile: {_fp_profile.name} ({_fp_profile.rps} rps{_fp_suffix})", Colors.CYAN)
    base_session = make_session(config)
    # Apply footprint UA rotation + header randomization to the base session
    if container and container.footprint_manager:
        _fp_profile = container.footprint_manager.get_profile()
        if _fp_profile:
            from urllib.parse import urlparse as _up
            _target_domain = _up(config.get("target", "")).netloc.split(":")[0]
            container.footprint_manager.apply_to_session(base_session, _fp_profile, _target_domain)
    role_sessions = build_role_sessions(config, base_session=base_session)
    if len(role_sessions) >= 2:
        config["_role_sessions"] = role_sessions

    try:
        run_scans(config, recon_data, recon, run_all, disabled_modules, all_findings, all_findings_lock, container=container, capabilities=capabilities)
    except KeyboardInterrupt:
        log("\n[!] Scan interrupted — saving partial report...", Colors.YELLOW)

    # Merge JS secret findings AFTER run_scans (so they appear after scanner findings)
    all_findings.extend(js_findings)

    # ── Multi-Account Discovery ──────────────────────────────────────────
    if "multi_account" not in disabled_engines and container and container.multi_account_discovery:
        try:
            log("[*] Running multi-account discovery...", Colors.CYAN)
            from engines.multi_account_discovery import MultiAccountDiscoveryEngine
            mae = container.multi_account_discovery
            cross_account_findings = mae.run_cross_account_scan(recon_data, container.discovery_store)
            if cross_account_findings:
                converted = []
                for f_dict in cross_account_findings:
                    if isinstance(f_dict, dict):
                        converted.append(Finding.from_dict(f_dict))
                    else:
                        converted.append(f_dict)
                all_findings.extend(converted)
                log(f"[+] Multi-account discovery: {len(converted)} new authZ findings",
                    Colors.GREEN)
            else:
                log("[*] Multi-account discovery: no new findings", Colors.CYAN)
        except Exception as e:
            log(f"[!] Multi-account discovery failed: {e}", Colors.YELLOW)

    # ── Convert to Finding instances for engine processing ───────────────
    all_findings = _findings_to_finding(config, all_findings, recon_data, js_data)

    # ── Default-credential finding ──────────────────────────────────────
    default_cred = config.pop("_default_cred_finding", None)
    if default_cred:
        duser, dpass = default_cred
        from modules.utils import finding
        dc_url = config.get("_default_cred_url", "") or config["target"]
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

    # ── Cross-scan diff (--diff-scan) ────────────────────────────────────
    diff_scan_path = config.get("diff_scan", "")
    if diff_scan_path and os.path.isfile(diff_scan_path):
        try:
            log(f"[*] Comparing against previous scan: {diff_scan_path}", Colors.CYAN)
            from engines.diff import ScanDiffEngine
            new_findings = [f.to_dict() if hasattr(f, "to_dict") else dict(f) for f in all_findings]
            old_findings = []
            with open(diff_scan_path) as f:
                old_data = json.load(f)
            if isinstance(old_data, list):
                old_findings = old_data
            elif isinstance(old_data, dict):
                old_findings = old_data.get("findings", [])
            diff_result = ScanDiffEngine.diff(new_findings, old_findings)
            log(ScanDiffEngine.format_summary(diff_result), Colors.WHITE)
            config["_diff_result"] = diff_result
            if diff_result.regressed_findings:
                log(f"[!] {len(diff_result.regressed_findings)} regressed finding(s)",
                    Colors.RED)
        except Exception as e:
            log(f"[!] Cross-scan diff failed: {e}", Colors.YELLOW)

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

    # ── Business Logic Candidate Auto-Investigation ─────────────────────
    if "investigation" not in disabled_engines and container:
        bl_candidates = config.get("_business_logic_candidates", [])
        if bl_candidates and hasattr(container, 'investigation_engine'):
            try:
                ie = container.investigation_engine
                high_yield = [c for c in bl_candidates if c.yield_rank >= 0.5]
                for c in high_yield[:5]:
                    abuse_url = c.abuse_url or (c.workflow.source_urls or [""])[0]
                    log(f"[*] Auto-investigating biz-logic candidate: "
                        f"{c.workflow.category.value} @ {abuse_url} "
                        f"(yield={c.yield_rank:.2f})",
                        Colors.CYAN, verbose_only=True,
                        verbose=config.get("verbose", False))
                    results = ie.investigate_candidate(c, budget=5)
                    n_success = sum(1 for r in results if r.success)
                    if n_success:
                        log(f"  [+] {n_success}/{len(results)} investigation signals "
                            f"confirmed for {c.workflow.name}",
                            Colors.GREEN, verbose_only=True,
                            verbose=config.get("verbose", False))
            except Exception as e:
                log(f"[!] Business logic candidate investigation failed: {e}",
                    Colors.YELLOW, verbose_only=True,
                    verbose=config.get("verbose", False))

    # ── GQL Authorization Plan Investigation (real HTTP probes) ─────────
    if "investigation" not in disabled_engines and container:
        if hasattr(container, 'discovery_store'):
            try:
                ds = container.discovery_store
                plans = ds.get_by_category("gql_auth_plan")
                if plans:
                    log(f"[*] Investigating {len(plans)} GQL authorization plans with HTTP probes...",
                        Colors.CYAN)
                    gql_session = make_session(config)
                    gql_auth_findings: list[Finding] = []
                    investigated = 0
                    for plan in plans[:10]:
                        extra = plan.get("extra", {}) or {}
                        if isinstance(extra, str):
                            import json
                            try:
                                extra = json.loads(extra)
                            except (json.JSONDecodeError, TypeError):
                                extra = {}
                        confidence = extra.get("confidence", 0)
                        if confidence < 0.5:
                            continue
                        target_url = extra.get("target_url", "") or plan.get("source_url", "")
                        plan_type = extra.get("plan_type", "unknown")
                        gql_op = extra.get("gql_operation", "")
                        if not target_url:
                            continue
                        log(f"  [*] Probing {plan_type}: {gql_op} @ {target_url} "
                            f"(confidence={confidence:.2f})",
                            Colors.CYAN, verbose_only=True,
                            verbose=config.get("verbose", False))

                        # Build a type-appropriate GQL query based on plan type
                        is_mutation = any(kw in gql_op.lower() for kw in ("create", "update", "delete", "set", "add", "remove"))
                        if is_mutation:
                            if "role" in gql_op.lower() or plan_type == "role_escalation":
                                query_str = f"mutation {{ {gql_op}(role: \"admin\") {{ __typename }} }}"
                            else:
                                query_str = f"mutation {{ {gql_op}(id: 1) {{ __typename }} }}"
                        else:
                            selection = "{ __typename }"
                            if plan_type in ("cross_tenant", "ownership_violation"):
                                selection = "{ __typename id }"
                            query_str = f"{{ {gql_op} {selection} }}"
                        gql_payload = {"query": query_str}
                        headers = {"Content-Type": "application/json"}
                        resp = safe_post(gql_session, target_url,
                                         json=gql_payload, headers=headers,
                                         timeout=config.get("timeout", 10))
                        if resp is not None:
                            status = resp.status_code
                            resp_text = resp.text[:2000] if resp.text else ""
                            data_signal = '"data"' in resp_text[:500] or '__typename' in resp_text[:500]
                            error_signal = '"errors"' in resp_text[:500]
                            if status == 200 and data_signal and not error_signal:
                                gql_finding = Finding(
                                    vuln_type=f"GQL Auth Bypass ({plan_type})",
                                    url=target_url,
                                    severity="high" if "cross_tenant" in plan_type or "ownership" in plan_type else "medium",
                                    details=f"GQL authorization plan '{plan_type}' confirmed via probe. Operation: {gql_op}",
                                    evidence=f"Query: {query_str} — Status: {status}",
                                    verification_stage="validated",
                                    confidence_score=60,
                                    response_excerpt=resp_text[:500],
                                    reproduction_steps=[
                                        f"Send GQL query to {target_url}",
                                        f"Operation: {gql_op}",
                                        "Observe successful data return (200) with query results",
                                    ],
                                )
                                gql_finding.finding_state = FindingState.from_verification_stage("validated").value
                                gql_finding.evidence_strength = "moderate"
                                gql_finding.false_positive_risk = "medium"
                                gql_auth_findings.append(gql_finding)
                                log(f"    [FOUND] GQL Auth Bypass ({plan_type}) @ {target_url}",
                                    Colors.RED)
                            elif status == 200 and error_signal:
                                log(f"    [-] Query executed but returned errors (still accessible)",
                                    Colors.YELLOW, verbose_only=True,
                                    verbose=config.get("verbose", False))
                            elif status in (401, 403):
                                log(f"    [-] Protected (HTTP {status})",
                                    Colors.YELLOW, verbose_only=True,
                                    verbose=config.get("verbose", False))
                            else:
                                log(f"    [-] Unexpected HTTP {status}",
                                    Colors.YELLOW, verbose_only=True,
                                    verbose=config.get("verbose", False))
                        else:
                            log(f"    [!] No response from {target_url}",
                                Colors.YELLOW, verbose_only=True,
                                verbose=config.get("verbose", False))
                        investigated += 1

                    if gql_auth_findings:
                        log(f"[+] {len(gql_auth_findings)} GQL auth bypass(es) confirmed via probe",
                            Colors.RED)
                        all_findings.extend(gql_auth_findings)
                    elif investigated:
                        log(f"[-] {investigated} GQL auth plans probed — no bypass confirmed",
                            Colors.YELLOW, verbose_only=True,
                            verbose=config.get("verbose", False))
            except Exception as e:
                log(f"[!] GQL auth plan investigation failed: {e}", Colors.YELLOW,
                    verbose_only=True, verbose=config.get("verbose", False))

    # ── Feed investigation results back into DiscoveryStore ─────────────
    if "investigation" not in disabled_engines and container:
        if hasattr(container, 'discovery_store') and hasattr(container, 'object_harvester'):
            try:
                ds = container.discovery_store
                oh = container.object_harvester
                feed_count = 0
                for f in all_findings:
                    if (f.confidence_score or 0) >= 60 and f.verification_stage in ("validated", "verified", "exploitable"):
                        # Store confirmed endpoint as discovery resource
                        fp = oh._fingerprint(f.url)
                        ds_link = ds.get_by_fingerprint(fp, "confirmed_endpoint")
                        if not ds_link:
                            ds.store(
                                category="confirmed_endpoint",
                                value=f.url,
                                source_url=f.url,
                                extra=json.dumps({
                                    "vuln_type": f.vuln_type,
                                    "severity": f.severity,
                                    "verification_stage": f.verification_stage,
                                    "confidence": f.confidence_score,
                                })
                            )
                            feed_count += 1
                        # Extract and store numeric IDs from URL path
                        import re
                        ids_in_url = re.findall(r'/(\d{4,12})(?:/|$|[\?&#])', f.url)
                        for id_val in ids_in_url:
                            id_fp = oh._fingerprint(f"resource:{id_val}")
                            existing = ds.get_by_fingerprint(id_fp, "validated_resource")
                            if not existing:
                                ds.store(
                                    category="validated_resource",
                                    value=id_val,
                                    source_url=f.url,
                                    extra=json.dumps({"vuln_type": f.vuln_type})
                                )
                                feed_count += 1
                if feed_count:
                    log(f"[+] Investigation feedback: {feed_count} artifacts stored in DiscoveryStore",
                        Colors.GREEN, verbose_only=True,
                        verbose=config.get("verbose", False))
            except Exception as e:
                log(f"[!] Investigation feedback failed: {e}", Colors.YELLOW,
                    verbose_only=True, verbose=config.get("verbose", False))

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

    # ── HackerOne Duplicate Detection ────────────────────────────────────
    programme_intel = config.get("programme_intel")
    if programme_intel:
        try:
            from engines.cross_scan_dedup import is_likely_duplicate
            dup_count = 0
            for f in all_findings:
                is_dup, reason = is_likely_duplicate(f, programme_intel)
                if is_dup:
                    dup_count += 1
                    object.__setattr__(f, "likely_duplicate", True)
                    object.__setattr__(f, "duplicate_reason", reason)
            if dup_count:
                log(f"[H1] {dup_count} finding(s) flagged as likely duplicates against disclosed reports",
                    Colors.YELLOW)
        except Exception as e:
            log(f"[!] HackerOne duplicate detection failed: {e}", Colors.YELLOW)

    # ── Filter likely duplicates if --skip-likely-duplicates ──────────────
    if config.get("skip_likely_duplicates", False):
        before = len(all_findings)
        all_findings = [f for f in all_findings if not getattr(f, "likely_duplicate", False)]
        skipped = before - len(all_findings)
        if skipped:
            log(f"[H1] Skipped {skipped} likely duplicate(s) from report (--skip-likely-duplicates)",
                Colors.YELLOW)

    # ── Report blocked out-of-scope requests ──────────────────────────────
    scope_enforcer = config.get("scope_enforcer")
    if scope_enforcer and hasattr(scope_enforcer, "get_blocked_count"):
        blocked = scope_enforcer.get_blocked_count()
        if blocked:
            log(f"[Scope] {blocked} request(s) blocked (out of scope)", Colors.YELLOW)
            blocked_urls = scope_enforcer.get_blocked_urls()
            if blocked_urls:
                config["_blocked_urls"] = blocked_urls

    if autosave_thread:
        stop_autosave.set()
        autosave_thread.join(timeout=2)

    # ── Final status print if --status was requested ──────────────────────
    if config.get("status_print", False):
        config.setdefault("status", {})["phase"] = "complete"
        print_scan_status(config, all_findings=all_findings, recon_data=recon_data, phase="complete")

    exit_code = _write_report_and_summary(config, all_findings, recon_data, js_data=js_data, container=container)

    # ── Per-finding export (--per-finding-export) ─────────────────────────
    if config.get("per_finding_export"):
        try:
            from reporting.per_finding import PerFindingExporter
            per_dir = os.path.join(config["output_dir"], "findings")
            exporter = PerFindingExporter()
            high_conf = [f for f in all_findings if (f.confidence_score or 0) >= 40]
            paths = exporter.export_all(high_conf, per_dir)
            log(f"[+] Per-finding export: {len(paths)} pages → {per_dir}", Colors.GREEN)
        except Exception as e:
            log(f"[!] Per-finding export failed: {e}", Colors.YELLOW)

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
