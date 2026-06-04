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

from modules.recon import Recon
from modules.scanner import VulnScanner
from modules.reporter import Reporter
from modules.utils import banner, log, Colors


def parse_args():
    parser = argparse.ArgumentParser(
        description="BugBounty Hunter - Automated vulnerability detector",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--config", "-C", help="Path to YAML configuration file")
    parser.add_argument("--target", "-t", help="Target URL (e.g. https://example.com)")
    parser.add_argument("--modules", "-m", nargs="+",
        choices=["recon", "xss", "sqli", "lfi", "ssrf", "open_redirect", "headers", "csrf", "dirb", "sensitive", "exposed_files", "clickjacking", "http_methods", "insecure_forms", "subdomain_takeover", "all"],
        default=["all"])
    parser.add_argument("--output", "-o", default="reports")
    parser.add_argument("--format", "-f", choices=["json", "html", "txt"], default="html")
    parser.add_argument("--threads", type=int, default=10)
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--cookies", "-c", default=None)
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
    parser.add_argument("--wordlist", help="Optional directory fuzzing wordlist path")
    parser.add_argument("--disable-modules", nargs="+",
        choices=["recon", "xss", "sqli", "lfi", "ssrf", "open_redirect", "headers", "csrf", "dirb", "sensitive", "exposed_files", "clickjacking", "http_methods", "insecure_forms", "subdomain_takeover"],
        default=[], help="Disable specific modules when scanning all or default modules")
    parser.add_argument("--module-param", action="append", default=[],
        help="Override module settings using module.key=value")
    parser.add_argument("--retries", type=int, default=3,
        help="HTTP retry attempts for transient failures")
    parser.add_argument("--autosave-interval", type=int, default=0,
        help="Autosave interim report every N seconds (0 = disabled)")
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("--passive", action="store_true")
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
    
    # Map YAML config keys to argument names
    yaml_to_arg = {
        'target': 'target',
        'output': 'output',
        'format': 'format',
        'threads': 'threads',
        'timeout': 'timeout',
        'cookies': 'cookies',
        'auth': 'auth',
        'proxy': 'proxy',
        'verify_ssl': 'verify_ssl',
        'crawl_depth': 'crawl_depth',
        'max_urls': 'max_urls',
        'delay': 'delay',
        'wordlist': 'wordlist',
        'retries': 'retries',
        'verbose': 'verbose',
        'passive': 'passive',
        'autosave_interval': 'autosave_interval',
    }
    
    # Apply config file values only if CLI arg was not explicitly set
    for yaml_key, arg_key in yaml_to_arg.items():
        if yaml_key in config_file:
            cli_value = getattr(cli_args, arg_key, None)
            # Only override if CLI didn't explicitly set it (check for defaults)
            if cli_value is None or (arg_key in ('threads', 'timeout', 'retries', 'crawl_depth', 'autosave_interval') and cli_value in (10, 2, 3, 0)):
                setattr(cli_args, arg_key, config_file[yaml_key])
    
    # Handle module-specific configuration
    if 'modules' in config_file:
        if isinstance(config_file['modules'], list):
            cli_args.modules = config_file['modules']
    
    if 'disable_modules' in config_file:
        if isinstance(config_file['disable_modules'], list):
            cli_args.disable_modules = config_file['disable_modules']
    
    # Handle headers from config (merge with CLI headers)
    if 'headers' in config_file and isinstance(config_file['headers'], dict):
        config_headers = [f"{k}:{v}" for k, v in config_file['headers'].items()]
        if cli_args.headers:
            cli_args.headers.extend(config_headers)
        else:
            cli_args.headers = config_headers
    
    # Handle module parameters
    if 'module_params' in config_file and isinstance(config_file['module_params'], dict):
        for module_name, params in config_file['module_params'].items():
            if isinstance(params, dict):
                for param_key, param_value in params.items():
                    cli_args.module_param.append(f"{module_name}.{param_key}={param_value}")
    
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
        "headers": custom_headers,
        "auth": args.auth,
        "proxy": args.proxy,
        "verify_ssl": getattr(args, "verify_ssl", True),
        "crawl_depth": args.crawl_depth,
        "max_urls": args.max_urls,
        "delay": args.delay,
        "wordlist": args.wordlist,
        "retries": args.retries,
        "autosave_interval": args.autosave_interval,
        "module_params": module_params,
        "verbose": args.verbose,
        "passive": args.passive,
        "timestamp": datetime.now().strftime("%Y%m%d_%H%M%S"),
    }


def main():
    banner()
    args = parse_args()
    
    # Load YAML config file if provided
    if args.config:
        log(f"Loading configuration from {args.config}", Colors.CYAN)
        config_file = load_config_file(args.config)
        args = merge_configs(args, config_file)
    
    # Validate that target is provided
    if not args.target:
        log("[!] Error: --target is required (or specify via --config file)", Colors.RED)
        sys.exit(1)
    
    config = build_config(args)

    os.makedirs(config["output_dir"], exist_ok=True)

    log(f"Target      : {config['target']}", Colors.CYAN)
    modules = config['modules']
    if 'all' in modules:
        modules = ['all']
    log(f"Modules     : {', '.join(modules)}", Colors.CYAN)
    if config.get('disable_modules'):
        log(f"Disabled    : {', '.join(config['disable_modules'])}", Colors.CYAN)
    log(f"Threads     : {config['threads']}", Colors.CYAN)
    log(f"Max URLs    : {config['max_urls']}", Colors.CYAN)
    log(f"Delay       : {config['delay']}s", Colors.CYAN)
    log(f"Mode        : {'Passive' if config['passive'] else 'Active'}", Colors.CYAN)
    log(f"Report      : {config['report_format'].upper()}\n", Colors.CYAN)

    all_findings = []
    run_all = "all" in config["modules"]
    disabled_modules = set(config.get("disable_modules", []))
    run_recon = (run_all and "recon" not in disabled_modules) or "recon" in config["modules"]

    if run_recon:
        log("[*] Starting Recon...", Colors.YELLOW)
        recon = Recon(config)
        recon_data = recon.run()
        log(f"[+] Discovered {len(recon_data.get('urls', []))} URLs, "
            f"{len(recon_data.get('subdomains', []))} subdomains", Colors.GREEN)
    else:
        recon_data = {"urls": [config["target"]], "subdomains": [], "forms": []}

    autosave_interval = config.get("autosave_interval", 0)
    all_findings_lock = threading.Lock()
    stop_autosave = threading.Event()
    autosave_thread = None

    def _start_autosave():
        reporter = Reporter(config, [], recon_data)
        while not stop_autosave.wait(autosave_interval):
            with all_findings_lock:
                reporter.findings = list(all_findings)
            try:
                reporter.generate(suffix="partial")
                log(f"[✓] Interim report autosaved", Colors.GREEN)
            except Exception as e:
                log(f"[!] Autosave failed: {e}", Colors.YELLOW)

    if autosave_interval > 0:
        autosave_thread = threading.Thread(target=_start_autosave, daemon=True)
        autosave_thread.start()

    if config["passive"]:
        log("[*] Passive mode — skipping active fuzzing.", Colors.YELLOW)
    else:
        scanner = VulnScanner(config, recon_data)

        active_modules = {
            "xss":                  scanner.scan_xss,
            "sqli":                 scanner.scan_sqli,
            "lfi":                  scanner.scan_lfi,
            "ssrf":                 scanner.scan_ssrf,
            "open_redirect":        scanner.scan_open_redirect,
            "headers":              scanner.scan_headers,
            "csrf":                 scanner.scan_csrf,
            "dirb":                 scanner.scan_directory_fuzz,
            "sensitive":            scanner.scan_sensitive_data,
            "exposed_files":        scanner.scan_exposed_files,
            "clickjacking":         scanner.scan_clickjacking,
            "http_methods":         scanner.scan_http_methods,
            "insecure_forms":       scanner.scan_insecure_forms,
            "subdomain_takeover":   scanner.scan_subdomain_takeover,
        }

        disabled_modules = set(config.get("disable_modules", []))
        for mod_name, mod_fn in active_modules.items():
            if mod_name in disabled_modules:
                log(f"[-] Skipping disabled module {mod_name.upper()}", Colors.CYAN)
                continue
            if run_all or mod_name in config["modules"]:
                log(f"[*] Running {mod_name.upper()} scan...", Colors.YELLOW)
                findings = mod_fn()
                if findings:
                    log(f"[!] {len(findings)} finding(s) from {mod_name.upper()}", Colors.RED)
                    with all_findings_lock:
                        all_findings.extend(findings)
                else:
                    log(f"[+] {mod_name.upper()} — nothing found", Colors.GREEN)

    if autosave_interval > 0:
        stop_autosave.set()
        if autosave_thread:
            autosave_thread.join(timeout=2)

    reporter = Reporter(config, all_findings, recon_data)
    try:
        report_path = reporter.generate()
        log(f"\n[✓] Report saved → {report_path}", Colors.GREEN)
    except Exception as e:
        log(f"\n[✗] Failed to save report: {e}", Colors.RED)
        return 1

    critical = [f for f in all_findings if f.get("severity") == "critical"]
    high     = [f for f in all_findings if f.get("severity") == "high"]
    medium   = [f for f in all_findings if f.get("severity") == "medium"]
    low      = [f for f in all_findings if f.get("severity") == "low"]

    log(f"\n{'─'*50}", Colors.CYAN)
    log(f"  SCAN SUMMARY", Colors.BOLD)
    log(f"{'─'*50}", Colors.CYAN)
    log(f"  Critical : {len(critical)}", Colors.RED   if critical else Colors.WHITE)
    log(f"  High     : {len(high)}",     Colors.RED   if high     else Colors.WHITE)
    log(f"  Medium   : {len(medium)}",   Colors.YELLOW if medium  else Colors.WHITE)
    log(f"  Low      : {len(low)}",      Colors.CYAN  if low      else Colors.WHITE)
    log(f"  Total    : {len(all_findings)}", Colors.BOLD)
    log(f"{'─'*50}\n", Colors.CYAN)

    return 0 if not critical and not high else 1


if __name__ == "__main__":
    sys.exit(main())
