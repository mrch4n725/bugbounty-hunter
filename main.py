#!/usr/bin/env python3
"""
BugBounty Hunter - Automated vulnerability scanner for bug bounty programs.
Usage: python main.py --target https://example.com [options]
"""

import argparse
import sys
import os
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
    parser.add_argument("--target", "-t", required=True, help="Target URL (e.g. https://example.com)")
    parser.add_argument("--modules", "-m", nargs="+",
        choices=["recon", "xss", "sqli", "lfi", "ssrf", "open_redirect", "headers", "all"],
        default=["all"])
    parser.add_argument("--output", "-o", default="reports")
    parser.add_argument("--format", "-f", choices=["json", "html", "txt"], default="html")
    parser.add_argument("--threads", type=int, default=10)
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--cookies", "-c", default=None)
    parser.add_argument("--headers", "-H", nargs="+", default=[])
    parser.add_argument("--crawl-depth", type=int, default=2)
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("--passive", action="store_true")
    return parser.parse_args()


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

    return {
        "target": args.target.rstrip("/"),
        "modules": args.modules,
        "output_dir": args.output,
        "report_format": args.format,
        "threads": args.threads,
        "timeout": args.timeout,
        "cookies": cookies,
        "headers": custom_headers,
        "crawl_depth": args.crawl_depth,
        "verbose": args.verbose,
        "passive": args.passive,
        "timestamp": datetime.now().strftime("%Y%m%d_%H%M%S"),
    }


def main():
    banner()
    args = parse_args()
    config = build_config(args)

    os.makedirs(config["output_dir"], exist_ok=True)

    log(f"Target      : {config['target']}", Colors.CYAN)
    log(f"Modules     : {', '.join(config['modules'])}", Colors.CYAN)
    log(f"Threads     : {config['threads']}", Colors.CYAN)
    log(f"Mode        : {'Passive' if config['passive'] else 'Active'}", Colors.CYAN)
    log(f"Report      : {config['report_format'].upper()}\n", Colors.CYAN)

    all_findings = []
    run_all = "all" in config["modules"]

    if run_all or "recon" in config["modules"]:
        log("[*] Starting Recon...", Colors.YELLOW)
        recon = Recon(config)
        recon_data = recon.run()
        log(f"[+] Discovered {len(recon_data.get('urls', []))} URLs, "
            f"{len(recon_data.get('subdomains', []))} subdomains", Colors.GREEN)
    else:
        recon_data = {"urls": [config["target"]], "subdomains": [], "forms": []}

    if config["passive"]:
        log("[*] Passive mode — skipping active fuzzing.", Colors.YELLOW)
    else:
        scanner = VulnScanner(config, recon_data)

        active_modules = {
            "xss":           scanner.scan_xss,
            "sqli":          scanner.scan_sqli,
            "lfi":           scanner.scan_lfi,
            "ssrf":          scanner.scan_ssrf,
            "open_redirect": scanner.scan_open_redirect,
            "headers":       scanner.scan_headers,
        }

        for mod_name, mod_fn in active_modules.items():
            if run_all or mod_name in config["modules"]:
                log(f"[*] Running {mod_name.upper()} scan...", Colors.YELLOW)
                findings = mod_fn()
                if findings:
                    log(f"[!] {len(findings)} finding(s) from {mod_name.upper()}", Colors.RED)
                    all_findings.extend(findings)
                else:
                    log(f"[+] {mod_name.upper()} — nothing found", Colors.GREEN)

    reporter = Reporter(config, all_findings, recon_data)
    report_path = reporter.generate()
    log(f"\n[✓] Report saved → {report_path}", Colors.GREEN)

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
