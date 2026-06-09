<div align="center">

# BugBounty Hunter

**A high-discovery vulnerability scanner with first-class validation and evidence generation — built to find real vulnerabilities, automatically validate them, and package the results into submission-ready reports.**

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)

</div>

---

## Table of Contents

- [Overview](#overview)
- [How It Works](#how-it-works)
- [Quick Start](#quick-start)
- [Installation](#installation)
  - [Standard Install](#standard-install)
  - [Optional Dependencies](#optional-dependencies)
- [Usage Guide](#usage-guide)
  - [Basic Scan](#basic-scan)
  - [Common Workflows](#common-workflows)
  - [Authenticated Scanning](#authenticated-scanning)
  - [Dry-Run (Recon Only)](#dry-run-recon-only)
  - [Resume Interrupted Scan](#resume-interrupted-scan)
  - [Configuration File](#configuration-file)
- [CLI Reference](#cli-reference)
- [Modules](#modules)
- [Verification & Evidence](#verification--evidence)
  - [Finding Lifecycle](#finding-lifecycle)
  - [Out-of-Band (OOB) Confirmation](#out-of-band-oob-confirmation)
  - [Browser-Based XSS Validation](#browser-based-xss-validation)
  - [Live Secret Validation](#live-secret-validation)
- [Reports](#reports)
- [Scope Control](#scope-control)
- [Project Layout](#project-layout)
- [Extending](#extending)
- [FAQ](#faq)
- [Disclaimer](#disclaimer)

---

## Overview

BugBounty Hunter is a **high-discovery vulnerability scanner with first-class validation and evidence generation**. It does not force you to choose between a scanner and a reporting platform — it is both. The goal is to discover the maximum number of real vulnerabilities while automatically validating, documenting, and packaging findings into high-quality reports suitable for rapid triage and responsible disclosure.

It combines multithreaded reconnaissance, intelligence-led module selection, and multi-signal verification to produce findings that are ready for submission to HackerOne, Bugcrowd, or any bug bounty program — complete with curl reproduction commands, response excerpts, CVSS vectors, impact assessments, and step-by-step reproduction instructions.

Key capabilities:

- **27+ scan modules** — XSS, SQLi, SSTI, SSRF, XXE, Command Injection, Blind XSS, LFI, Open Redirect, CSRF, IDOR, GraphQL, API, JWT, CORS, and more
- **Evidence chain** — every finding progresses through Detection → Validation → Exploitation → Verification with confidence scoring
- **Out-of-band (OOB) confirmation** — SSRF, XXE, Command Injection, Blind XSS, and SQLi confirmed via DNS/HTTP callbacks (Interactsh / Burp Collaborator)
- **Browser-based XSS validation** — Playwright executes payloads in a headless Chromium instance and captures screenshots of successful execution
- **Intelligence-led scanning** — each URL is classified by signals (query params, path patterns, forms) and only relevant modules run
- **Scope enforcement** — every outbound request, including redirect chains, is validated against allowed targets
- **Canonical Finding model** — all findings normalized to the `Finding` dataclass with UUIDv7 identifiers, SHA-256 root-cause fingerprints, CVSS vectors, impact narratives, and remediation guidance
- **Submission-ready reports** — HTML, JSON, TXT, Markdown, HackerOne, and Bugcrowd formats with CVSS scoring, impact assessment, remediation guidance, structured evidence, and curl reproduction commands
- **Resume support** — interrupted scans can be resumed from their last checkpoint
- **Authenticated scanning** — cookie and header injection for session-based testing

---

## How It Works

The scanner operates in five phases:

```
Recon ──▶ Intelligence ──▶ Active Checks ──▶ Verification ──▶ Post-Scan ──▶ Report
```

1. **Reconnaissance** — Crawls the target, discovers URLs, forms, and query parameters; performs subdomain discovery; extracts JavaScript bundles and mines them for endpoints and secrets.

2. **Intelligence** — Technology fingerprinting (framework, CMS, language, WAF); JS AST analysis (regex-based with optional esprima); endpoint classification to determine which modules to run per URL.

3. **Active Checks** — Each discovered URL is classified by `classify_endpoint()` (signals: has query parameters, numeric parameters, URL parameters, forms, etc.) and only applicable modules run. Results are deduplicated by `(vuln_type, url, parameter)` fingerprint.

4. **Verification** — Findings are enriched with:
   - **OOB callbacks** — SSRF, XXE, CMDI, Blind XSS, SQLi confirmed via DNS/HTTP callback tokens
   - **Browser execution** — XSS payloads executed in headless Chromium with screenshot capture
   - **Live secret validation** — AWS keys tested against STS, GitHub tokens against the API, Slack tokens validated by format
   - **Multi-signal analysis** — SQLi requires 2+ independent signals (error, boolean, time, OOB) before Confirmed

5. **Post-Scan** — Findings pass through a pipeline: duplicate risk assessment, CVSS/impact narrative enrichment, pipeline metrics collection (funnel/bottleneck analysis), and regression comparison against previous scan outputs.

---

## Quick Start

```bash
git clone https://github.com/mrch4n725/bugbounty-hunter.git
cd bugbounty-hunter
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 main.py --target https://example.com

# One-command scan with sensible defaults
python3 main.py --target https://example.com --auto
```

`--auto` sets safe defaults (`rps=3`, `threads=5`, `autosave=60s`) and outputs a ChatGPT-optimized markdown report. Reports are written to `reports/` by default (override with `--output`).

---

## Installation

### Standard Install

| Platform | Prerequisites |
|----------|---------------|
| **Linux (Debian/Ubuntu)** | `sudo apt install python3 python3-pip git` |
| **Linux (Arch)** | `sudo pacman -S python python-pip git` |
| **macOS** | `brew install python git` or python.org installer |
| **Windows** | Python 3.10+ from python.org (add to PATH); Git optional |

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate          # Linux/macOS
# .venv\Scripts\activate           # Windows
pip install -r requirements.txt
```

Verify the install:

```bash
python3 main.py --help
```

### Optional Dependencies

| Package | Required For | Install |
|---------|-------------|---------|
| **Playwright** | Browser-based XSS execution validation (headless Chromium) + JavaScript-rendered crawling. Screenshots captured automatically on confirmed execution. | `pip install -r requirements-headless.txt && python3 -m playwright install chromium` |
| **esprima** | Enhanced JavaScript AST parsing for more accurate endpoint and secret extraction from minified bundles. Built-in regex fallback when absent. | `pip install esprima` |
| **boto3** | Live AWS key validation via STS `GetCallerIdentity`. | `pip install boto3` |

All optional dependencies have built-in fallbacks — the tool works fully without them.

---

## Usage Guide

### Basic Scan

```bash
python3 main.py --target https://example.com
```

This runs reconnaissance plus all applicable modules. Results appear in `reports/` as HTML (default) and autosaved JSON.

### Common Workflows

```bash
# Reconnaissance only (no active fuzzing)
python3 main.py --target https://example.com --passive

# Dry-run: recon + attack surface summary, then exit
python3 main.py --target https://example.com --dry-run

# Selective modules
python3 main.py --target https://example.com --modules xss sqli headers

# Exclude specific modules
python3 main.py --target https://example.com --disable-modules rate_limiting sensitive

# Common modules for quick assessment
python3 main.py --target https://example.com \
  --modules xss sqli lfi ssrf headers clickjacking exposed_files

# Full output formats
python3 main.py --target https://example.com --format hackerone
python3 main.py --target https://example.com --format bugcrowd
python3 main.py --target https://example.com --format json

# High-speed scan
python3 main.py --target https://example.com --threads 20 --rps 10

# Stealth mode (slow, randomized)
python3 main.py --target https://example.com --stealth

# Use legacy scanner architecture (opt-out, not recommended)
python3 main.py --target https://example.com --legacy-scanners
```

### Authenticated Scanning

```bash
# Cookie-based authentication
python3 main.py --target https://example.com \
  --cookies "session=eyJ...; csrf=abc123"

# Custom headers (repeatable)
python3 main.py --target https://example.com \
  --headers "Authorization: Bearer eyJ..." "X-CSRF-Token: abc123"

# Basic authentication
python3 main.py --target https://example.com --auth admin:password123

# Two-account IDOR testing (horizontal privilege escalation)
python3 main.py --target https://example.com \
  --cookies "session=USER_A_TOKEN" \
  --cookies-alt "session=USER_B_TOKEN"

# Multi-role authorization testing (Phase 5)
python3 main.py --target https://example.com \
  --role user_a \
  --auth-header user_b:'Authorization:Bearer tok_b' \
  --auth-header admin:'Cookie:session=admin'

# Full authenticated scan
python3 main.py --target https://example.com \
  --cookies "session=valid_token" \
  --headers "Authorization: Bearer jwt_token" \
  --headers "X-CSRF: abc123" \
  --threads 5
```

### Dry-Run (Recon Only)

Use `--dry-run` to see the attack surface before committing to active fuzzing:

```bash
python3 main.py --target https://example.com --dry-run
```

This runs reconnaissance and JavaScript intelligence, then prints a summary:

```
[DRY-RUN] Attack Surface Summary
─────────────────────────────────
  URLs discovered:    142
  Forms found:        18
  Subdomains found:   5
  JS endpoints:       37
  JS secrets:         3
```

### Resume Interrupted Scan

If a scan is interrupted (Ctrl+C, crash, timeout), resume it:

```bash
python3 main.py --target https://example.com --resume
```

This reads `.scan_state.json` from the current directory and skips previously completed URLs. Only URLs that were not processed are re-scanned.

### Configuration File

All CLI options can be specified in a YAML config file:

```bash
python3 main.py --config config.yaml
```

CLI flags override config file values. See `config.example.yaml` for all available options.

```yaml
target: https://example.com
output: reports
format: html
threads: 10
timeout: 10
crawl_depth: 2
max_urls: 200
rps: 5.0
verbose: false
passive: false

headers:
  Authorization: "Bearer token_here"
  User-Agent: "CustomUserAgent/1.0"

module_params:
  sqli:
    time_threshold: 5
    error_threshold: 3
  xss:
    encode_payloads: true
```

---

## CLI Reference

| Flag | Default | Description |
|------|---------|-------------|
| `--target`, `-t` | — | Target URL (required unless set in config) |
| `--config`, `-C` | — | YAML configuration file |
| `--modules`, `-m` | `all` | Modules to run (space-separated list) |
| `--disable-modules` | — | Modules to skip when running `all` |
| `--output`, `-o` | `reports` | Report output directory |
| `--format`, `-f` | `html` | Output format: `html`, `json`, `txt`, `markdown-report`, `hackerone`, `bugcrowd`, `chatgpt` |
| `--threads` | `10` | Number of concurrent worker threads |
| `--timeout` | `10` | HTTP request timeout in seconds |
| `--crawl-depth` | `2` | Recon crawl depth (0 = target only) |
| `--max-urls` | `200` | Maximum URLs to collect during recon |
| `--delay` | `0` | Static delay between requests in seconds |
| `--cookies`, `-c` | — | Cookie header string (e.g. `"session=abc; csrf=xyz"`) |
| `--cookies-alt` | — | Second account cookies for horizontal IDOR testing |
| `--headers`, `-H` | — | Custom HTTP headers (repeatable) |
| `--auth` | — | Basic auth credentials (`user:pass`) |
| `--proxy` | — | HTTP/HTTPS proxy URL |
| `--no-verify-ssl` | off | Disable SSL/TLS certificate verification |
| `--wordlist` | — | Path to wordlist for directory fuzzing (beyond built-in paths) |
| `--oob-host` | — | OOB callback host (Interactsh URL or Burp Collaborator) |
| `--headless` | off | Enable Playwright headless browser for JS-rendered crawling |
| `--rps` | `5.0` | Requests per second (auto-halved on 429, restored after 20 OK) |
| `--stealth` | off | Rotate 20 User-Agent strings, random 0.5–2s delay, shuffle POST params |
| `--scope` | — | Path to scope file (one domain/IP/CIDR per line) |
| `--exclude-patterns` | — | Regex patterns for URL exclusion (e.g. `/logout` `\.pdf$`) |
| `--include-paths` | — | Regex patterns for URL inclusion (all others excluded) |
| `--verify-only`, `-V` | — | Re-verify unconfirmed findings from a previous JSON report |
| `--resume` | off | Resume scan from `.scan_state.json` |
| `--module-param` | — | Module-specific overrides (`module.key=value`) |
| `--retries` | `3` | HTTP retry attempts |
| `--autosave-interval` | `0` | Autosave partial report every N seconds |
| `--no-rich` | off | Disable Rich terminal output (plain text for CI/pipe) |
| `--max-js-files` | `50` | Maximum JS files to scan for secrets/endpoints |
| `--no-mask-curl` | off | Show sensitive headers (Authorization, Cookie, etc.) in curl commands |
| `--dry-run` | off | Recon + attack surface summary only; skip all active fuzzing |
| `--passive` | off | No active fuzzing (headers, recon, and passive checks only) |
| `--status` | off | Show detailed scan status: pre-scan config summary, periodic progress every 25 URLs, and final findings-by-severity report. |
| `--role` | — | Current user role name for authorization testing (e.g. `user_a`, `admin`) |
| `--auth-header` | — | Auth header for a role in format `role_name:Header:Value` (repeatable). E.g. `--auth-header user_b:'Authorization:Bearer tok_b'` |
| `--auto` | off | Auto mode: sensible defaults for a quick scan (`rps=3`, `threads=5`, `autosave=60s`, `format=chatgpt`). Single-command convenience — just `python main.py --target https://x.com --auto`. |
| `--legacy-scanners` | off | Fall back to legacy inline scanner logic in `modules/scanner.py` (not recommended; ScannerBase is the default). |
| `--verbose`, `-v` | off | Per-request and per-finding diagnostic output |

---

## Modules

| Module | CLI Name | Type | Description |
|--------|----------|------|-------------|
| Recon | `recon` | Setup | Crawler, subdomain DNS, robots/sitemap, JS intelligence |
| XSS | `xss` | Per-URL | Context-aware reflected XSS (HTML/attribute/JS/URL contexts) with Playwright execution verification and screenshot capture |
| SQLi | `sqli` | Per-URL | Error-based, boolean-based, time-based blind, and OOB callback — requires 2+ signals for Confirmed, OOB for Verified |
| LFI | `lfi` | Per-URL | Path traversal and local file inclusion detection |
| SSRF | `ssrf` | Per-URL | OOB callback + cloud metadata endpoint verification |
| XXE | `xxe` | Per-URL | In-band file read, error-based leak, OOB blind XXE via callback |
| SSTI | `ssti` | Per-URL | 4-stage template injection detection (arithmetic evaluation, command execution) |
| Command Injection | `cmd_injection` | Per-URL | Output-based (`uid=`), time-based (≥5s delay), OOB callback (nslookup/curl) |
| Blind XSS | `blind_xss` | Target-level | Inject OOB-payload into forms/params; poll for callback from admin browser |
| Open Redirect | `open_redirect` | Per-URL | Redirect parameter abuse with external domain detection |
| Headers | `headers` | Target-level | Missing security headers, server disclosure, CORS (origin reflection), cookie analysis, subdomain scan |
| CSRF | `csrf` | Per-URL | POST forms without anti-CSRF tokens |
| Directory Fuzz | `dirb` | Target-level | Common paths (200 = exposed, 403/401 = access control info); optional wordlist |
| Sensitive Data | `sensitive` | Per-URL | Secret pattern detection in page bodies + live validation (AWS, GitHub, Slack, Twilio) |
| Exposed Files | `exposed_files` | Target-level | `.env`, `.git/HEAD`, backups, configuration files |
| Clickjacking | `clickjacking` | Target-level | Missing `X-Frame-Options` / CSP `frame-ancestors` |
| HTTP Methods | `http_methods` | Per-URL | Dangerous HTTP methods via `Allow` header analysis |
| Insecure Forms | `insecure_forms` | Per-URL | HTTP action URLs, cross-origin password submission |
| Subdomain Takeover | `subdomain_takeover` | Target-level | Dangling CNAME / SaaS service fingerprints |
| GraphQL | `graphql` | Target-level | Introspection, query batching, alias amplification, SQLi/XSS via GraphQL |
| IDOR (Parameter) | `idor` | Per-URL | Numeric/UUID parameter mutation and horizontal privilege escalation |
| IDOR (Path) | `idor_path` | Target-level | Path-based IDOR via parameter mutation across discovered routes |
| API | `api` | Target-level | OpenAPI/Swagger discovery, REST endpoint fuzzing, mass assignment, BOLA |
| JS Secrets | `js_secrets` | Target-level | Regex + AST secret extraction from JavaScript bundles (integrated into recon) |
| Rate Limiting | `rate_limiting` | Target-level | Tests endpoint rate limiting by rapid sequential requests (runs once per host, not per URL) |

**Module types** — Per-URL modules run only on URLs where they are applicable (determined by `classify_endpoint()`). Target-level modules run once per target regardless of URL count.

Use `--modules all` (default) or list specific modules. Disable selectively with `--disable-modules`.

---

## Verification & Evidence

### Finding Lifecycle

Every finding progresses through four stages:

```
Detected ──▶ Validated ──▶ Exploitable ──▶ Verified
```

| Stage | Detection | Validation | Exploitation | Confidence | Evidence |
|-------|-----------|------------|--------------|------------|----------|
| **Detected** | ✓ | — | — | 25 | Weak |
| **Validated** | ✓ | ✓ | — | 60 | Moderate |
| **Exploitable** | ✓ | ✓ | ✓ | 100 | Strong |
| **Verified** | ✓ | ✓ | ✓ | 100 | Verified |

- **Detected** — Payload reflected, error triggered, or header missing
- **Validated** — Multiple independent signals confirm the vulnerability (e.g., time delay + error for SQLi)
- **Exploitable** — Demonstrated real-world impact (file read, command output, XSS in browser)
- **Verified** — Confirmed via strong evidence: OOB callback received, Playwright screenshot captured, or live API call to cloud provider

### Out-of-Band (OOB) Confirmation

SSRF, XXE, Command Injection, Blind XSS, and SQLi support OOB callback verification:

1. A unique callback token is generated per test (e.g., `hostname`.oob.example.com)
2. The payload triggers the target to make a DNS or HTTP request to the callback URL
3. The scanner polls for the callback; if received, the finding is promoted to **Verified**
4. OOB-confirmed findings include the callback evidence and a curl command in the report

Enable with `--oob-host https://your-instance.oastify.com` (Interactsh, Burp Collaborator, or any DNS/HTTP callback server).

### Browser-Based XSS Validation

XSS findings can be validated and captured using Playwright (headless Chromium):

1. A confirming request is sent with the XSS payload
2. If the payload is reflected in the response, Playwright loads the page (with `goto()` for GET or `set_content()` for POST)
3. Playwright checks for `alert()` execution and DOM mutations
4. On successful execution, a full-page PNG screenshot is captured
5. The finding is promoted to **Verified** with the screenshot embedded in the HTML report

Install with:

```bash
pip install -r requirements-headless.txt
python3 -m playwright install chromium
```

Browser validation is optional — the scanner runs fine without it, reporting XSS as **Detected** instead of **Verified**.

### Scanner Architecture (Default: ScannerBase)

BugBounty Hunter uses the `ScannerBase`-based architecture by default (all 25 scanners)
with typed evidence, lifecycle phases, and EvidenceEngine integration:

1. **5-phase lifecycle** — Each scanner implements `detect → validate → collect_evidence → generate_reproduction → calculate_confidence`
2. **Typed evidence** — `HttpRequestEvidence`, `BrowserExecutionEvidence`, `TimingEvidence`, `OOBCallbackEvidence`, etc. render as structured blocks in reports (HackerOne, Bugcrowd, HTML)
3. **EvidenceEngine integration** — Evidence is content-fingerprinted (SHA-256), deduplicated, and linked to findings. Reporters automatically enrich findings with linked evidence

To fall back to the legacy inline scanner logic:

```bash
python3 main.py --target https://example.com --legacy-scanners
```

### Live Secret Validation

Discovered credentials are validated against live APIs before reporting:

| Secret Type | Validation Method |
|-------------|------------------|
| AWS Access Key | STS `GetCallerIdentity` (via boto3) |
| GitHub Token | `GET /user` on api.github.com |
| Slack Token | Format validation (xoxp-/xoxb-) |
| Twilio SID | Offline format + entropy validation |

Only validated secrets appear in findings. Invalid or unverifiable secrets are filtered.

---

## Reports

Every report format now computes **CVSS score + vector**, **impact narrative**, and **remediation guidance** per finding — even for findings from the legacy scanner that lacked these fields. The canonical `Finding` dataclass supports structured evidence via `EvidenceBase` polymorphic subclasses, UUIDv7 identifiers, and SHA-256 root-cause fingerprints for deduplication.

| Format | Contents |
|--------|----------|
| **HTML** | Dark-themed dashboard with severity summary, verified badges, finding cards with collapsible evidence blocks, CVSS score + rating, impact narrative, remediation guidance, screenshot display, and one-click curl copy |
| **JSON** | Full structured scan result with CVSS, impact, remediation, and tool metadata for programmatic processing |
| **TXT** | Plain-text CVSS + impact + remediation per finding, with structured evidence blocks |
| **Markdown** (`markdown-report`) | Per-finding `.md` files with CVSS vector + score + rating, impact narrative, remediation guidance, structured evidence, and curl reproduction commands |
| **ChatGPT** (`chatgpt`) | Single-file markdown optimized for LLM ingestion — YAML frontmatter, consistent per-finding sections, colon-delimited fields, raw JSON data block for structured parsing. One copy-paste into ChatGPT. Auto-selected by `--auto`. |
| **HackerOne** (`hackerone`) | Submission-optimized format: evidence blocks → CVSS vector → component → parameter → verification stage → FP risk → summary → affected URLs → evidence → request → response → impact → remediation → reproduction steps |
| **Bugcrowd** (`bugcrowd`) | CVSS vector in finding summary table plus per-finding detail with evidence, verification stage, impact, and remediation |

Root-cause grouping can be enabled via config (`--module-param reporter.group_by_root_cause=true`) to group findings by their root-cause fingerprint. Enriched findings include `grouped_urls`, `group_severity`, and `group_verification_stage` fields used by HackerOne and Bugcrowd reporters.

All report output is self-XSS safe — `html.escape()` applied to every user-provided field at render time, and copy buttons use a single delegated event listener (`no onclick=` attributes).

Additional report features:

- **One-click curl copy** — each finding card has a copy button for the curl reproduction command
- **Screenshot embedding** — Playwright-confirmed XSS findings include the full-page screenshot
- **JSON-LD structured data** — every HTML report includes `<script type="application/ld+json">` block with all finding data for LLM parsing (ChatGPT, Claude)
- **Interim autosave** — `--autosave-interval N` saves partial reports every N seconds (`.partial` suffix)
- **Live findings counter** — a background thread reports `[Live] N findings (M confirmed)` every 30 seconds
- **Rich progress bar** — live ETA, findings counter, current module/URL display during both target-level module execution (`ModuleProgress`) and per-URL scanning (`ScanProgress`). Falls back to plain text with `--no-rich`.
- **Real-time output** — `[FOUND] [severity] title @ url` for each new finding as it's discovered
- **Keyboard interrupt safe** — Ctrl+C saves all findings collected so far with no data loss
- **Regression detection** — findings flagged as regressions from prior scans are highlighted with `[!] N regression(s) detected` in terminal output; stored in `config["_regressions"]` for downstream tools
- **Pipeline metrics** — post-scan pipeline funnel printed: signals → potential → validated → verified → submission ready, including validation/submission rates and bottleneck stage (`--disable-engines metrics` to opt out)

**Exit codes:**

| Code | Meaning |
|------|---------|
| `0` | Scan finished; no critical or high findings |
| `1` | One or more critical or high findings |

---

## Scope Control

Limit scan scope with regex patterns:

**Config file:**

```yaml
exclude_patterns:
  - "/logout"
  - "\\.pdf$"
  - "^/cdn/"
include_paths:
  - "^/api/"
  - "^/graphql"
```

**CLI:**

```bash
# Skip matching URLs
--exclude-patterns "/logout" "\\.pdf$"

# Only test matching URLs
--include-paths "^/api/" "^/app/"
```

**Scope file** (one entry per line):

```
example.com
*.example.com
192.168.1.0/24
```

```bash
python3 main.py --target https://app.example.com --scope scope.txt
```

Patterns are matched against the full URL. Out-of-scope URLs are logged and skipped. Scope is enforced on every outbound request, including redirect chains.

---

## Project Layout

```
bugbounty-hunter/
├── main.py                          # CLI entry point, orchestration, module dispatch
├── config.example.yaml              # Sample YAML configuration
├── requirements.txt                 # Core Python dependencies
├── requirements-headless.txt        # Playwright (optional)
├── AGENTS.md                        # Architecture guide for AI agents & contributors
├── download.py                      # Payload list download helper
├── payloads/
│   ├── xss.yaml                     # XSS test payloads
│   └── sqli.yaml                    # SQL injection test payloads
├── modules/
│   ├── __init__.py
│   ├── utils.py                     # finding(), _build_curl(), RateLimiter, OOBDetectionFramework,
│   │                                # BrowserValidator, SecretValidator, classify_endpoint(),
│   │                                # safe_get/safe_post, DeduplicationEngine, build_role_sessions()
│   ├── recon.py                     # Recon — crawler, subdomain discovery, JS intelligence
│   ├── scanner.py                   # VulnScanner — 25+ scan methods, chain analysis, _add()
│   ├── api_scanner.py               # ApiScanner — OpenAPI/Swagger, REST fuzzing, BOLA, mass assignment,
│   │                                # GraphQL auth bypass, query depth attacks
│   ├── idor.py                      # IdorScanner — parameter mutation, horizontal escalation,
│   │                                # ownership validation (role-based)
│   ├── js_intelligence.py           # JSIntelligence — AST + regex endpoint/secret extraction
│   └── reporter.py                  # Legacy wrapper — delegates to reporting/ package
├── models/
│   ├── __init__.py
│   ├── finding.py                   # Canonical Finding dataclass (UUIDv7, SHA-256 fingerprints, enums)
│   ├── evidence.py                  # EvidenceBase + 10 polymorphic subclasses
│   └── config.py                    # ScanConfig typed dataclass
├── engines/
│   ├── __init__.py
│   ├── validation_engine.py         # Centralized OOB, browser, timing, secret, auth, GraphQL validation
│   └── evidence_engine.py           # Evidence storage, linking, snapshot/restore
├── scanners/
│   ├── __init__.py
│   ├── base.py                      # ScannerBase — shared lifecycle (detect/validate/collect/reproduce/confidence)
│   ├── xss.py                       # XSSScanner — context-aware XSS with browser validation (Level 4)
│   └── headers.py                   # HeadersScanner — security header analysis (Level 2)
├── reporting/
│   ├── __init__.py
│   ├── base.py                      # ReporterBase — shared utilities, impact analysis, root-cause grouping
│   ├── html.py                      # HTMLReporter — dark-themed dashboard with Chart.js
│   ├── json_report.py               # JSONReporter — structured output
│   ├── txt.py                       # TXTReporter — plain-text summary
│   ├── markdown.py                  # MarkdownReporter — per-finding .md files
│   ├── chatgpt.py                   # ChatGPTReporter — single-file LLM-optimized report
│   ├── hackerone.py                 # HackerOneReporter — submission-ready format
│   └── bugcrowd.py                  # BugcrowdReporter — summary + per-finding detail
├── tests/
│   └── run.py                       # 214 standalone tests (zero external dependencies)
└── reports/                         # Output directory (gitignored)
```

---

## Extending

### Adding a New Scan Module (Phase 3 style)

New scanners should follow the **5-phase lifecycle** using `ScannerBase` from `scanners/base.py`:

```python
from scanners.base import ScannerBase, DetectionResult

class MyCheckScanner(ScannerBase):
    SCANNER_NAME = "mycheck"
    SCANNER_MATURITY = 3   # 1=detect, 2=validate, 3=exploit, 4=verify

    def detect(self, url: str, parameter: str | None = None) -> DetectionResult | None:
        # Phase 1: Find the vulnerability signal
        ...
        return DetectionResult(url=url, parameter=param, payload=..., context=...)

    def validate(self, detection: DetectionResult) -> dict | None:
        # Phase 2: Confirm the finding (OOB, browser, timing, etc.)
        ...
        return {"confirmed": True, "method": "oob"}

    def collect_evidence(self, detection: DetectionResult,
                         validation_result: dict | None = None) -> list:
        # Phase 3: Collect evidenced requests, responses, screenshots
        ...

    def generate_reproduction(self, detection: DetectionResult) -> list[str]:
        # Phase 4: Produce step-by-step reproduction instructions
        ...

    def scan(self, target_urls: list[str] | None = None) -> list[dict]:
        self._prepare_scan()
        urls = ...   # resolve URLs
        for url in urls:
            detection = self.detect(url)
            if not detection:
                continue
            validation = self.validate(detection)
            evidence = self.collect_evidence(detection, validation)
            f = finding("My Vuln Type", url, "high", ...)
            if f:
                self._add_finding(f)
        return self._get_findings()
```

2. **Register in `main.py`:**
   - Add the module name to `parse_args()` `choices` for `--modules` and `--disable-modules`
   - Add to `module_map` in `run()`
   - If it runs once per target (not per URL), add to `TARGET_LEVEL`

3. **Configure per-URL dispatch** — Add to `classify_endpoint()` in `utils.py` so it only runs on applicable URLs.

4. **Add impact narrative** — Add an entry to `IMPACT_MATRIX` in `reporting/base.py`.
5. **Add remediation guidance** — Add an entry to `REMEDIATION_MATRIX` in `reporting/base.py` so reports include actionable fix guidance for the new vuln type.

### Legacy Method (VulnScanner subclass)

For complex modules, subclass `VulnScanner` in a new file under `modules/`:

```python
from modules.scanner import VulnScanner
from modules.utils import finding, _build_curl

class MyScanner(VulnScanner):
    def run_all(self) -> list[dict]:
        findings: list[dict] = []
        # ... scanning logic with self.session, self._in_scope(), etc. ...
        self._append_finding(findings, f)
        return self._deduplicate(findings)
```

Import and instantiate in `module_map` in `main.py`.

---

## FAQ

**Q: Do I need Playwright?**  
No. XSS findings are reported as **Detected** when Playwright is unavailable. Only install it if you want verified XSS with screenshots.

**Q: How does SQLi work without a database?**  
SQLi detection uses multiple independent signals (error patterns, boolean differences, time delays, OOB callbacks). Requiring 2+ signals reduces false positives.

**Q: What is OOB and how do I set it up?**  
OOB (Out-of-Band) detection uses a callback server to confirm blind vulnerabilities. Use a free Interactsh instance (`--oob-host https://oastify.com`) or Burp Collaborator. The scanner generates a unique token per test and polls for DNS/HTTP callbacks.

**Q: Can I stop and resume a scan?**  
Yes. Press Ctrl+C to save findings collected so far. Resume with `--resume`. The scan state is persisted in `.scan_state.json`.

**Q: How are secrets validated?**  
AWS keys are tested against STS `GetCallerIdentity`, GitHub tokens against the REST API, and Slack/Twilio tokens by format analysis. Only valid secrets are reported.

**Q: What does `--dry-run` show?**  
URLs discovered, forms, subdomains, JS endpoints, and JS secrets — without sending any exploit payloads. Use it to assess attack surface before committing to active scanning.

**Q: Are my credentials safe in reports?**  
Yes. Curl commands in reports mask sensitive headers (Authorization, Cookie, X-API-Key, X-Auth-Token) by default as `<REDACTED>`. Use `--no-mask-curl` to disable masking.

**Q: Can I run this in CI?**  
Yes. Use `--no-rich` for plain terminal output. Use `--format json` for machine-readable results. Exit code 0 = no critical/high findings; exit code 1 = findings present.

---

## Disclaimer

This software is for **education and authorized security testing only**. Obtain explicit written permission before scanning any system. Unauthorized scanning may violate computer fraud laws and bug bounty program rules. The authors and contributors are not liable for misuse or damages.

---

<div align="center">

Built for the bug bounty community · Use responsibly

</div>
