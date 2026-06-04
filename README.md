<div align="center">

# BugBounty Hunter

**Automated web reconnaissance and vulnerability scanning for bug bounty programs**

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)

</div>

---

> **Authorized testing only.** Run BugBounty Hunter only against targets you have **explicit written permission** to assess. Unauthorized scanning may violate law and program rules.

---

## What it does

BugBounty Hunter is a modular, multithreaded scanner that:

1. **Recon** — crawls the target, discovers URLs, forms, query parameters, and common subdomains.
2. **Active checks** — fuzzes for XSS, SQLi, LFI, SSRF, open redirects, missing headers, CSRF, exposed files, and more.
3. **Reporting** — writes HTML, JSON, or plain-text reports with severity summaries and evidence.

Each finding is a structured record with **CVSS metadata**, **confidence** (`confirmed` / `probable` / `tentative`), **fingerprint** (for deduplication), and **timestamp**.

---

## Quick start

```bash
git clone https://github.com/mrch4n725/bugbounty-hunter.git
cd bugbounty-hunter
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python3 main.py --target https://example.com
```

Reports are written to `reports/` by default (override with `--output`).

---

## Installation

| Platform | Prerequisites |
|----------|----------------|
| **Linux** | `python3`, `python3-pip`, `git` |
| **macOS** | `brew install python git` or python.org installer |
| **Windows** | Python 3.10+ with “Add to PATH”; Git optional but recommended |

Use a **virtual environment** so dependencies stay isolated:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

If `python` is not found, try `python3` or `py` (Windows). On permission errors: `pip install --user -r requirements.txt`.

---

## Usage examples

```bash
# Full active scan (default modules)
python3 main.py --target https://example.com

# Passive mode — recon + headers only
python3 main.py --target https://example.com --passive

# Selected modules
python3 main.py --target https://example.com --modules xss sqli lfi headers

# Authenticated scan
python3 main.py --target https://example.com \
  --cookies "session=abc; csrf=xyz" \
  --headers "Authorization: Bearer TOKEN" \
  --threads 20

# YAML config (CLI flags override file values)
python3 main.py --config config.example.yaml

# JSON report + interim autosave every 60s
python3 main.py --target https://example.com --format json --autosave-interval 60
```

Copy `config.example.yaml` to `config.yaml` and edit target, scope, and module settings.

---

## Scan scope

Limit what gets crawled and tested with regex in config or YAML:

| Key | Effect |
|-----|--------|
| `exclude_patterns` | List of regexes matched against the **full URL** — matches are skipped |
| `include_paths` | When set, only URLs whose path/query match at least one regex are tested |

Recon and all active modules respect these rules.

---

## Modules

| Module | CLI name | Description |
|--------|----------|-------------|
| Recon | `recon` | Crawler, subdomain DNS, robots/sitemap |
| XSS | `xss` | Reflected XSS (URL params + forms) |
| SQLi | `sqli` | Error-based, boolean-based, time-based blind |
| LFI | `lfi` | Path traversal / local file inclusion |
| SSRF | `ssrf` | Internal/metadata URL probes |
| Open redirect | `open_redirect` | Redirect parameter abuse |
| Headers | `headers` | Missing security headers, disclosure, CORS, cookies |
| CSRF | `csrf` | POST forms without anti-CSRF tokens |
| Directory fuzz | `dirb` | Common paths and optional wordlist |
| Sensitive data | `sensitive` | Secret patterns in page bodies |
| Exposed files | `exposed_files` | `.env`, `.git`, backups, etc. |
| Clickjacking | `clickjacking` | Missing frame protection |
| HTTP methods | `http_methods` | Dangerous `Allow` / CORS methods |
| Insecure forms | `insecure_forms` | HTTP actions, cross-origin password posts |
| Subdomain takeover | `subdomain_takeover` | Dangling SaaS fingerprints |

Use `--modules all` (default) or list modules explicitly. Disable with `--disable-modules sqli sensitive`.

---

## CLI reference

| Flag | Default | Description |
|------|---------|-------------|
| `--target` / `-t` | — | Target URL (required unless set in config) |
| `--config` / `-C` | — | YAML configuration file |
| `--modules` / `-m` | `all` | Modules to run (see table above) |
| `--disable-modules` | — | Modules to skip when running `all` |
| `--output` / `-o` | `reports` | Report output directory |
| `--format` / `-f` | `html` | `html`, `json`, or `txt` |
| `--threads` | `10` | Worker threads |
| `--timeout` | `10` | Request timeout (seconds) |
| `--crawl-depth` | `2` | Recon crawl depth |
| `--max-urls` | `200` | Max URLs to collect |
| `--delay` | `0` | Delay between requests (seconds) |
| `--cookies` / `-c` | — | Cookie header string |
| `--headers` / `-H` | — | Custom header (repeatable) |
| `--auth` | — | Basic auth `user:pass` |
| `--proxy` | — | HTTP(S) proxy URL |
| `--no-verify-ssl` | off | Disable TLS verification |
| `--wordlist` | — | Extra paths for directory fuzzing |
| `--module-param` | — | `module.key=value` overrides |
| `--retries` | `3` | HTTP retry count |
| `--autosave-interval` | `0` | Autosave partial report every N seconds |
| `--passive` | off | No active fuzzing |
| `--verbose` / `-v` | off | Per-request / per-finding logs |

---

## Finding format

Findings are produced by `finding()` in `modules/utils.py`:

```python
{
  "type": "Reflected XSS",
  "url": "https://example.com/?q=...",
  "severity": "high",           # critical | high | medium | low | info
  "details": "...",
  "evidence": "...",
  "confidence": "confirmed",    # confirmed | probable | tentative
  "fingerprint": "<sha256>",
  "timestamp": "2026-06-04T12:00:00Z",
  "cvss_score": 6.1,
  "cvss_vector": "CVSS:3.1/...",
  "what_is_it": "...",
  "impact": "...",
  "remediation": "...",
  "references": ["https://owasp.org/..."],
  "grouped_urls": ["..."]       # present when 5+ similar hits collapsed
}
```

The scanner deduplicates by **fingerprint** (same issue across modules) and can **group** five or more hits on the same parameter into one finding with `grouped_urls`.

---

## Reports

| Format | Contents |
|--------|----------|
| **HTML** | Dark-themed dashboard, severity summary, findings with evidence |
| **JSON** | Machine-readable full scan payload |
| **TXT** | Plain-text summary for terminals and CI |

Interim reports use the `.partial` suffix when `--autosave-interval` is set.

**Exit codes**

| Code | Meaning |
|------|---------|
| `0` | Scan finished; no critical or high findings |
| `1` | One or more critical or high findings |

---

## Project layout

```
bugbounty-hunter/
├── main.py                 # CLI and orchestration
├── config.example.yaml     # Sample YAML configuration
├── requirements.txt
├── modules/
│   ├── utils.py            # HTTP helpers, finding(), logging, scope
│   ├── recon.py            # Crawler and subdomain discovery
│   ├── scanner.py          # Vulnerability checks
│   └── reporter.py         # Report generation
└── reports/                # Output (gitignored)
```

---

## Extending

1. Add `scan_mycheck(self) -> list[dict]` on `VulnScanner` in `modules/scanner.py`.
2. Return findings via `finding(...)` and end with `return self._deduplicate(findings)`.
3. Register the module in `main.py` (`parse_args` choices + `active_modules` dict).
4. Optionally add metadata in `VULN_METADATA` inside `modules/utils.py`.

Respect `_in_scope()` in every URL loop and use `_add()` so fingerprint deduplication applies.

---

## Dependencies

| Package | Role |
|---------|------|
| `requests` | HTTP client |
| `beautifulsoup4` | HTML parsing |
| `lxml` | Parser backend |
| `PyYAML` | Config files |
| `rich` | Terminal UI (progress, tables, colored logs) |
| `urllib3` | Retries and connection pooling |

---

## Disclaimer

This software is for **education and authorized security testing** only. Obtain written permission before scanning any system. Authors and contributors are not liable for misuse or damages.

---

<div align="center">

Built for the bug bounty community · Use responsibly

</div>
