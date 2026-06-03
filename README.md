<div align="center">

```
  ____              ____                   _          
 | __ ) _   _  __ _| __ )  ___  _   _ _ __| |_ _   _ 
 |  _ \| | | |/ _` |  _ \ / _ \| | | | '_ \ __| | | |
 | |_) | |_| | (_| | |_) | (_) | |_| | | | | |_| |_| |
 |____/ \__,_|\__, |____/ \___/ \__,_|_| |_|\__|\__, |
              |___/  Hunter                      |___/ 
```

**Automated vulnerability scanner for bug bounty programs**

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen?style=flat-square)](CONTRIBUTING.md)

</div>

---

> [!WARNING]
> **Authorised use only.** Only run this tool against targets you have explicit written permission to test. Unauthorised scanning is illegal and unethical. The authors accept no liability for misuse.

---

## Overview

BugBounty Hunter is a modular, multithreaded web vulnerability scanner built for bug bounty hunters. Point it at a target, and it crawls the attack surface, discovers endpoints and forms, then actively fuzzes for common web vulnerabilities — outputting a clean HTML, JSON, or TXT report.

```bash
python main.py --target https://example.com
```

---

## Modules

| Module | Technique | Severity |
|---|---|---|
| 🔍 **Recon** | Crawler, subdomain brute-force, form/param discovery | — |
| ⚡ **XSS** | Reflected XSS via URL params and HTML forms | High |
| 💉 **SQLi** | Error-based + time-based blind injection | Critical |
| 📁 **LFI** | Path traversal with signature matching | Critical |
| 🔄 **SSRF** | AWS/GCP metadata, localhost probe | Critical |
| ↪️ **Open Redirect** | 16 common redirect parameter names | Medium |
| 🛡️ **Headers** | Missing security headers, version disclosure | Low–High |

---

## Installation

**Requirements:** Python 3.10+

```bash
git clone https://github.com/youruser/bugbounty-hunter.git
cd bugbounty-hunter
pip install -r requirements.txt
```

---

## Usage

```bash
# Full scan with HTML report (default)
python main.py --target https://example.com

# Passive mode — recon and headers only, no active fuzzing
python main.py --target https://example.com --passive

# Run specific modules
python main.py --target https://example.com --modules xss sqli lfi

# Authenticated scan with cookies and custom headers
python main.py \
  --target https://example.com \
  --cookies "session=abc123; csrf=xyz" \
  --headers "Authorization: Bearer <token>" \
  --format json \
  --threads 20

# Deep crawl with verbose output
python main.py --target https://example.com --crawl-depth 4 --verbose
```

---

## CLI Reference

| Flag | Default | Description |
|---|---|---|
| `--target` / `-t` | *required* | Target URL |
| `--modules` / `-m` | `all` | Space-separated list: `recon xss sqli lfi ssrf open_redirect headers all` |
| `--output` / `-o` | `reports/` | Output directory |
| `--format` / `-f` | `html` | Report format: `html` · `json` · `txt` |
| `--threads` | `10` | Concurrent threads |
| `--timeout` | `10` | Per-request timeout (seconds) |
| `--cookies` / `-c` | — | Cookie string e.g. `"session=x; token=y"` |
| `--headers` / `-H` | — | Custom header e.g. `"Authorization: Bearer ..."` (repeatable) |
| `--crawl-depth` | `2` | Crawler recursion depth |
| `--passive` | off | Passive mode — no active fuzzing |
| `--verbose` / `-v` | off | Print each request and finding as they occur |

---

## Reports

Reports are saved to `reports/` (configurable via `--output`).

The **HTML report** includes a dark-themed dashboard with:
- Severity summary cards (Critical / High / Medium / Low)
- Full findings table with URLs and evidence
- Discovered subdomains and URLs from recon

**Exit codes**

| Code | Meaning |
|---|---|
| `0` | Scan complete — no critical or high findings |
| `1` | One or more critical or high findings detected |

---

## Project Structure

```
bugbounty-hunter/
├── main.py              # CLI entry point & orchestration
├── requirements.txt     # Python dependencies
├── modules/
│   ├── recon.py         # Multithreaded crawler + subdomain enumeration
│   ├── scanner.py       # All active vulnerability checks
│   ├── reporter.py      # HTML / JSON / TXT report generation
│   └── utils.py         # Shared helpers, session factory, finding() dict
└── reports/             # Generated reports (gitignored)
```

---

## Extending

Adding a new vulnerability module takes three steps:

**1.** Add a method to `VulnScanner` in `modules/scanner.py`:

```python
def scan_mycheck(self) -> list[dict]:
    findings = []
    for url in self._urls_with_params():
        # ... test logic ...
        findings.append(finding("My Check", url, "high", "Details here", "evidence"))
    return findings
```

**2.** Register it in `main.py`:

```python
# In parse_args choices list:
choices=["recon", "xss", "sqli", ..., "mycheck", "all"]

# In the active_modules dict:
"mycheck": scanner.scan_mycheck,
```

Use the `finding()` helper from `utils.py` to return standardised dicts with consistent severity levels: `critical · high · medium · low · info`.

---

## Dependencies

| Package | Purpose |
|---|---|
| `requests` | HTTP client |
| `beautifulsoup4` | HTML parsing for crawler and form extraction |
| `lxml` | Fast HTML parser backend |
| `urllib3` | Connection pooling |

---

## Disclaimer

This tool is provided for **educational purposes and authorised security testing only**. Always obtain written permission before scanning any target. The authors and contributors accept no responsibility or liability for any damage or legal consequences caused by misuse of this software.

---

<div align="center">

Made for the bug bounty community · Use responsibly

</div>
