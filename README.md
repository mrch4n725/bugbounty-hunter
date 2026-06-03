<div align="center">

```
  ____              ____                   _          
 | __ ) _   _  __ _| __ )  ___  _   _ _ __| |_ _   _ 
 |  _ \| | | |/ _` |  _ \ / _ \| | | | '_ \ __| | | |
 | |_) | |_| | (_| | |_) | (_) | |_| | | | | |_| |_| |
 |____/ \__,_|\__, |____/ \___/ \__,_|_| |_|\__|\__, |
              |___/     1st-version-separate    |___/ 
```

**Branch: `installer-tools` — standalone installer & individual module files**

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python)](https://python.org)
[![Branch](https://img.shields.io/badge/Branch-installer--tools-orange?style=flat-square)]()
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey?style=flat-square)]()

</div>

---

> [!NOTE]
> This is the **`installer-tools`** branch with **fully fixed and verified modules**. It contains the project's individual module files separated for easier reading, contribution, and modification. All 6 vulnerability scanning modules are implemented and tested.

---

## Quick Start

### 1. Install Dependencies

```bash
# Create virtual environment (recommended)
python3 -m venv venv

# Activate virtual environment
# On macOS/Linux:
source venv/bin/activate
# On Windows (Command Prompt):
venv\Scripts\activate.bat
# On Windows (PowerShell):
venv\Scripts\Activate.ps1

# Install dependencies
pip3 install -r requirements.txt
```

### 2. Run a Scan

```bash
# Full scan with all modules
python3 main.py --target https://example.com

# Passive mode (recon + headers only, no active fuzzing)
python3 main.py --target https://example.com --passive

# Specific modules only
python3 main.py --target https://example.com --modules xss sqli headers

# With custom output format
python3 main.py --target https://example.com --format json --threads 20

# With authentication
python3 main.py --target https://example.com \
  --cookies "session=abc123; csrf=xyz" \
  --headers "Authorization: Bearer token"

# Deep crawl with verbose output
python3 main.py --target https://example.com --crawl-depth 4 --verbose
```

---

## Branch Structure

```
bugbounty-hunter/  (installer-tools branch)
├── main.py              # CLI entry point with full argparse
├── requirements.txt     # Python dependencies (requests, beautifulsoup4, lxml, urllib3)
├── modules/
│   ├── __init__.py      # Package initialization
│   ├── recon.py         # Crawler + subdomain enumeration (266 lines)
│   ├── scanner.py       # XSS, SQLi, LFI, SSRF, redirect, headers (568 lines)
│   ├── reporter.py      # HTML / JSON / TXT report generation (566 lines)
│   └── utils.py         # Shared helpers, session factory, finding() dict (282 lines)
└── README.md            # This file
```

---

## CLI Usage

See all available options:
```bash
python3 main.py --help
```

### Command-Line Reference

| Flag | Default | Description |
|---|---|---|
| `--target` / `-t` | *required* | Target URL |
| `--modules` / `-m` | `all` | Space-separated: `recon xss sqli lfi ssrf open_redirect headers all` |
| `--output` / `-o` | `reports/` | Output directory for reports |
| `--format` / `-f` | `html` | Report format: `html` · `json` · `txt` |
| `--threads` | `10` | Concurrent threads for scanning |
| `--timeout` | `10` | Per-request timeout (seconds) |
| `--cookies` / `-c` | — | Cookie string e.g. `"session=x; token=y"` |
| `--headers` / `-H` | — | Custom header e.g. `"Authorization: Bearer ..."` (repeatable) |
| `--crawl-depth` | `2` | Crawler recursion depth |
| `--passive` | off | Passive mode — no active fuzzing |
| `--verbose` / `-v` | off | Verbose output with detailed logging |

---

## Module Files

Each module is self-contained and professionally implemented:

### `modules/recon.py` (266 lines)
Multithreaded web crawler and subdomain enumerator. Discovers URLs, HTML forms, query parameters, and live subdomains using 28+ common prefixes. Thread-safe operations with URL validation. Controlled by `--crawl-depth` and `--threads`.

**Methods:**
- `run()` - Execute reconnaissance
- `_crawl()` - Multithreaded website crawling
- `_extract_forms()` - Parse HTML forms and fields
- `_enumerate_subdomains()` - Test common subdomains

### `modules/scanner.py` (568 lines)
All active vulnerability checks in one file. Each vulnerability type is a separate method — easy to extend. Covers:
- **XSS** - Reflected XSS via URL params and HTML forms
- **SQLi** - Error-based and time-based blind injection
- **LFI** - Path traversal with signature matching
- **SSRF** - AWS/GCP metadata, localhost probing
- **Open Redirect** - Tests 16 common redirect parameters
- **Headers** - Missing security headers, version disclosure

**Methods:**
- `scan_xss()`, `scan_sqli()`, `scan_lfi()`, `scan_ssrf()`, `scan_open_redirect()`, `scan_headers()`

### `modules/reporter.py` (566 lines)
Generates the final report from standardised finding dicts. Supports:
- **HTML** - Dark-themed dashboard with severity cards
- **JSON** - Structured data export
- **TXT** - Clean text format

**Methods:**
- `generate()` - Create and save report
- `_html()`, `_json()`, `_txt()` - Format-specific generation

### `modules/utils.py` (282 lines)
Shared helpers used across all modules:
- `Colors` - ANSI color codes for terminal output
- `banner()` - ASCII art banner and intro
- `log()` - Thread-safe colored logging
- `finding()` - Standardized vulnerability finding dictionary
- `make_session()` - Pre-configured requests.Session with headers/cookies
- `safe_get()` / `safe_post()` - Error-handled HTTP requests
- `normalize_url()` / `same_domain()` - URL utilities

---

## Reports

Reports are automatically saved to `reports/` (configurable with `--output`).

### HTML Report
Dark-themed dashboard including:
- Severity summary cards (Critical / High / Medium / Low)
- Full findings table with URLs, severity, and evidence
- Discovered subdomains and URLs
- Professional styling

### Exit Codes
| Code | Meaning |
|---|---|
| `0` | Scan complete — no critical or high findings |
| `1` | One or more critical or high findings detected |

---

## Contributing

This branch is the recommended starting point for contributors:

1. Fork the repo and clone your fork
2. Check out this branch: `git checkout installer-tools`
3. Install dependencies: `pip3 install -r requirements.txt`
4. Make changes to the relevant module file
5. Test with: `python3 main.py --target <your-authorised-target>`
6. Open a pull request

### Adding a New Vulnerability Module

**1.** Add a method to `VulnScanner` in `modules/scanner.py`:

```python
def scan_mycheck(self) -> list[dict]:
    findings = []
    for url in self._urls_with_params():
        # ... test logic ...
        findings.append(finding("My Check", url, "high", "Details", "evidence"))
    return findings
```

**2.** Register it in `main.py`:

```python
# In parse_args choices list:
choices=["recon", "xss", "sqli", ..., "mycheck", "all"]

# In the active_modules dict:
"mycheck": scanner.scan_mycheck,
```

**3.** Use `finding()` helper from `modules/utils.py` with severity: `critical · high · medium · low · info`

---

## Switching Between Branches

```bash
# Current branch (installer-tools with individual modules)
git branch

# Switch back to main (if created)
git checkout main

# See all branches
git branch -a
```

---

## Dependencies

| Package | Version | Purpose |
|---|---|---|
| `requests` | ≥ 2.31.0 | HTTP client with session management |
| `beautifulsoup4` | ≥ 4.12.0 | HTML parsing for crawler and form extraction |
| `lxml` | ≥ 4.9.0 | Fast HTML parser backend |
| `urllib3` | ≥ 2.0.0 | Connection pooling and retries |

**All dependencies are installed via:**
```bash
pip3 install -r requirements.txt
```

---

## Project Info

| Item | Details |
|---|---|
| Language | Python 3.10+ |
| Modules | 5 (recon, scanner, reporter, utils, main) |
| Total Code | ~1,827 lines |
| Vulnerability Checks | 6 types (XSS, SQLi, LFI, SSRF, Open Redirect, Headers) |
| Report Formats | 3 (HTML, JSON, TXT) |
| Multithreading | Configurable concurrent threads |

---

## Disclaimer

This tool is provided for **educational purposes and authorised security testing only**. Always obtain written permission before scanning any target. The authors and contributors accept no responsibility or liability for any damage or legal consequences caused by misuse of this software.

> [!WARNING]
> **Authorised use only.** Only run this tool against targets you have explicit written permission to test. Unauthorised scanning is illegal and unethical.

---

<div align="center">

Made for the bug bounty community · Use responsibly

`installer-tools` branch · All modules verified and tested

</div>
