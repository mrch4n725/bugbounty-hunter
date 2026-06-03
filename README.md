<div align="center">

```
  ____              ____                   _          
 | __ ) _   _  __ _| __ )  ___  _   _ _ __| |_ _   _ 
 |  _ \| | | |/ _` |  _ \ / _ \| | | | '_ \ __| | | |
 | |_) | |_| | (_| | |_) | (_) | |_| | | | | |_| |_| |
 |____/ \__,_|\__, |____/ \___/ \__,_|_| |_|\__|\__, |
              |___/                             |___/ 
```

**Automated vulnerability scanner for bug bounty programs**

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey?style=flat-square)](README.md)
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

### Windows

**1. Install Python** (if not already installed) — download from [python.org](https://www.python.org/downloads/windows/) and check **"Add Python to PATH"** during setup.

**2. Install Git** — download from [git-scm.com](https://git-scm.com/download/win) (Git Bash is included and recommended).

**3. Clone and install** — open **Command Prompt**, **PowerShell**, or **Git Bash**:

```cmd
git clone https://github.com/mrch4n725/bugbounty-hunter.git
cd bugbounty-hunter
python -m pip install -r requirements.txt
```
### Specific Branch Installation
```cmd
git clone -b installer-tools --single-branch https://github.com/mrch4n725/bugbounty-hunter.git
cd bugbounty-hunter
python -m pip install -r requirements.txt
```
* This specific Branch instillation is for users struggling to navigate the git clone. Use this command to clone the second branch, then it will be easier to run the software.

> **Tip:** If (on linux or cloning main branch without manual files) you receive: `ERROR: Could not open requirements file: [Errno 2] No such file or directory: 'requirements.txt'` You probably didn't unzip the file or cloned the wrong directory.
 
> **Tip:** If `python` isn't recognised, try `py` or `python3` instead (the Python Launcher for Windows).

> **Tip:** If you hit permission errors with pip, add `--user` flag: `pip install --user -r requirements.txt`

### macOS

**1. Install Python** via [Homebrew](https://brew.sh) (recommended) or [python.org](https://python.org):

```bash
brew install python git
```

**2. Clone and install:**

```bash
git clone https://github.com/mrch4n725/bugbounty-hunter.git
cd bugbounty-hunter
pip3 install -r requirements.txt
```

### Linux

```bash
sudo apt install python3 python3-pip git   # Debian/Ubuntu
# or
sudo dnf install python3 python3-pip git   # Fedora/RHEL

git clone https://github.com/mrch4n725/bugbounty-hunter.git
cd bugbounty-hunter
pip3 install -r requirements.txt
```

### Virtual environment (all platforms, recommended)

Keeps dependencies isolated from your system Python:

```bash
# Create and activate
python -m venv .venv

# Windows (Command Prompt)
venv\Scripts\activate.bat

# Windows (PowerShell)
venv\Scripts\Activate.ps1

# macOS / Linux
source .venv/bin/activate

# Install
pip install -r requirements.txt
```

---

## Usage

### Windows (Command Prompt / PowerShell)

```cmd
# Full scan
python main.py --target https://example.com

# Passive mode
python main.py --target https://example.com --passive

# Specific modules
python main.py --target https://example.com --modules xss sqli lfi

# Authenticated scan (note: use double quotes on Windows)
python main.py --target https://example.com --cookies "session=abc123; csrf=xyz" --headers "Authorization: Bearer <token>" --format json --threads 20

# Deep crawl with verbose output
python main.py --target https://example.com --crawl-depth 4 --verbose
```

### macOS / Linux

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
