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
> This is the **`installer-tools`** branch. It contains the standalone `install.py` installer and the project's individual module files separated for easier reading, contribution, and modification. For the main scanner, see the [`main`](../main/README.md) branch.

---

## What's Different on This Branch

| | `main` branch | `installer-tools` branch |
|---|---|---|
| Purpose | Run the scanner | Set up the environment |
| Key file | `main.py` | `install.py` |
| Modules | Bundled | Listed separately |
| Intended for | End users | Contributors / first-time setup |

---

## Branch Structure

```
bugbounty-hunter/  (installer-tools branch)
├── install.py           # ← Automated installer (this branch's main file)
├── requirements.txt     # Pinned dependencies
├── modules/
│   ├── recon.py         # Crawler + subdomain enumeration
│   ├── scanner.py       # XSS, SQLi, LFI, SSRF, redirect, headers
│   ├── reporter.py      # HTML / JSON / TXT report generation
│   └── utils.py         # Shared helpers, session factory, finding() dict
└── main.py              # Scanner entry point (same as main branch)
```

---

## install.py

The installer is a zero-dependency Python script — it uses only the standard library, so it runs on a fresh Python install with nothing else needed.

### What it does

| Step | Action |
|---|---|
| **1 — Python check** | Verifies Python 3.10+ is in use; prints download link if not |
| **2 — Virtual environment** | Creates `venv/` in the project directory (skippable) |
| **3 — Dependencies** | Runs `pip install -r requirements.txt`; auto-retries with `--break-system-packages` on Debian/Ubuntu |
| **4 — Verification** | Confirms each package installed correctly and prints its version |

### Running the installer

**Windows (Command Prompt or PowerShell)**

```cmd
python install.py
```

**Windows — skip virtual environment**

```cmd
python install.py --no-venv
```

**macOS / Linux**

```bash
python3 install.py

# Skip virtual environment
python3 install.py --no-venv
```

### Flags

| Flag | Description |
|---|---|
| *(none)* | Default — creates `venv/` and installs into it |
| `--no-venv` | Skips virtual environment creation, installs into system Python |

### After installation

The installer prints the exact command to activate your virtual environment and run a scan:

**Windows (Command Prompt)**
```cmd
venv\Scripts\activate.bat
python main.py --target https://example.com
```

**Windows (PowerShell)**
```powershell
venv\Scripts\Activate.ps1
python main.py --target https://example.com
```

**macOS / Linux**
```bash
source venv/bin/activate
python main.py --target https://example.com
```

---

## Module Files

Each module is self-contained and can be read or modified independently.

### `modules/recon.py`
Multithreaded web crawler and subdomain enumerator. Discovers URLs, HTML forms, query parameters, and live subdomains using a wordlist of ~30 common prefixes. Controlled by `--crawl-depth` and `--threads`.

### `modules/scanner.py`
All active vulnerability checks in one file. Each check is a method on the `VulnScanner` class — easy to extend. Covers XSS, SQLi (error-based + time-based blind), LFI, SSRF, open redirect, and security header analysis.

### `modules/reporter.py`
Generates the final report from a list of standardised `finding()` dicts. Supports HTML (dark dashboard), JSON, and plain text. Output path and format are controlled by `--output` and `--format`.

### `modules/utils.py`
Shared helpers used across all modules: coloured logging, a pre-configured `requests.Session` factory, safe GET/POST wrappers, URL normalisation, and the `finding()` dict constructor.

---

## Switching Between Branches

```bash
# Switch to the main scanner branch
git checkout main

# Switch back to this branch
git checkout installer-tools

# See all branches
git branch -a
```

---

## Contributing

This branch is the recommended starting point for contributors:

1. Fork the repo and clone your fork
2. Check out this branch: `git checkout installer-tools`
3. Run `install.py` to set up your environment
4. Make changes to the relevant module file
5. Test with `python main.py --target <your-authorised-target>`
6. Open a pull request against `main`

When adding a new vulnerability module, see the **Extending** section in the [main branch README](../main/README.md) for the three-step pattern.

---

## Dependencies

| Package | Version | Purpose |
|---|---|---|
| `requests` | ≥ 2.31.0 | HTTP client |
| `beautifulsoup4` | ≥ 4.12.0 | HTML parsing for crawler and form extraction |
| `lxml` | ≥ 5.0.0 | Fast HTML parser backend |
| `urllib3` | ≥ 2.0.0 | Connection pooling |

> `install.py` itself has **no external dependencies** — standard library only.

---

## Disclaimer

This tool is provided for **educational purposes and authorised security testing only**. Always obtain written permission before scanning any target. The authors and contributors accept no responsibility or liability for any damage or legal consequences caused by misuse of this software.

---

<div align="center">

`installer-tools` branch · BugBounty Hunter · Use responsibly

</div>
