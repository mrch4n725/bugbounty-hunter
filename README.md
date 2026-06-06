<div align="center">

# BugBounty Hunter

**Automated web reconnaissance and vulnerability scanning for bug bounty programs — with evidence-based verification and bug-bounty-grade reporting**

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)

</div>

---

## Documentation

| File | Contents |
|------|----------|
| `IMPLEMENTATION_SUMMARY.md` | Full implementation walkthrough — all phases, changes, and bug fix log |
| `IMPROVEMENTS.md` | Detailed false-positive fixes, performance improvements, and technical depth |
| `config.example.yaml` | All available options with annotations |

---

> **Authorized testing only.** Run BugBounty Hunter only against targets you have **explicit written permission** to assess. Unauthorized scanning may violate law and program rules.

---

## What it does

BugBounty Hunter is a modular, multithreaded scanner with **evidence-based verification** — findings progress through Detection → Validation → Exploitation → Verified, each with confidence scoring and proof-of-concept evidence.

1. **Recon** — crawls the target, discovers URLs, forms, query parameters, subdomains, and mines JavaScript bundles for endpoints/secrets.
2. **Intelligence** — technology fingerprinting (framework/CMS/language/WAF), JS AST analysis for hidden endpoints and hardcoded credentials.
3. **Active checks** — fuzzes for XSS, SQLi, LFI, SSRF, XXE, Command Injection, Blind XSS, open redirects, missing headers, CSRF, IDOR, GraphQL, exposed files, subdomain takeover, and more.
4. **Verification** — OOB callback framework (Interactsh/Collaborator), browser-based XSS execution verification (Playwright), live secret validation (AWS STS, GitHub API, Slack API), multi-signal SQLi, 4-stage SSTI.
5. **Reporting** — HTML, JSON, TXT, per-finding Markdown, and **bug-bounty-ready** HackerOne/Bugcrowd submission formats with CVSS, impact assessment, and reproduction steps.

Each finding is a structured record with **CVSS metadata**, **verification stage** (detected / validated / exploitable / verified), **confidence score** (0–100), **evidence strength** (Weak / Moderate / Strong / Verified), **false positive risk**, **impact assessment** (data exposure / ATO / RCE potential), **fingerprint** (for deduplication), and **grouped URLs**.

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

## Optional Dependencies

| Package | Required for | Install |
|---------|-------------|---------|
| **esprima** | AST-based JavaScript analysis — more accurate secret/endpoint extraction from minified bundles (regex fallback used when absent) | `pip install esprima` |
| **openai** | AI-assisted triage narratives in Markdown reports via `--triage-assist` (requires `OPENAI_API_KEY` env var) | `pip install openai` |
| **playwright** | Headless browser for JS-rendered crawling + XSS execution verification (`--headless` flag) | `pip install -r requirements-headless.txt` |

All three packages are fully optional — the tool works without them using built-in fallbacks.

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
| Recon | `recon` | Crawler, subdomain DNS, robots/sitemap, JS endpoint mining via JSIntelligence |
| XSS | `xss` | Context-aware reflected XSS (HTML/attribute/JS/URL) + Playwright execution verification |
| SQLi | `sqli` | Error-based, boolean-based, time-based blind, OOB callback — requires 2+ signals for Confirmed |
| LFI | `lfi` | Path traversal / local file inclusion |
| SSRF | `ssrf` | OOB callback + cloud metadata endpoint verification (no parameter-name heuristics) |
| XXE | `xxe` | In-band file read, error-based leak, OOB blind XXE via Interactsh |
| Command Injection | `cmd_injection` | Output-based (`uid=`), time-based (≥5s), OOB callback (nslookup/curl) |
| Blind XSS | `blind_xss` | Inject OOB-payload forms/params, poll for callback from admin browser |
| Open redirect | `open_redirect` | Redirect parameter abuse |
| Headers | `headers` | Missing security headers, disclosure, CORS (including origin reflection), cookies, subdomain scan |
| CSRF | `csrf` | POST forms without anti-CSRF tokens |
| Directory fuzz | `dirb` | Common paths (200 → exposed, 403/401 → access control info) and optional wordlist |
| Sensitive data | `sensitive` | Secret patterns in page bodies + **live validation** (AWS keys, GitHub tokens, Slack tokens) |
| Exposed files | `exposed_files` | `.env`, `.git`, backups, etc. |
| Clickjacking | `clickjacking` | Missing frame protection |
| HTTP methods | `http_methods` | Dangerous `Allow` / CORS methods |
| Insecure forms | `insecure_forms` | HTTP actions, cross-origin password posts |
| Subdomain takeover | `subdomain_takeover` | Dangling SaaS fingerprints |
| GraphQL | `graphql` | Introspection, query batching, alias amplification |
| IDOR | `idor` | Numeric/UUID parameter mutation and horizontal escalation |
| API | `api` | OpenAPI/Swagger discovery, REST fuzzing, mass assignment |
| JS secrets | `js_secrets` | AST + regex secret extraction from JS bundles (integrated into recon) |

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
| `--format` / `-f` | `html` | `html`, `json`, `txt`, `markdown-report`, `hackerone`, or `bugcrowd` |
| `--threads` | `10` | Worker threads |
| `--timeout` | `10` | Request timeout (seconds) |
| `--crawl-depth` | `2` | Recon crawl depth |
| `--max-urls` | `200` | Max URLs to collect |
| `--delay` | `0` | Delay between requests (seconds) |
| `--cookies` / `-c` | — | Cookie header string |
| `--cookies-alt` | — | Second account cookies for horizontal IDOR testing |
| `--headers` / `-H` | — | Custom header (repeatable) |
| `--auth` | — | Basic auth `user:pass` |
| `--proxy` | — | HTTP(S) proxy URL |
| `--no-verify-ssl` | off | Disable TLS verification |
| `--wordlist` | — | Extra paths for directory fuzzing |
| `--oob-host` | — | Out-of-band callback host for SSRF / SQLi / XXE / Cmd Injection / Blind XSS OOB verification |
| `--headless` | off | Use Playwright headless browser for JS-rendered crawling + XSS execution verification |
| `--rps` | `5.0` | Requests per second (halved on 429, restored after 20 OK) |
| `--stealth` | off | Rotate 20 User-Agent strings, random 0.5–2s delay, shuffle POST params |
| `--scope` | — | Path to scope file (one domain/IP/CIDR per line) |
| `--verify-only` / `-V` | — | Re-verify unconfirmed findings from a previous JSON report |
| `--triage-assist` | off | Use OpenAI to enhance impact narrative in markdown reports |
| `--module-param` | — | `module.key=value` overrides |
| `--retries` | `3` | HTTP retry count |
| `--autosave-interval` | `0` | Autosave partial report every N seconds |
| `--no-rich` | off | Disable Rich terminal output (plain text, good for CI/pipe) |
| `--max-js-files` | `50` | Max JS files to scan for secrets/endpoints |
| `--passive` | off | No active fuzzing |
| `--verbose` / `-v` | off | Per-request / per-finding logs |

---

## Finding format

Findings are produced by `finding()` (legacy) or `finding_v2()` (explicit stage scoring) in `modules/utils.py`:

```python
{
  "title": "Reflected XSS",
  "type": "Reflected XSS",
  "url": "https://example.com/?q=...",
  "severity": "high",             # critical | high | medium | low | info
  "details": "Payload reflected in response without sanitization",
  "evidence": "<svg/onload=alert(1)>",
  "confidence": "Probable",
  "confidence_score": 60,          # 0–100
  "verification_stage": "validated", # detected | validated | exploitable | verified
  "evidence_strength": "Moderate",  # Weak | Moderate | Strong | Verified
  "false_positive_risk": "Medium",  # Low | Medium | High
  "fingerprint": "<sha256>",
  "timestamp": "2026-06-04T12:00:00Z",
  "cvss_score": 6.1,
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
  "what_is_it": "User input is reflected in the HTML response body without encoding",
  "impact": "Session theft, phishing, or UI redressing via stored/reflected script execution",
  "remediation": "Apply context-aware output encoding; use Content-Security-Policy",
  "references": ["https://owasp.org/www-community/attacks/xss/"],
  "grouped_urls": ["https://...", "https://..."],
  "validation_steps": [
    "Payload reflected in response body without sanitization",
    "Context: HTML attribute — payload breaks out with \"><svg/onload=alert(1)>",
    "Browser execution verified via Playwright (screenshot captured)"
  ],
  "impact_assessment": {
    "data_exposure": {"score": 2, "label": "Medium (limited data)"},
    "account_takeover_potential": {"score": 5, "label": "Immediate takeover possible"},
    "rce_potential": {"score": 0, "label": "No risk"},
    "demonstrated_impact": "alert(1) in browser context",
    "narrative": "Business: Account takeover via session theft | Data exposure: Medium | ATO potential: Immediate takeover possible | RCE potential: No risk"
  }
}
```

The scanner deduplicates by **fingerprint** (same vuln type + parameter + root cause) and can **group** related hits across URLs into a single finding with `grouped_urls`.

### Confidence calculation

| Component | Weight |
|-----------|--------|
| Detection (reflection / error) | 25 pts |
| Validation (OOB callback / boolean diff / >4.5s delay) | 35 pts |
| Exploitation (screenshot / file read / live API call) | 40 pts |

**Stages:** `detected` (0–25) → `validated` (26–60) → `exploitable` (61–99) → `verified` (100)

### Verification stages

| Stage | Meaning |
|-------|---------|
| **Detected** | Payload reflected or error triggered; theoretical risk only |
| **Validated** | Multiple independent signals confirm the vulnerability exists |
| **Exploitable** | Demonstrated real-world impact; proof-of-concept evidence |
| **Verified** | Confirmed with strong evidence (screenshot, OOB callback, live secret) |

---

## Reports

| Format | Contents |
|--------|----------|
| **HTML** | Dark-themed dashboard with confidence badges, verification stage badges, severity summary, findings with evidence |
| **JSON** | Machine-readable full scan payload with confidence/verification/impact breakdown |
| **TXT** | Plain-text summary for terminals and CI |
| **Markdown** (`markdown-report`) | Per-finding `.md` files with CVSS, evidence, impact, remediation, validation steps |
| **HackerOne** (`hackerone`) | Ready-to-submit bug bounty report: per-finding sections, CVSS, evidence, impact, reproduction steps, FP risk |
| **Bugcrowd** (`bugcrowd`) | Summary table + per-finding detail with verification stage, confidence, and impact assessment |

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
├── main.py                          # CLI and orchestration
├── config.example.yaml              # Sample YAML configuration
├── IMPLEMENTATION_SUMMARY.md        # Implementation walkthrough & change log
├── IMPROVEMENTS.md                  # Detailed false-positive fixes & improvements
├── requirements.txt
├── requirements-headless.txt        # Playwright (optional, for --headless mode)
├── download.py                      # Payload download helper
├── Alternate_requirements_installer.py
├── payloads/
│   ├── xss.yaml
│   └── sqli.yaml
├── modules/
│   ├── __init__.py
│   ├── utils.py                     # HTTP helpers, finding(), finding_v2(), OOB, Dedup, TechFP, SecretValidator, BrowserValidator
│   ├── recon.py                     # Crawler, subdomain discovery, JS secret mining via JSIntelligence
│   ├── scanner.py                   # VulnScanner — XXE, Cmd Injection, Blind XSS, XSS, SQLi, SSRF, LFI, SSTI, etc.
│   ├── api_scanner.py               # ApiScanner — REST / GraphQL / OpenAPI checks
│   ├── idor.py                      # IdorScanner — IDOR / BOLA detection
│   ├── js_intelligence.py           # JSIntelligence — AST + regex endpoint/secret/route extraction
│   └── reporter.py                  # HTML / JSON / TXT / Markdown / HackerOne / Bugcrowd reports
└── reports/                         # Output (gitignored)
```

---

## Extending

**Inline scanner (add to `VulnScanner` in `modules/scanner.py`):**

1. Add `scan_mycheck(self) -> list[dict]` on `VulnScanner`.
2. Return findings via `self._record_confirmed(...)` or `finding(...)` and end with `return self._deduplicate(findings)`.
3. Register the module in `main.py` (`parse_args` choices + `_active_module_map` dict).
4. Optionally add metadata in `VULN_METADATA` inside `modules/utils.py`.

**Standalone scanner (subclass `VulnScanner`):**

For complex modules (e.g., `ApiScanner`, `IdorScanner`), create a new file under `modules/` that subclasses `VulnScanner` and implements `run_all(self) -> list[dict]`. Import and instantiate it in `_active_module_map` inside `main.py`.

Respect `url_in_scope()` in every URL loop and use `self._record_confirmed(...)` so fingerprint deduplication applies.

---

## Dependencies

| Package | Role |
|---------|-------|
| `requests` | HTTP client |
| `beautifulsoup4` | HTML parsing |
| `lxml` | Parser backend |
| `PyYAML` | Config files |
| `rich` | Terminal UI (progress, tables, colored logs) |
| `urllib3` | Retries and connection pooling |
| `tqdm` | Progress bars |
| `playwright` | (optional) Headless browser for JS-rendered crawling + XSS execution verification (`requirements-headless.txt`) |
| `esprima` | (optional) JavaScript AST parsing for enhanced JS intelligence |
| `boto3` | (optional) Live AWS key validation via STS |

---

## AI-Prompt Engineering for Impact Narratives

Every finding's impact and remediation text is built from static templates that interpolate the actual finding data — URL, parameter name, evidence excerpt, and business impact from the `IMPACT_MATRIX`. This means the output is deterministic, reproducible, and does not require any external API calls.

**How it works:**

1. `_build_impact_narrative(finding)` in `reporter.py` selects a severity-based template (critical/high/medium/low) and fills in `{url}`, `{parameter}`, and `{evidence}` from the finding.
2. If a finding has a custom `impact` string, it's used directly (and any `{url}`, `{parameter}`, `{evidence}` placeholders in it are interpolated).
3. `_build_remediation(finding)` works identically — interpolating `{url}` and `{parameter}` into remediation templates.

**Example output for a critical XSS finding:**

> This vulnerability at `https://example.com/search?q=` via parameter `q` poses a severe risk to confidentiality, integrity, and availability. Successful exploitation could lead to complete compromise of the application, including arbitrary code execution, data exfiltration, or full account takeover. Business impact: Account takeover via session theft, phishing, or UI redressing.

**To customize:** Edit the template strings in `_build_impact_narrative()` and `_build_remediation()` in `modules/reporter.py`. You can add `{url}`, `{parameter}`, `{evidence}`, or any key from the finding dict as a placeholder.

The old `--triage-assist` flag (OpenAI prompt-based narrative generation) has been removed in favor of these static but interpolated templates. The result is faster, cheaper, deterministic, and works entirely offline.

---

## Disclaimer

This software is for **education and authorized security testing** only. Obtain written permission before scanning any system. Authors and contributors are not liable for misuse or damages.

---

<div align="center">

Built for the bug bounty community · Use responsibly

</div>
