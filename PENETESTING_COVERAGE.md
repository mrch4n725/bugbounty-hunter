# Penetration Testing Coverage

## Detection Coverage by Vulnerability Type

### XSS (`xss.py`)
| Signal | Probed | FP Pre-check | Validation |
|--------|--------|-------------|------------|
| Reflected XSS (HTML/attribute/JS/URL context) | ✓ | Canary pre-probe, baseline reflection | Browser execution |
| DOM fragment XSS (`#<script>`, `#"><img>`, `#<svg>`) | ✓ | `location.hash/href/window.location` gate | Browser execution |
| JSON reflection XSS | ✓ | `text/html` Content-Type filter | Context match |
| SVG XSS (`<svg/onload=alert(1)>`) | ✓ | Part of XSS_PAYLOADS | Browser execution |
| Stored XSS (form submission → re-fetch) | ✓ | Baseline body comparison | Browser execution |
| WAF bypass variants (HTML entities, case mix, etc.) | ✓ | Conditional on WAF detection | N/A |
| Framework-specific (React, Angular, Vue, jQuery) | ✓ | Canary pre-probe | N/A |
| **Signal count** | Up to 4: reflected + DOM fragment + JSON reflection + SVG |

Recon targeting: JS endpoint context from `js_endpoints` and `js_urls` — params referenced in JS files scanned first.

---

### SQLi (`sqli.py`)
| Signal | Probed | FP Pre-check | Validation |
|--------|--------|-------------|------------|
| Error-based SQLi | ✓ | Baseline error subtraction | Multi-signal (2+) |
| Boolean-based SQLi | ✓ | Baseline MD5 hash | Multi-signal (2+) |
| Time-based SQLi | ✓ | Baseline timing (min 4s threshold) | Multi-signal (3+) |
| Union-based SQLi | ✓ | `ORDER BY` no-error + column count | Multi-signal (2+) |
| OOB SQLi (DNS callback) | ✓ | OOB framework required | VERIFIED on callback |
| Second-order SQLi (POST → GET) | ✓ | Baseline error subtraction; dual cycle | Dual probe (2 cycles) |
| Header-based SQLi (X-Forwarded-For, User-Agent, etc.) | ✓ | Header reflection gate + differential | Benign header diff |
| JSON body SQLi | ✓ | Baseline error + status 200 + non-login | Boolean + time follow-up |
| XML body SQLi | ✓ | Baseline error subtraction | Single signal |
| Form body SQLi | ✓ | Baseline error subtraction | Single signal |
| **Signal count** | Up to 7: error + boolean + time + OOB + second-order + header + JSON body |

Recon targeting: RESTful path patterns (`/users/{id}`), numeric params, SQL-keyword params (`id`, `query`, `search`), baseline timing priority.

---

### SSRF (`ssrf.py`)
| Signal | Probed | FP Pre-check | Validation |
|--------|--------|-------------|------------|
| AWS metadata (IMDSv1) | ✓ | Baseline MD5 hash diff | Multi-signature match |
| AWS IMDSv2 | ✓ | Header-based token request | N/A |
| GCP metadata | ✓ | `Metadata-Flavor: Google` header | Multi-signature match |
| Azure metadata | ✓ | `Metadata: true` header | Multi-signature match |
| Alibaba/DO/OpenStack/Oracle metadata | ✓ | Baseline diff | Single signature |
| Redirect-based SSRF | ✓ | Baseline status/length diff | Metadata verification |
| Protocol smuggling (gopher://, dict://, file://) | ✓ | Baseline hash diff + status check | N/A |
| DNS rebinding timing | ✓ | Internal vs. non-routable timing diff | N/A |
| Internal port scanning (Redis, MySQL, etc.) | ✓ | Status code filter (no 502/503/504) | Service response |
| OOB callback (DNS/HTTP) | ✓ | OOB framework required | VERIFIED on callback |
| **Signal count** | Up to 5: metadata + redirect + protocol smuggling + DNS timing + OOB |

Recon targeting: Params with `://` values get priority; SSRF_PARAM_NAMES (`url`, `uri`, `path`, etc.) sorted next.

---

### LFI (`lfi.py`)
| Signal | Probed | FP Pre-check | Validation |
|--------|--------|-------------|------------|
| Path traversal (Unix: `/etc/passwd`, `/etc/shadow`, etc.) | ✓ | Baseline signature subtraction | Multi-signature (2+) or cross-payload |
| Path traversal (Windows: `win.ini`, `boot.ini`) | ✓ | Baseline signature subtraction | Multi-signature (2+) |
| PHP wrappers (`php://filter`, `expect://`, `file://`) | ✓ | Baseline body diff + base64 decode | Decoded content check |
| Double/URL encoding bypass | ✓ | Baseline diff | N/A |
| Log poisoning (Apache/Nginx access log) | ✓ | PHP detection + User-Agent injection | `BBH_TEST_POISON` in log |
| `/proc/self/` filesystem (`environ`, `cmdline`, `fd/0`) | ✓ | Baseline body check | Content structure check |
| Zip slip (`%00.zip` null byte) | ✓ | Baseline subtraction | N/A |
| **Signal count** | Up to 3: traversal + log poisoning + /proc/self |

Recon targeting: Classic file-path params (`file`, `path`, `read`, `include`, `page`, `document`) get priority.

---

### SSTI (`ssti.py`)
| Signal | Probed | FP Pre-check | Validation |
|--------|--------|-------------|------------|
| Arithmetic evaluation (`{{7*7}}`, `${7*7}`, `<%=7*7%>`, `#{7*7}`) | ✓ | Baseline value pre-check (`49`, `14`); template syntax reflection | Dual arithmetic (2nd payload) |
| Polyglot probes (`{{7*'7'}}${7*7}#{7*7}*{7*7}`) | ✓ | Reflection gate | Dual arithmetic |
| Engine fingerprint (Twig, Jinja2, FreeMarker, Velocity, Razor, Smarty, Mustache) | ✓ | N/A | Engine-specific payload + regex |
| Error fingerprint (jinja2.exceptions, freemarker.core, etc.) | ✓ | N/A | Engine name from error |
| Filter bypass (`{%raw%}`, unicode `｛｝`, class chain) | ✓ | Standard arithmetic failed | Dual arithmetic |
| Read-proof (`{{config}}`, `self._TemplateReference__context`) | ✓ | N/A | >500 char response |
| **Signal count** | Up to 3: arithmetic + fingerprint + read-proof |

Recon targeting: Template-context params (`name`, `message`, `content`, `template`, `view`) get priority.

---

### Command Injection (`command_injection.py`)
| Signal | Probed | FP Pre-check | Validation |
|--------|--------|-------------|------------|
| Unix output-based (`; id`, `\| id`, `` `id` ``, `$(id)`) | ✓ | Baseline diff (signature `uid=`) | Multi-signal (2+) |
| Windows output-based (`\| ver`, `& ver`, `\| dir`) | ✓ | IIS/ASP.NET platform detection | Multi-signal (2+) |
| Time-based (`; sleep 5`, `\| sleep 5`, etc.) | ✓ | Baseline timing (4s threshold) | Multi-signal (2+) |
| OOB (nslookup, dig, curl, wget, PowerShell, etc.) | ✓ | OOB framework required | VERIFIED on callback |
| Argument injection (`--help`, `-version`, `;id`, `\|id`) | ✓ | Tool keyword params (`file`, `path`, etc.) | Tool output signatures |
| Windows cmd (`^whoami^`, `%26whoami%26`) | ✓ | Platform detection (IIS/ASP.NET) | `nt authority` in response |
| **Signal count** | Up to 4: output + time + OOB + argument injection |

Recon targeting: Command-like params (`cmd`, `exec`, `run`, `shell`, `file`, `path`) get priority.

---

### XXE (`xxe.py`)
| Signal | Probed | FP Pre-check | Validation |
|--------|--------|-------------|------------|
| In-band XXE (file read via entity) | ✓ | Multiple Content-Type variants | File signature match |
| Error-based XXE (file content via parser error) | ✓ | N/A | File signature match |
| OOB XXE (parameter entity + DTD) | ✓ | OOB framework required | VERIFIED on callback |
| SVG upload XXE | ✓ | SVG extension check on URL | File signature match |
| XInclude (xi:include bypass) | ✓ | N/A | File signature match |
| SOAP/XML-RPC XXE | ✓ | Multiple SOAPAction values | File signature match |
| JSON-to-XML conversion XXE | ✓ | JSON endpoint indicator check; JSON baseline first | File signature match |
| **Signal count** | Up to 6: in-band + error + XInclude + SVG + SOAP + JSON-to-XML |

Recon targeting: XML endpoints (`.xml`, `.soap`, `.wsdl`) and XML-like param names (`xml`, `data`, `soap`) get priority.

---

## Validation Depth

| Scanner | DETECTED | VALIDATED | EXPLOITABLE | VERIFIED | Maturity |
|---------|----------|-----------|-------------|----------|----------|
| XSS | Reflection | Context match | — | Browser execution | 4 |
| SQLi | 1 signal | 2+ signals | 3+ signals | OOB callback | 4 |
| SSRF | Metadata sig | 2+ sigs | — | OOB callback | 4 |
| LFI | 1 sig | 2+ sigs or cross-payload | Log poison / /proc/self | — | 3 |
| SSTI | Arithmetic | Engine fingerprint | Read-proof output | — | 4 |
| CMDI | 1 signal | 2+ signals | — | OOB callback | 4 |
| XXE | — | File content | — | OOB callback | 4 |

## FP Hardening Pre-checks

| Pre-check | Scanners | Mechanism |
|-----------|----------|-----------|
| Baseline reflection check | XSS, SSTI | Send canary/reflection test before payload |
| Baseline error subtraction | SQLi, LFI, XXE | Subtract errors present in baseline response |
| Baseline hash comparison | SSRF, LFI | MD5 hash diff between baseline and probe |
| Baseline timing measurement | SQLi, CMDI | Baseline response time before time-based probes |
| Content-Type filter | XSS (JSON reflection) | Only flag if `text/html` response |
| Header reflection gate | SQLi (header) | Probe header reflects or Vary header present |
| Platform detection | CMDI (Windows) | IIS/ASP.NET server headers |
| URL extension gate | XXE (SVG upload) | SVG extension check before probe |
| Pre-existing value check | SSTI | Skip if `49`/`14` already in baseline |
| Differential comparison | SQLi (header), SSRF | Benign vs. malicious value comparison |
| Login/redirect filter | SQLi (POST body) | Skip if response contains login page |
| Parameter name gate | LFI, CMDI, SSTI, XXE | Skip probes on non-matching param names |

## Signal Counting Rules

```
Scanner        Max signals  Signals tracked
────────────────────────────────────────────────
XSS            4            reflected, DOM fragment, JSON reflection, SVG
SQLi           7            error, boolean, time, OOB, second-order, header, JSON body
SSRF           5            metadata, redirect, protocol smuggling, DNS timing, OOB
LFI            3            traversal, log poisoning, /proc/self
SSTI           3            arithmetic, fingerprint, read-proof
CMDI           4            output, time, OOB, argument injection
XXE            6            in-band, error, XInclude, SVG, SOAP, JSON-to-XML
```

## Recon-Driven Targeting

| Scanner | Recon signal | Priority params |
|---------|-------------|-----------------|
| XSS | JS endpoint context | Params referenced in JS files |
| SQLi | RESTful path patterns + baseline timings | Numeric/ID params, slow-query params |
| SSRF | URL-like param values | Params with `://` values |
| CMDI | Tool/file-path keyword matching | `cmd`, `exec`, `run`, `shell`, `file`, `path` |
| XXE | XML endpoint detection + param name | `.xml`/`.soap` URLs, `xml`/`data`-named params |
| LFI | File-path keyword matching | `file`, `path`, `read`, `include`, `page` |
| SSTI | Template-context keyword matching | `name`, `message`, `content`, `template`, `view` |

All parameters are scanned — recon signals only **reorder**, never exclude.

## Metrics Collection

Post-scan, `PipelineMetrics` produces a per-vuln-type table:

```
Vuln Type       Detected  Validated  Rate      Status
──────────────── ────────  ─────────  ─────     ────────────
xss             12        8          0.67      ✓
sqli            5         1          0.20      ← needs attention
```

Scanners with `validation_rate < 0.5` and `detected >= 2` are flagged for attention. Metrics are computed from `signal_count` stored on each finding.
