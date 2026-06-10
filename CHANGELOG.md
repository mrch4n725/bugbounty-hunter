# Changelog

## 1.0.0 (2026-06-10)

### Major Features

- **AuthSessionManager** — OAuth flow automation, JWT refresh handling, multi-role session management (admin/user/unauthenticated), CSRF token extraction and injection, login sequence replay with template-based value extraction
- **WAF evasion layer** — WAF fingerprinting (Cloudflare, Akamai, ModSecurity, AWS WAF, F5, Imperva, Sucuri, Wordfence), encoding/fragmentation strategy selection per WAF type, payload variant generation (base64, hex, unicode, UTF-7, HTML entities, case permutation, whitespace fragmentation, null byte injection, comment injection)
- **Technology-aware scanner registry** — Framework-specific probe sets for WordPress (xmlrpc SSRF, user enumeration, plugin SQLi, debug log), Spring Boot (actuator exposure, SpEL injection, heapdump, Swagger), Rails (mass assignment, CSRF forgery, send_file traversal), Laravel (debug mode, .env exposure, queue injection), GraphQL (batch abuse, alias bypass, depth attack)
- **Semantic response analysis** — PII detection (emails, phones, SSNs, passports, DOB, national IDs, medical IDs), financial data detection (credit cards with Luhn, bank accounts, IBANs, SWIFT, invoices, payment tokens), credential/API key detection (password hashes, AWS/GitHub/OpenAI/Slack keys, JWTs, connection strings), IDOR pair comparison with user-context cross-referencing
- **Headless browser recon** — Playwright-based SPA spidering with XHR/fetch capture, runtime parameter discovery (window.__INITIAL_STATE__, __NUXT__, __NEXT_DATA__), form-to-API mapping, framework detection (React/Vue/Angular/Nuxt/Next), API endpoint capture with auth token extraction
- **External intelligence gatherer** — Shodan/Censys port and service discovery, crt.sh certificate transparency subdomain enumeration, Wayback Machine historical endpoint discovery, GitHub code leak search with API key/token/credential matching
- **Request smuggling scanner** — CL.TE, TE.CL, TE.TE obfuscation variants, HTTP/2 downgrade smuggling, raw TCP connection testing with SSL support, response differential analysis for confirmation
- **Business logic testing** — Workflow state-graph analyzer (form sequences, redirect chains, multi-step flows), race condition detection via concurrent request flooding, step-skip/reorder/repeat testing with state validation
- **Per-finding evidence export** — Single finding HTML export with all typed evidence, curl commands, reproduction steps, evidence bundle metadata, and copy-to-clipboard curl button
- **Submission prioritisation queue** — Combined severity/confidence/evidence-strength/validation-rate scoring, ranked submission queue, per-vuln-type detection-to-validation ratio integration
- **Payload intelligence tracker** — Payload effectiveness recording by tech stack and WAF profile, historical success-rate weighting, optimal-payload selection
- **Cross-scan finding database** — SHA-256 fingerprint persistence across scans, first-seen/last-seen/still-present tracking, regression detection for previously patched findings
- **Scan audit log** — Every request recorded with timestamp, method, URL, headers, status code to audit file
- **CI/CD modes** — JSON diff between scan outputs, GitHub Actions PR annotation formatter, Slack/Discord webhook for high-confidence findings
- **Mobile API mode** — Burp Suite XML export and Charles Proxy session ingestion, custom auth header normalisation, certificate pinning bypass marker handling
- **Passive analysis mode** — HAR file and Burp XML import, parameter/endpoint/response-pattern analysis, prioritised active-test candidate list generation
- **Operational security** — Footprint profile system (stealth/normal/aggressive), User-Agent rotation, scan delay jitter, request signing header support, IP rotation hooks

### Scanner Improvements

- **7 uplifted scanners** — XSS, SQLi, SSRF, LFI, SSTI, CMDI, XXE expanded with new detection signals, FP hardening pre-checks, signal counting, and recon-driven parameter targeting
- **Per-vuln-type metrics** — Detection coverage and validation rate tracking per vulnerability type with `needs attention` flagging
- **Recon-driven parameter targeting** — All parameters scanned; recon signals reorder priority (JS context, REST patterns, URL-like values, file-path keywords, template-context keywords)
- **Signal counting** — Independent detection signals tracked per finding (up to 7 for SQLi, 6 for XXE, 5 for SSRF, 4 for XSS/CMDI/LFI/SSTI)

### Evidence & Reporting

- **Evidence export** — Per-finding self-contained HTML with evidence bundle, curl commands, reproduction steps
- **Submission queue** — Ranked by combined score with severity/confidence/evidence-strength weighting
- **Audit log** — Per-request CSV audit trail in output directory

### Fixes

- Fixed duplicate risk rendering in reports
- Fixed evidence enrichment fallback chain
- Fixed timing evidence field names across all reporter formats
- Fixed OwnershipEvidence and ImpactEvidence attachment in main.py
- Fixed ReplayEngine no-op (build_bundle now called before comparison)
