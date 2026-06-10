"""Semantic response classifier — PII, financial, credential, and IDOR analysis.

Detects sensitive data in HTTP response bodies using compiled regex libraries.
Provides IDOR pair comparison and response classification for the scanner pipeline.

Usage:
    from engines.semantic_analyzer import SemanticResponseAnalyzer, ClassificationResult
    analyzer = SemanticResponseAnalyzer()
    result = analyzer.classify_response(body, url)
"""

from __future__ import annotations

import csv
import io
import json
import re
import threading
from dataclasses import dataclass, field
from typing import Any, ClassVar


# ── Helpers ─────────────────────────────────────────────────────────────────

_STRIP_TAGS = re.compile(r"<[^>]+>", re.UNICODE)
_WHITESPACE = re.compile(r"\s+")
_NON_ALPHA = re.compile(r"[^a-zA-Z0-9 ]")


def _strip_html(text: str) -> str:
    return _WHITESPACE.sub(" ", _STRIP_TAGS.sub("", text)).strip()


def _context_window(text: str, pos: int, width: int = 60) -> str:
    start = max(0, pos - width)
    end = min(len(text), pos + width)
    return text[start:end].replace("\n", " ")


def _overlapping(match_a: re.Match, match_b: re.Match) -> bool:
    """Return True if two regex matches overlap in the source text."""
    a_start, a_end = match_a.start(), match_a.end()
    b_start, b_end = match_b.start(), match_b.end()
    return a_start < b_end and b_start < a_end


# ── Luhn check ──────────────────────────────────────────────────────────────

def _luhn_checksum(card_number: str) -> bool:
    digits = [int(ch) for ch in card_number if ch.isdigit()]
    if len(digits) < 12 or len(digits) > 19:
        return False
    alt = False
    total = 0
    for d in reversed(digits):
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


# ── ClassificationResult ────────────────────────────────────────────────────

@dataclass
class ClassificationResult:
    response_type: str = "unknown"
    sensitivity_score: int = 0
    patterns: list[dict[str, Any]] = field(default_factory=list)
    categories_detected: set[str] = field(default_factory=set)
    context: dict[str, Any] = field(default_factory=dict)


# ── Pattern library entry ───────────────────────────────────────────────────

@dataclass
class _Pattern:
    name: str
    category: str
    regex: re.Pattern[str]
    weight: int
    description: str = ""
    priority: int = 0  # higher = checked first, can suppress lower-priority overlaps


# ── SemanticResponseAnalyzer ────────────────────────────────────────────────

class SemanticResponseAnalyzer:
    """Detect PII, financial, credential, and internal data in HTTP responses."""

    # ── PERSONAL patterns ──────────────────────────────────────────────────

    _EMAIL_RE = re.compile(
        r"(?<![a-zA-Z0-9])[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9]"
        r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]"
        r"{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}(?![a-zA-Z])",
        re.UNICODE,
    )
    _PHONE_RE = re.compile(
        r"(?<![A-Za-z0-9])"
        r"(?:"
        r"(?:\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}"
        r"|"
        r"(?:\+?44[\s.-]?0?7\d{3}[\s.-]?\d{6})"
        r"|"
        r"(?:\+?91[\s.-]?\d{5}[\s.-]?\d{5})"
        r")"
        r"(?![A-Za-z0-9])",
    )
    _SSN_RE = re.compile(
        r"(?<!\d)(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}(?!\d)",
    )
    _US_PASSPORT_RE = re.compile(r"(?<![A-Za-z0-9])(\d{9})(?![A-Za-z0-9])")
    _UK_PASSPORT_RE = re.compile(
        r"(?<![A-Za-z0-9])(\d{9})(?![A-Za-z0-9])",
    )
    _DOB_RE = re.compile(
        r"(?i)"
        r"(?:"
        r"(?:dob|date_of_birth|birth(?:date|_date)?|birthday)"
        r"[\s\":,=]*(?::|=>|=)?\s*"
        r"(\d{4}[-/]\d{2}[-/]\d{2}|\d{2}[-/]\d{2}[-/]\d{4})"
        r")",
    )
    _AADHAAR_RE = re.compile(
        r"(?<!\d)\d{4}\s?\d{4}\s?\d{4}(?!\d)",
    )
    _UK_NIN_RE = re.compile(
        r"(?<![A-Za-z0-9])[A-Za-z]{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-Za-z](?![A-Za-z0-9])",
    )
    _CPF_RE = re.compile(
        r"(?<!\d)\d{3}\.?\d{3}\.?\d{3}-?\d{2}(?!\d)",
    )
    _CNPJ_RE = re.compile(
        r"(?<!\d)\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2}(?!\d)",
    )
    _STREET_ADDRESS_RE = re.compile(
        r"(?i)"
        r"\d{1,5}\s+[A-Za-z0-9\s.'-]+?"
        r"(?<![A-Za-z])"
        r"(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|"
        r"Way|Court|Ct|Place|Pl|Circle|Cir|Highway|Hwy|Parkway|Pkwy|"
        r"Square|Sq|Terrace|Ter|Trail|Trl|Run|Row|Crescent|Cres)"
        r"(?![A-Za-z])"
        r"(?:\s*,?\s*(?:[A-Za-z\s]+)\s*,?\s*"
        r"(?:[A-Z]{2}|[A-Za-z\s]+)\s*,?\s*\d{5}(?:-\d{4})?)?",
    )
    _MRN_RE = re.compile(
        r"(?i)"
        r"(?:mrn|medical.?record.?number|patient.?id|chart.?number)"
        r"[\s\":,=]*(?::|=>|=)?\s*([A-Za-z0-9-]{4,20})",
    )
    _ICD_CODE_RE = re.compile(
        r"(?<![A-Za-z0-9])[A-Z]\d{2}(?:\.\d{1,2})?(?![A-Za-z0-9])",
    )

    # ── FINANCIAL patterns ─────────────────────────────────────────────────

    _CC_VISA_RE = re.compile(r"(?<!\d)4\d{12}(?:\d{3})?(?!\d)")
    _CC_MC_RE = re.compile(r"(?<!\d)(?:5[1-5]\d{14}|2(?:2[2-9][1-9]|[3-6]\d{2}|7[01]\d|720)\d{12})(?!\d)")
    _CC_AMEX_RE = re.compile(r"(?<!\d)3[47]\d{13}(?!\d)")
    _CC_DISCOVER_RE = re.compile(r"(?<!\d)(?:6011\d{12}|65\d{14}|64[4-9]\d{13})(?!\d)")
    _CC_JCB_RE = re.compile(r"(?<!\d)(?:2131|1800|35\d{3})\d{11}(?!\d)")
    _ROUTING_RE = re.compile(r"(?<!\d)\d{9}(?!\d)")
    _IBAN_RE = re.compile(
        r"(?<![A-Za-z0-9])[A-Z]{2}\d{2}[A-Za-z0-9]{11,30}(?![A-Za-z0-9])",
    )
    _SWIFT_RE = re.compile(
        r"(?<![A-Za-z0-9])[A-Z]{4}[A-Z]{2}[A-Za-z0-9]{2}(?:[A-Za-z0-9]{3})?(?![A-Za-z0-9])",
    )
    _AMOUNT_RE = re.compile(
        r"(?i)"
        r"(?:"
        r"(?:\$|EUR|GBP|USD|INR|JPY|CNY)\s*\d{1,3}(?:,\d{3})*(?:\.\d{1,2})?"
        r"|"
        r"\d{1,3}(?:,\d{3})*(?:\.\d{2})?\s*(?:USD|EUR|GBP|INR|JPY|CNY)"
        r")",
    )
    _INVOICE_RE = re.compile(
        r"(?i)"
        r"(?:INV(?:OICE)?[-_.\s]?\d{4,12})",
    )
    _PAYMENT_TOKEN_RE = re.compile(
        r"(?i)"
        r"(?<![A-Za-z0-9])"
        r"(?:tok_|pm_|src_|card_|pi_|py_|ch_|cus_|sub_|plan_|in_|ii_|"
        r"txn_|sli_|evt_|acct_|cn_|cs_|cp_|ba_|bt_|we_|wr_)"
        r"[A-Za-z0-9_]{10,32}"
        r"(?![A-Za-z0-9])",
    )

    # ── CREDENTIAL patterns ────────────────────────────────────────────────

    _BCRYPT_RE = re.compile(
        r"(?<![A-Za-z0-9/$])\$2[aby]\$\d{2}\$[A-Za-z0-9./]{53}(?![A-Za-z0-9./$])",
    )
    _DJANGO_HASH_RE = re.compile(
        r"(?i)(?<![A-Za-z0-9])sha256\$\d+\$[A-Za-z0-9]+\$[A-Za-z0-9]+(?![A-Za-z0-9])",
    )
    _PBKDF2_RE = re.compile(
        r"(?i)(?<![A-Za-z0-9])PBKDF2\$[A-Za-z0-9]+\$[A-Za-z0-9]+(?![A-Za-z0-9])",
    )
    _OPENAI_KEY_RE = re.compile(
        r"(?<![A-Za-z0-9])sk-[A-Za-z0-9_-]{20,}(?![A-Za-z0-9])",
    )
    _GITHUB_KEY_RE = re.compile(
        r"(?<![A-Za-z0-9])(?:ghp_|gho_|ghu_|ghs_|ghr_)[A-Za-z0-9]{36}(?![A-Za-z0-9])",
    )
    _AWS_KEY_RE = re.compile(
        r"(?<![A-Za-z0-9])AKIA[0-9A-Z]{16}(?![A-Za-z0-9])",
    )
    _SLACK_TOKEN_RE = re.compile(
        r"(?<![A-Za-z0-9])xox[abprs]-[A-Za-z0-9]{10,}(?![A-Za-z0-9])",
    )
    _JWT_RE = re.compile(
        r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+(?![A-Za-z0-9_-])",
    )
    _BEARER_RE = re.compile(
        r"(?i)Bearer\s+[A-Za-z0-9_=.-]{20,200}",
    )
    _OAUTH_GOOGLE_RE = re.compile(
        r"(?<![A-Za-z0-9])ya29\.[A-Za-z0-9_-]{30,}(?![A-Za-z0-9])",
    )
    _OAUTH_FACEBOOK_RE = re.compile(
        r"(?<![A-Za-z0-9])EAA[A-Za-z0-9]{30,}(?![A-Za-z0-9])",
    )
    _CONNECTION_STRING_RE = re.compile(
        r"(?i)"
        r"(?:postgresql|postgres|mysql|mongodb|redis|amqp|rabbitmq)://"
        r"(?:[A-Za-z0-9_%-]+(?::[A-Za-z0-9_%-]+)?@)?"
        r"[A-Za-z0-9.-]+(?::\d+)?(?:/[A-Za-z0-9_%-]+)?",
    )

    # ── DRIVER'S LICENSE patterns (US state-specific) ──────────────────────

    _DL_PATTERNS: ClassVar[dict[str, re.Pattern[str]]] = {
        "CA": re.compile(r"(?<![A-Za-z0-9])[A-Z]\d{7}(?![A-Za-z0-9])"),
        "NY": re.compile(r"(?<![A-Za-z0-9])\d{8}(?![A-Za-z0-9])"),
        "TX": re.compile(r"(?<![A-Za-z0-9])\d{8}(?![A-Za-z0-9])"),
        "FL": re.compile(r"(?<![A-Za-z0-9])[A-Z]\d{12}(?![A-Za-z0-9])"),
        "IL": re.compile(r"(?<![A-Za-z0-9])\d{10}(?![A-Za-z0-9])"),
        "OH": re.compile(r"(?<![A-Za-z0-9])[A-Z]{2}\d{6}(?![A-Za-z0-9])"),
        "MI": re.compile(r"(?<![A-Za-z0-9])[A-Z]\d{10}(?![A-Za-z0-9])"),
        "PA": re.compile(r"(?<![A-Za-z0-9])\d{8}(?![A-Za-z0-9])"),
    }

    # ── Pattern library (ordered by category; higher-priority first) ───────

    PATTERNS: ClassVar[list[_Pattern]] = [
        # Credential (highest priority — checked first)
        _Pattern("bcrypt_hash", "credential", _BCRYPT_RE, 25, "Bcrypt password hash", priority=100),
        _Pattern("django_hash", "credential", _DJANGO_HASH_RE, 25, "Django password hash", priority=100),
        _Pattern("pbkdf2_hash", "credential", _PBKDF2_RE, 25, "PBKDF2 hash", priority=100),
        _Pattern("openai_key", "credential", _OPENAI_KEY_RE, 25, "OpenAI API key", priority=90),
        _Pattern("github_token", "credential", _GITHUB_KEY_RE, 25, "GitHub token", priority=90),
        _Pattern("aws_key", "credential", _AWS_KEY_RE, 25, "AWS access key", priority=90),
        _Pattern("slack_token", "credential", _SLACK_TOKEN_RE, 25, "Slack token", priority=90),
        _Pattern("jwt", "credential", _JWT_RE, 20, "JWT session token", priority=90),
        _Pattern("bearer_token", "credential", _BEARER_RE, 20, "Bearer token", priority=100),
        _Pattern("oauth_google", "credential", _OAUTH_GOOGLE_RE, 25, "Google OAuth token", priority=90),
        _Pattern("oauth_facebook", "credential", _OAUTH_FACEBOOK_RE, 25, "Facebook OAuth token", priority=90),
        _Pattern("conn_string", "credential", _CONNECTION_STRING_RE, 20, "Database connection string", priority=90),
        # Financial
        _Pattern("iban", "financial", _IBAN_RE, 18, "IBAN", priority=80),
        _Pattern("swift_bic", "financial", _SWIFT_RE, 15, "SWIFT/BIC code", priority=80),
        _Pattern("cc_visa", "financial", _CC_VISA_RE, 20, "Visa card number", priority=70),
        _Pattern("cc_mastercard", "financial", _CC_MC_RE, 20, "Mastercard number", priority=70),
        _Pattern("cc_amex", "financial", _CC_AMEX_RE, 20, "American Express number", priority=70),
        _Pattern("cc_discover", "financial", _CC_DISCOVER_RE, 20, "Discover card number", priority=70),
        _Pattern("cc_jcb", "financial", _CC_JCB_RE, 20, "JCB card number", priority=70),
        _Pattern("routing_number", "financial", _ROUTING_RE, 10, "Bank routing number", priority=60),
        _Pattern("amount", "financial", _AMOUNT_RE, 8, "Monetary amount", priority=50),
        _Pattern("invoice", "financial", _INVOICE_RE, 10, "Invoice number", priority=60),
        _Pattern("payment_token", "financial", _PAYMENT_TOKEN_RE, 18, "Payment token", priority=70),
        # Personal
        _Pattern("ssn", "personal", _SSN_RE, 20, "US Social Security number", priority=80),
        _Pattern("aadhaar", "personal", _AADHAAR_RE, 20, "Indian Aadhaar number", priority=80),
        _Pattern("uk_nin", "personal", _UK_NIN_RE, 18, "UK National Insurance number", priority=80),
        _Pattern("us_passport", "personal", _US_PASSPORT_RE, 18, "US Passport number", priority=70),
        _Pattern("uk_passport", "personal", _UK_PASSPORT_RE, 18, "UK Passport number", priority=70),
        _Pattern("cpf", "personal", _CPF_RE, 15, "Brazilian CPF", priority=60),
        _Pattern("cnpj", "personal", _CNPJ_RE, 15, "Brazilian CNPJ", priority=60),
        _Pattern("phone", "personal", _PHONE_RE, 12, "Phone number", priority=60),
        _Pattern("email", "personal", _EMAIL_RE, 15, "Email address", priority=60),
        _Pattern("dob", "personal", _DOB_RE, 15, "Date of birth", priority=50),
        _Pattern("street_address", "personal", _STREET_ADDRESS_RE, 10, "Physical address", priority=40),
        _Pattern("mrn", "personal", _MRN_RE, 18, "Medical record number", priority=60),
        _Pattern("icd_code", "personal", _ICD_CODE_RE, 5, "ICD medical code", priority=30),
    ]

    # ── False-positive exclusion set ───────────────────────────────────────

    _FP_EXCLUSIONS: ClassVar[set[str]] = {
        "example@example.com", "user@example.com", "admin@example.com",
        "test@test.com", "email@example.com",
        "000-00-0000", "123-45-6789", "111-11-1111",
        "222-22-2222", "333-33-3333", "444-44-4444",
        "555-55-5555", "666-66-6666", "777-77-7777",
        "888-88-8888", "999-99-9999",
        "$2a$10$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ12345",
        "sk-example", "sk-test", "ghp_example",
        "AKIAIOSFODNN7EXAMPLE",
        "eyJhbGciOiJIUzI1NiJ9.eyJ0ZXN0IjoiMSJ9.abc123",
    }

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._pattern_cache: dict[str, list[dict[str, Any]]] = {}
        # Sort patterns by priority descending for overlap suppression
        self._sorted_patterns = sorted(self.PATTERNS, key=lambda p: -p.priority)

    # ── Public API ─────────────────────────────────────────────────────────

    def classify_response(
        self,
        response_body: str,
        url: str = "",
        user_context: dict | None = None,
    ) -> ClassificationResult:
        """Scan *response_body* for all PII, financial, and credential patterns.

        Returns a *ClassificationResult* with matched patterns, sensitivity
        score, and detected categories.
        """
        if not response_body or not response_body.strip():
            return ClassificationResult(response_type="empty", sensitivity_score=0)

        body_lower = response_body.lower()
        stripped = _strip_html(response_body)
        all_patterns: list[dict[str, Any]] = []

        personal_found: list[str] = []
        financial_found: list[str] = []
        credential_found: list[str] = []
        dedup_seen: set[str] = set()
        # Track occupied (start, end) ranges to skip overlaps
        occupied: list[tuple[int, int]] = []

        for pat in self._sorted_patterns:
            try:
                result = self._scan_pattern(
                    pat, response_body, body_lower, stripped, occupied,
                )
            except Exception:
                continue
            if result is None:
                continue
            matched_values, match_ranges = result

            seen_key = f"{pat.name}:{matched_values[0]}"
            if seen_key in dedup_seen:
                continue
            dedup_seen.add(seen_key)

            # Register occupied ranges from this pattern
            for rng in match_ranges:
                occupied.append(rng)

            all_patterns.append({
                "pattern": pat.name,
                "category": pat.category,
                "value": matched_values[0],
                "weight": pat.weight,
                "count": len(matched_values),
                "context": _context_window(response_body, match_ranges[0][0]),
            })
            if pat.category == "personal":
                personal_found.append(pat.name)
            elif pat.category == "financial":
                financial_found.append(pat.name)
            elif pat.category == "credential":
                credential_found.append(pat.name)

        # Luhn validation for credit card patterns
        cc_names = {"cc_visa", "cc_mastercard", "cc_amex", "cc_discover", "cc_jcb"}
        luhn_valid = []
        for p in all_patterns:
            if p["pattern"] in cc_names:
                digits_only = re.sub(r"\D", "", p["value"])
                if not _luhn_checksum(digits_only):
                    continue
            luhn_valid.append(p)
        all_patterns = luhn_valid

        # DL patterns checked last (lowest priority, generic)
        for state_code, dl_re in self._DL_PATTERNS.items():
            for m in dl_re.finditer(response_body):
                value = m.group(0)
                if value in self._FP_EXCLUSIONS:
                    continue
                seen_key = f"dl_{state_code}:{value}"
                if seen_key in dedup_seen:
                    continue
                if self._ranges_overlap(m.start(), m.end(), occupied):
                    continue
                dedup_seen.add(seen_key)
                occupied.append((m.start(), m.end()))
                all_patterns.append({
                    "pattern": f"dl_{state_code}",
                    "category": "personal",
                    "value": value,
                    "weight": 14,
                    "count": 1,
                    "context": _context_window(response_body, m.start()),
                })
                personal_found.append(f"dl_{state_code}")

        categories: set[str] = set()
        if personal_found:
            categories.add("personal_data")
        if financial_found:
            categories.add("financial_data")
        if credential_found:
            categories.add("credentials")

        response_type = self._infer_response_type(
            response_body, body_lower, stripped, categories, all_patterns,
        )

        sensitivity = self._compute_sensitivity(all_patterns, categories)

        return ClassificationResult(
            response_type=response_type,
            sensitivity_score=sensitivity,
            patterns=all_patterns,
            categories_detected=categories,
            context={
                "url": url,
                "body_length": len(response_body),
                "pattern_count": len(all_patterns),
                "sensitivity_level": self._sensitivity_level(sensitivity),
            },
        )

    # ── IDOR pair analysis ─────────────────────────────────────────────────

    def compare_responses(
        self,
        original_response: str,
        target_response: str,
        original_user_context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Compare two responses for data belonging to different users.

        Returns a dict with:
            - data_exposure: bool — target has PII that original does not
            - user_data_leak: bool — original user's identity found in target
            - matched_patterns: list of pattern dicts
            - confidence: str (high/medium/low)
        """
        if not target_response:
            return {
                "data_exposure": False,
                "user_data_leak": False,
                "matched_patterns": [],
                "confidence": "low",
                "reason": "empty target response",
            }

        orig_classification = self.classify_response(original_response)
        target_classification = self.classify_response(target_response)

        orig_values = {p["value"] for p in orig_classification.patterns}
        target_unique = [
            p for p in target_classification.patterns
            if p["value"] not in orig_values
        ]

        data_exposure = bool(
            target_unique
            and target_classification.sensitivity_score > max(
                orig_classification.sensitivity_score, 10,
            )
        )

        user_data_leak = False
        if original_user_context:
            user_data_leak = self._check_user_context_leak(
                target_response, original_user_context,
            )

        patterns_found = [
            {
                "pattern": p["pattern"],
                "value": p["value"][:80] + "..." if len(p["value"]) > 80 else p["value"],
                "category": p["category"],
                "weight": p["weight"],
            }
            for p in target_unique
        ]

        confidence = self._idor_confidence(
            data_exposure, user_data_leak, target_classification, target_unique,
        )

        return {
            "data_exposure": data_exposure,
            "user_data_leak": user_data_leak,
            "matched_patterns": patterns_found,
            "confidence": confidence,
            "reason": self._idor_reason(
                data_exposure, user_data_leak, target_classification, len(target_unique),
            ),
        }

    def analyze_idor_pair(
        self,
        original_response: str,
        target_response: str,
        original_user: dict[str, Any] | None = None,
        target_user: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """IDOR-specific analysis of original vs target responses.

        Returns structured result for integration with the IDOR scanner:
            - idor_detected: bool
            - confidence: str (high / medium / low)
            - patterns_found: list of pattern dicts
            - sensitivity: int
            - evidence: str with description
        """
        comparison = self.compare_responses(original_response, target_response, original_user)
        patterns = comparison["matched_patterns"]

        user_mismatch = False
        user_signal = ""
        if original_user and target_user:
            for key in ("username", "email", "name", "id", "user_id"):
                orig_val = original_user.get(key)
                tgt_val = target_user.get(key)
                if orig_val and tgt_val and str(orig_val) != str(tgt_val):
                    user_mismatch = True
                    if tgt_val and str(tgt_val) in target_response:
                        user_signal = f"target user '{tgt_val}' found in target response"
                        break
                    if orig_val and str(orig_val) in target_response:
                        user_signal = f"original user '{orig_val}' leaked in target response"
                        user_mismatch = True
                        break

        idor_detected = comparison["data_exposure"] or user_mismatch or bool(patterns)
        sensitivity = 0
        if patterns:
            sensitivity = max(p.get("weight", 0) for p in patterns) * min(len(patterns), 5)

        confidence = "high" if comparison["confidence"] == "high" else (
            "medium" if comparison["data_exposure"] or user_mismatch else "low"
        )

        evidence_parts = []
        if comparison["data_exposure"]:
            evidence_parts.append("Target response contains PII absent from original")
        if user_signal:
            evidence_parts.append(user_signal)
        if user_mismatch and not user_signal:
            evidence_parts.append("Different users, response contains target data")
        if patterns and not evidence_parts:
            evidence_parts.append(
                f"Found {len(patterns)} data pattern(s) unique to target response",
            )

        return {
            "idor_detected": idor_detected,
            "confidence": confidence,
            "patterns_found": patterns,
            "sensitivity": min(sensitivity, 100),
            "evidence": "; ".join(evidence_parts) or "No significant difference detected",
        }

    # ── Internal helpers ───────────────────────────────────────────────────

    def _ranges_overlap(self, start: int, end: int, occupied: list[tuple[int, int]]) -> bool:
        for o_start, o_end in occupied:
            if start < o_end and end > o_start:
                return True
        return False

    def _scan_pattern(
        self,
        pattern: _Pattern,
        body: str,
        body_lower: str,
        stripped: str,
        occupied: list[tuple[int, int]],
    ) -> tuple[list[str], list[tuple[int, int]]] | None:
        """Scan *body* for a single pattern. Returns (values, ranges) or None."""
        matches: list[str] = []
        ranges: list[tuple[int, int]] = []

        for m in pattern.regex.finditer(body):
            value = m.group(0) if m.lastindex is None else m.group(m.lastindex)
            if value in self._FP_EXCLUSIONS:
                continue
            if self._ranges_overlap(m.start(), m.end(), occupied):
                continue
            if self._is_false_positive(pattern.name, value, body, m.start()):
                continue
            matches.append(value)
            ranges.append((m.start(), m.end()))

        if not matches:
            return None

        unique = list(dict.fromkeys(matches))
        unique_ranges = [
            r for i, r in enumerate(ranges)
            if matches[i] in dict.fromkeys(matches)
        ]

        return (unique, unique_ranges)

    def _is_false_positive(
        self,
        pattern_name: str,
        value: str,
        body: str,
        position: int,
    ) -> bool:
        """Heuristic false-positive reduction checks."""
        ctx = _context_window(body, position, 40).lower()

        if pattern_name in ("routing_number", "iban", "swift_bic"):
            if any(
                kw in ctx
                for kw in ("example", "sample", "placeholder", "test", "dummy", "fake")
            ):
                return True

        if pattern_name.startswith("cc_"):
            if any(
                kw in ctx
                for kw in ("example", "sample", "test card", "dummy", "fake", "xxxx")
            ):
                return True
            val_digits = re.sub(r"\D", "", value)
            if len(val_digits) < 13:
                return True

        if pattern_name == "email":
            safe_suffixes = (
                "@example.com", "@example.org", "@example.net",
                "@test.com", "@domain.com", "@sample.com",
            )
            if value.lower().endswith(safe_suffixes):
                return True

        if pattern_name == "jwt":
            if "data:" in ctx or "base64" in ctx:
                return True

        if pattern_name == "phone":
            if any(
                kw in ctx
                for kw in ("version", "build", "release", "api-", "v1.", "v2.")
            ):
                return True
            # 10 consecutive digits without separators — only accept with context
            digits = re.sub(r"\D", "", value)
            if len(digits) == 10 and value == digits:
                if not any(
                    kw in ctx for kw in ("phone", "call", "tel", "mobile", "cell", "contact", "fax")
                ):
                    return True

        if pattern_name == "icd_code":
            # Exclude common 3-letter acronyms that look like ICD codes
            known_lookalikes = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"}
            if value.upper() in known_lookalikes:
                return True

        return False

    def _check_user_context_leak(
        self,
        response: str,
        user_context: dict[str, Any],
    ) -> bool:
        """Check if *user_context* identifiers appear in *response*."""
        resp_lower = response.lower()
        for key in ("username", "email", "name", "user_id", "id", "display_name"):
            val = user_context.get(key)
            if not val:
                continue
            val_str = str(val).lower().strip()
            if val_str and len(val_str) > 2 and val_str in resp_lower:
                return True

        email = user_context.get("email", "")
        if email and "@" in email:
            local, domain = email.lower().split("@", 1)
            if local in resp_lower:
                return True

        return False

    def _infer_response_type(
        self,
        body: str,
        body_lower: str,
        stripped: str,
        categories: set[str],
        patterns: list[dict[str, Any]],
    ) -> str:
        """Infer the semantic response type."""
        if len(body) < 50:
            if any(
                kw in body_lower
                for kw in ("error", "not found", "404", "500", "fail", "denied", "unauthorized")
            ):
                return "error"

        if patterns:
            if "credentials" in categories:
                return "credentials"
            if "financial_data" in categories:
                return "financial_data"
            if "personal_data" in categories:
                return "personal_data"

        if body.count("{") >= 3 and body.count("}") >= 3:
            try:
                parsed = json.loads(body)
                if isinstance(parsed, list):
                    return "listing"
                if isinstance(parsed, dict):
                    return "detail"
            except (json.JSONDecodeError, ValueError):
                pass

        if body.count("<tr") > 3 or body.count("<li") > 3:
            return "listing"

        return "unknown"

    def _compute_sensitivity(
        self,
        patterns: list[dict[str, Any]],
        categories: set[str],
    ) -> int:
        """Compute a 0-100 sensitivity score."""
        if not patterns:
            return 0

        direct = sum(p["weight"] for p in patterns)
        diversity = len(categories) * 10
        base = min(direct + diversity, 90)

        if "credentials" in categories:
            base += 10
        elif "financial_data" in categories and "personal_data" in categories:
            base += 5

        return min(base, 100)

    def _sensitivity_level(self, score: int) -> str:
        if score >= 75:
            return "critical"
        if score >= 50:
            return "high"
        if score >= 25:
            return "medium"
        if score >= 10:
            return "low"
        return "none"

    def _idor_confidence(
        self,
        data_exposure: bool,
        user_data_leak: bool,
        classification: ClassificationResult,
        unique_patterns: list[dict[str, Any]],
    ) -> str:
        if data_exposure or user_data_leak:
            return "high"
        if classification.sensitivity_score >= 50:
            return "high"
        if classification.sensitivity_score >= 25:
            return "medium"
        if unique_patterns:
            return "medium"
        return "low"

    def _idor_reason(
        self,
        data_exposure: bool,
        user_data_leak: bool,
        classification: ClassificationResult,
        unique_count: int,
    ) -> str:
        parts = []
        if data_exposure:
            parts.append("sensitive data exposed in target but not original")
        if user_data_leak:
            parts.append("original user identity found in target response")
        if classification.sensitivity_score > 0:
            parts.append(f"target sensitivity score: {classification.sensitivity_score}/100")
        if unique_count > 0:
            parts.append(f"{unique_count} unique pattern(s) in target only")
        if classification.response_type != "unknown":
            parts.append(f"target classified as {classification.response_type}")
        return "; ".join(parts) if parts else "no significant difference detected"

    # ── Utility: extract structured data from response ─────────────────────

    def extract_json(self, body: str) -> dict | list | None:
        """Attempt to parse *body* as JSON, returning the result or *None*."""
        try:
            return json.loads(body)
        except (json.JSONDecodeError, ValueError):
            pass
        m = re.search(r">\s*(\{.*\})\s*<", body, re.DOTALL)
        if m:
            try:
                return json.loads(m.group(1))
            except (json.JSONDecodeError, ValueError):
                pass
        return None

    def extract_html_text(self, body: str) -> str:
        """Strip HTML tags and normalise whitespace."""
        return _strip_html(body)

    def extract_csv_records(self, body: str) -> list[dict[str, str]] | None:
        """Attempt to parse *body* as CSV, returning a list of dicts or *None*."""
        try:
            reader = csv.DictReader(io.StringIO(body))
            rows = list(reader)
            return rows if rows else None
        except Exception:
            return None
