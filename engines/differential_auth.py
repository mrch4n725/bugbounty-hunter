"""DifferentialAuthorizationEngine — field-level response comparison for authorization testing.

Compares two HTTP responses at the JSON field level rather than just
checking HTTP status codes. Detects subtle authorization flaws where:

- Both users get HTTP 200 but with different data
- One user gets extra fields (PII, financial, credential)
- Ownership fields contain different values across users
- Fields are missing, null, or have different values
"""

import json
from typing import Any
from dataclasses import dataclass, field

from modules.utils import log, Colors


@dataclass
class FieldLevelDifference:
    field_path: str
    diff_type: str
    original_value: Any = None
    target_value: Any = None
    sensitivity: str = "none"

    @property
    def is_violation(self) -> bool:
        if self.diff_type == "missing" and self.sensitivity != "none":
            return True
        if self.diff_type == "extra" and self.sensitivity != "none":
            return True
        if self.diff_type == "different_value":
            sensitivity_violations = {"pii", "financial", "credential", "internal", "ownership"}
            return self.sensitivity in sensitivity_violations
        return False


@dataclass
class ComparisonResult:
    status_diff: bool
    original_status: int
    target_status: int
    field_diffs: list[FieldLevelDifference] = field(default_factory=list)
    body_diff_detected: bool = False

    @property
    def has_violation(self) -> bool:
        if self.status_diff and self.target_status in (200, 201, 204):
            return True
        if any(d.is_violation for d in self.field_diffs):
            return True
        return False

    @property
    def sensitive_field_leaks(self) -> list[FieldLevelDifference]:
        return [d for d in self.field_diffs if d.is_violation]


_SENSITIVITY_KEYWORDS = {
    "pii": {"email", "phone", "address", "ssn", "dob", "birthday",
            "firstname", "lastname", "fullname", "name"},
    "financial": {"price", "cost", "amount", "balance", "card", "cvv",
                   "payment", "invoice", "salary", "wage", "billing"},
    "credential": {"password", "secret", "token", "jwt", "apikey",
                    "api_key", "session", "auth"},
    "internal": {"internal", "private", "hidden", "secret_note",
                  "admin_note", "debug", "trace", "stacktrace"},
    "ownership": {"owner_id", "created_by", "user_id", "creator_id",
                   "assigned_to", "belongs_to"},
}


def _classify_field_sensitivity(field_name: str) -> str:
    """Determine the sensitivity of a field based on its name."""
    lower = field_name.lower().strip()
    for category, keywords in _SENSITIVITY_KEYWORDS.items():
        if lower in keywords:
            return category
        for kw in keywords:
            if kw in lower:
                return category
    return "none"


def _recursive_diff(
    orig: Any,
    target: Any,
    path: str = "",
    depth: int = 0,
) -> list[FieldLevelDifference]:
    """Recursively compare two parsed JSON values field by field."""
    diffs: list[FieldLevelDifference] = []

    if depth > 10:
        return diffs

    if isinstance(orig, dict) and isinstance(target, dict):
        all_keys = set(orig.keys()) | set(target.keys())
        for key in sorted(all_keys):
            child_path = f"{path}.{key}" if path else key
            if key not in target:
                sensitivity = _classify_field_sensitivity(key)
                diffs.append(FieldLevelDifference(
                    field_path=child_path,
                    diff_type="missing",
                    original_value=orig[key],
                    sensitivity=sensitivity,
                ))
            elif key not in orig:
                sensitivity = _classify_field_sensitivity(key)
                diffs.append(FieldLevelDifference(
                    field_path=child_path,
                    diff_type="extra",
                    target_value=target[key],
                    sensitivity=sensitivity,
                ))
            else:
                child_diffs = _recursive_diff(
                    orig[key], target[key], child_path, depth + 1,
                )
                diffs.extend(child_diffs)
    elif isinstance(orig, list) and isinstance(target, list):
        max_len = max(len(orig), len(target))
        for i in range(max_len):
            child_path = f"{path}[{i}]"
            if i >= len(target):
                diffs.append(FieldLevelDifference(
                    field_path=child_path,
                    diff_type="missing",
                    original_value=orig[i] if i < len(orig) else None,
                ))
            elif i >= len(orig):
                diffs.append(FieldLevelDifference(
                    field_path=child_path,
                    diff_type="extra",
                    target_value=target[i],
                ))
            else:
                child_diffs = _recursive_diff(
                    orig[i], target[i], child_path, depth + 1,
                )
                diffs.extend(child_diffs)
    else:
        if orig != target:
            sensitivity = _classify_field_sensitivity(path.split(".")[-1] if "." in path else path)
            diffs.append(FieldLevelDifference(
                field_path=path,
                diff_type="different_value",
                original_value=orig,
                target_value=target,
                sensitivity=sensitivity,
            ))

    return diffs


class DifferentialAuthorizationEngine:
    """Compare HTTP responses at field level to detect subtle authorization flaws."""

    def compare(self, response_a_text: str, response_b_text: str) -> ComparisonResult:
        """Deep comparison of two response bodies."""
        parsed_a = self._try_parse(response_a_text)
        parsed_b = self._try_parse(response_b_text)

        if parsed_a is not None and parsed_b is not None:
            field_diffs = _recursive_diff(parsed_a, parsed_b)
        else:
            field_diffs = []

        body_diff = response_a_text != response_b_text

        return ComparisonResult(
            status_diff=False,
            original_status=0,
            target_status=0,
            field_diffs=field_diffs,
            body_diff_detected=body_diff,
        )

    def compare_http(
        self,
        resp_a,
        resp_b,
    ) -> ComparisonResult:
        """Full HTTP response comparison with field-level analysis."""
        status_diff = resp_a.status_code != resp_b.status_code

        parsed_a = self._try_parse(resp_a.text)
        parsed_b = self._try_parse(resp_b.text)

        field_diffs: list[FieldLevelDifference] = []
        if parsed_a is not None and parsed_b is not None:
            field_diffs = _recursive_diff(parsed_a, parsed_b)

        body_diff = resp_a.text != resp_b.text

        return ComparisonResult(
            status_diff=status_diff,
            original_status=resp_a.status_code,
            target_status=resp_b.status_code,
            field_diffs=field_diffs,
            body_diff_detected=body_diff,
        )

    def classify_violation(
        self,
        result: ComparisonResult,
        original_role: str,
        target_role: str,
    ) -> tuple[str, str]:
        """Classify violation type and severity from field-level comparison.

        Returns (vuln_type, severity).
        """
        if result.target_status in (200, 201) and result.status_diff:
            return ("Authorization - Status Bypass", "critical")

        sensitive_leaks = result.sensitive_field_leaks
        if sensitive_leaks:
            sensitivities = {d.sensitivity for d in sensitive_leaks}
            if "financial" in sensitivities or "credential" in sensitivities:
                return ("Authorization - Data Leak", "critical")
            if "ownership" in sensitivities:
                return ("Authorization - Ownership Violation", "critical")
            if "pii" in sensitivities:
                return ("Authorization - PII Exposure", "high")
            if "internal" in sensitivities:
                return ("Authorization - Internal Data Leak", "high")
            return ("Authorization - Field Leak", "high")

        if result.body_diff_detected:
            return ("Authorization - Horizontal", "high")

        return ("Authorization - Checked", "info")

    def _try_parse(self, text: str) -> Any:
        """Try to parse response text as JSON, return None on failure."""
        if not text:
            return None
        text = text.strip()
        if not text.startswith(("{", "[")):
            return None
        try:
            return json.loads(text)
        except (json.JSONDecodeError, ValueError):
            return None
