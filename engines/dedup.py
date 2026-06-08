"""Deduplication engine — groups duplicate findings by fingerprint."""

from threading import Lock
from typing import Any, Dict, List, Optional

from models.finding import Finding


class DeduplicationEngine:
    """Deduplicate findings by fingerprint.
    Groups findings that share the same fingerprint across URLs.
    Stores Finding objects directly.
    """

    def __init__(self):
        self._lock = Lock()
        self._groups: Dict[str, Finding] = {}

    def add(self, finding: Finding) -> Optional[Finding]:
        fp = finding.fingerprint
        with self._lock:
            if fp in self._groups:
                existing = self._groups[fp]
                existing.grouped_urls.append(finding.url)
                return None
            self._groups[fp] = finding
            return finding

    def add_legacy(self, f: dict[str, Any] | Finding) -> dict[str, Any] | Finding | None:
        if isinstance(f, Finding):
            return f if self.add(f) else None
        finding_obj = Finding.from_dict(f)
        return f if self.add(finding_obj) else None

    def get_findings(self) -> List[Finding]:
        with self._lock:
            results = []
            for f in self._groups.values():
                if len(f.grouped_urls) >= 5:
                    f.details = f"{f.details} \u2014 Found on {len(f.grouped_urls)} URLs"
                results.append(f)
            return results

    def clear(self) -> None:
        with self._lock:
            self._groups.clear()
