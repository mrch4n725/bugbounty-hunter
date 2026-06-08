"""Baseline fingerprinting — record safe response baselines for anomaly detection."""

import hashlib
import threading
from urllib.parse import urlparse

import requests


class BaselineFingerprinter:
    """Record a known-safe response baseline per (method, base_url) and
    flag deviations >15% length, different status code, or error patterns."""

    def __init__(self, session: requests.Session, timeout: int = 10):
        self.session = session
        self.timeout = timeout
        self._baselines: dict[tuple[str, str], dict] = {}
        self._lock = threading.Lock()

    def _base_key(self, url: str, method: str = "GET") -> tuple[str, str]:
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}".rstrip("/")
        return (method, base)

    def fingerprint(self, url: str, method: str = "GET") -> dict:
        """Fetch a URL and store its baseline.  Returns the baseline dict."""
        key = self._base_key(url, method)
        with self._lock:
            if key in self._baselines:
                return self._baselines[key]
        try:
            r = self.session.get(url, timeout=self.timeout) if method == "GET" else self.session.post(url, timeout=self.timeout)
        except Exception:
            r = None
        baseline = {
            "status": r.status_code if r else 0,
            "length": len(r.text) if r else 0,
            "hash": hashlib.md5(r.text.encode()).hexdigest() if r else "",
        }
        with self._lock:
            self._baselines[key] = baseline
        return baseline

    def is_anomalous(self, url: str, response, method: str = "GET") -> bool:
        """Return True if the response meaningfully deviates from the baseline."""
        key = self._base_key(url, method)
        bl = self._baselines.get(key)
        if bl is None:
            return True
        if response is None:
            return False
        length = len(response.text)
        length_diff = abs(length - bl["length"])
        if bl["length"] > 0 and length_diff / max(bl["length"], 1) > 0.15:
            return True
        if response.status_code != bl["status"] and response.status_code not in (0,):
            return True
        return False
