import importlib
import logging
import socket
import sys
import threading
import time
from typing import Any

logger = logging.getLogger(__name__)


class CapabilityRegistry:
    """Centralized runtime capability detection.

    Probes the system at construction time and stores results as a flat
    dict of boolean flags.  Also provides a small set of derived
    properties for common compound checks.
    """

    _STARTUP_LOCK: threading.Lock = threading.Lock()
    _global_instance: "CapabilityRegistry | None" = None

    # ── Always-true capabilities (stdlib / pure Python) ──────────────────
    ALWAYS_TRUE = frozenset({
        "sqlite",
        "dns_resolution",
        "html_reporting",
        "json_reporting",
        "markdown_reporting",
        "local_persistence",
        "resume_support",
        "parallel_execution",
    })

    # ── Detectors: name -> (detect_fn, summary_label) ────────────────────
    DETECTORS: dict[str, tuple[str, str]] = {
        "sqlite": ("_detect_sqlite", "SQLite"),
        "playwright": ("_detect_playwright", "Playwright"),
        "chromium": ("_detect_chromium", "Chromium"),
        "firefox": ("_detect_firefox", "Firefox"),
        "webkit": ("_detect_webkit", "WebKit"),
        "dns_resolution": ("_detect_dns", "DNS Resolution"),
        "oob_validation": ("_detect_oob", "OOB Validation"),
        "screenshots": ("_detect_screenshots", "Screenshots"),
        "rich": ("_detect_rich", "Rich Terminal"),
        "esprima": ("_detect_esprima", "Esprima AST"),
        "html_reporting": ("_detect_always_true", "HTML Reports"),
        "json_reporting": ("_detect_always_true", "JSON Reports"),
        "markdown_reporting": ("_detect_always_true", "Markdown Reports"),
        "local_persistence": ("_detect_always_true", "Local Persistence"),
        "resume_support": ("_detect_always_true", "Resume Support"),
        "parallel_execution": ("_detect_always_true", "Parallel Execution"),
    }

    def __init__(self, config: dict[str, Any] | None = None):
        self.config = config or {}
        self._caps: dict[str, bool] = {}
        self._details: dict[str, str] = {}
        self._detect_all()

    # ── Public API ───────────────────────────────────────────────────────

    def has(self, name: str) -> bool:
        return self._caps.get(name, False)

    def get(self, name: str, default: bool = False) -> bool:
        return self._caps.get(name, default)

    def all(self) -> dict[str, bool]:
        return dict(self._caps)

    def details(self) -> dict[str, str]:
        return dict(self._details)

    # ── Derived (computed) properties ────────────────────────────────────

    @property
    def browser_validation(self) -> bool:
        return self.has("playwright") and self.has("chromium")

    @property
    def browser_validation_full(self) -> bool:
        return self.has("playwright") and (
            self.has("chromium") or self.has("firefox") or self.has("webkit")
        )

    @property
    def cross_browser_testing(self) -> bool:
        return self.has("playwright") and self.has("firefox")

    # ── Summary output ───────────────────────────────────────────────────

    CAPABILITY_WEIGHTS: dict[str, int] = {
        "browser_validation": 25,
        "screenshots": 10,
        "oob_validation": 20,
        "cross_browser_testing": 5,
        "esprima": 5,
    }

    def summary(self) -> str:
        lines: list[str] = []
        lines.append("Capabilities Detected")
        lines.append("─" * 50)
        for name, (_, label) in sorted(self.DETECTORS.items()):
            ok = self._caps.get(name, False)
            detail = self._details.get(name, "")
            if name in self.ALWAYS_TRUE:
                icon = "INFO"
            elif ok:
                icon = "PASS"
            else:
                icon = "WARN"
            padded = label.ljust(22)
            extra = f"  ({detail})" if detail else ""
            lines.append(f"  {padded} {icon}{extra}")
        lines.append("─" * 50)

        auto_lines: list[str] = []
        if self.browser_validation:
            auto_lines.append("  Browser Validation .. Enabled")
            auto_lines.append("  Screenshots ......... Enabled")
            auto_lines.append("  XSS Confidence ...... High")
        if self.has("oob_validation"):
            auto_lines.append("  OOB Validation ...... Enabled")
        if not self.browser_validation:
            auto_lines.append("  Browser Validation .. Disabled (static fallback)")
            auto_lines.append("  XSS Confidence ...... Medium")
        if not self.has("oob_validation"):
            auto_lines.append("  OOB Validation ...... Disabled (configure --oob-host to enable)")
        if auto_lines:
            lines.append("")
            lines.append("Auto-Upgrades Applied")
            lines.append("─" * 50)
            lines.extend(auto_lines)
            lines.append("─" * 50)
        return "\n".join(lines)

    def print_summary(self) -> None:
        try:
            from modules.utils import log, Colors
            for line in self.summary().split("\n"):
                log(line, Colors.CYAN if "PASS" in line or "INFO" in line
                    else Colors.YELLOW if "WARN" in line
                    else Colors.GREEN if "Enabled" in line or "Applied" in line
                    else Colors.WHITE)
        except ImportError:
            print(self.summary())

    # ── Internal detection ───────────────────────────────────────────────

    def _detect_all(self) -> None:
        for name, (method_name, _) in self.DETECTORS.items():
            ok, detail = getattr(self, method_name)()
            self._caps[name] = ok
            self._details[name] = detail

    def _set(self, name: str, value: bool, detail: str = "") -> None:
        self._caps[name] = value
        self._details[name] = detail

    # ── Individual detectors ─────────────────────────────────────────────

    @staticmethod
    def _detect_sqlite() -> tuple[bool, str]:
        try:
            import sqlite3
            conn = sqlite3.connect(":memory:")
            conn.close()
            return True, ""
        except Exception:
            return False, "not available"

    @staticmethod
    def _detect_playwright() -> tuple[bool, str]:
        try:
            import playwright.sync_api  # noqa: F401
            return True, ""
        except ImportError:
            return False, "pip install playwright"
        except Exception:
            return False, "import failed"

    def _detect_chromium(self) -> tuple[bool, str]:
        if not self.has("playwright"):
            return False, "playwright not installed"
        return self._launch_browser("chromium")

    def _detect_firefox(self) -> tuple[bool, str]:
        if not self.has("playwright"):
            return False, "playwright not installed"
        return self._launch_browser("firefox")

    def _detect_webkit(self) -> tuple[bool, str]:
        if not self.has("playwright"):
            return False, "playwright not installed"
        return self._launch_browser("webkit")

    @staticmethod
    def _launch_browser(browser_name: str) -> tuple[bool, str]:
        try:
            from playwright.sync_api import sync_playwright
            pw = sync_playwright().start()
            browser_type = getattr(pw, browser_name, None)
            if browser_type is None:
                pw.stop()
                return False, f"unknown browser type '{browser_name}'"
            browser = browser_type.launch(headless=True, timeout=15000)
            browser.close()
            pw.stop()
            return True, ""
        except Exception as exc:
            msg = str(exc).split("\n")[0][:80]
            return False, msg

    @staticmethod
    def _detect_dns() -> tuple[bool, str]:
        try:
            socket.gethostbyname("example.com")
            return True, ""
        except Exception:
            return False, "DNS resolution failed"

    def _detect_oob(self) -> tuple[bool, str]:
        host = self.config.get("oob_host", "") or ""
        if host:
            return True, host
        if self.config.get("allow_auto_oob", False):
            available = self._detect_oob_services()
            if available:
                host = available[0]
                self._oob_auto_host = host
                self.config["oob_host"] = host
                return True, f"auto:{host}"
        return False, "configure --oob-host to enable"

    def _detect_oob_services(self) -> list[str]:
        """Try to auto-detect available OOB callback services."""
        available = []
        for service, check_fn in [
            ("dnslog", self._check_dnslog),
            ("interactsh", self._check_interactsh),
        ]:
            try:
                result = check_fn()
                if result:
                    available.append(result)
            except Exception:
                continue
        return available

    @staticmethod
    def _check_interactsh() -> str | None:
        """Check if interactsh is reachable. Returns oob host domain if so."""
        import urllib.request
        try:
            req = urllib.request.Request("https://oast.fun", method="HEAD")
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.status < 400:
                    return "oast.fun"
        except Exception:
            pass
        try:
            req = urllib.request.Request("https://oast.pro", method="HEAD")
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.status < 400:
                    return "oast.pro"
        except Exception:
            pass
        return None

    @staticmethod
    def _check_dnslog() -> str | None:
        """Check if dnslog.cn is reachable. Returns oob host domain if so."""
        import urllib.request
        try:
            req = urllib.request.Request("http://dnslog.cn/getdomain.php", method="GET")
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.status == 200:
                    domain = resp.read().decode().strip()
                    if domain:
                        return domain
        except Exception:
            pass
        return None

    @staticmethod
    def _detect_screenshots() -> tuple[bool, str]:
        return True, "available when browser validation active"

    @staticmethod
    def _detect_rich() -> tuple[bool, str]:
        try:
            import rich  # noqa: F401
            return True, ""
        except ImportError:
            return False, "pip install rich"

    @staticmethod
    def _detect_esprima() -> tuple[bool, str]:
        try:
            import esprima  # noqa: F401
            return True, ""
        except ImportError:
            return False, "pip install esprima"

    @staticmethod
    def _detect_always_true() -> tuple[bool, str]:
        return True, ""

    # ── Class-level singleton (optional) ─────────────────────────────────

    @classmethod
    def get_global(cls, config: dict[str, Any] | None = None) -> "CapabilityRegistry":
        if cls._global_instance is None:
            with cls._STARTUP_LOCK:
                if cls._global_instance is None:
                    cls._global_instance = cls(config)
        return cls._global_instance

    @classmethod
    def reset_global(cls) -> None:
        with cls._STARTUP_LOCK:
            cls._global_instance = None
