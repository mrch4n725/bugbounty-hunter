"""
AuthorizationScanner — ScannerBase adapter for AuthorizationEngine.

Lifecycle:
  Wraps engines.authorization.AuthorizationEngine to prove
  authorization failures with evidence-driven role comparison.

Maturity: Level 4 (Verified — produces VERIFIED evidence via ownership comparison)
"""

from typing import Any

from scanners.base import ScannerBase
from engines.authorization import AuthorizationEngine
from modules.utils import log, Colors, build_role_sessions


class AuthorizationScanner(ScannerBase):
    """Proves authorization failures via role-based access comparison.

    Tests discovered URLs against all configured role sessions,
    detecting horizontal (same-level) and vertical (cross-level)
    authorization failures with VERIFIED evidence.
    """

    SCANNER_NAME = "authorization"
    SCANNER_MATURITY = 4
    TARGET_LEVEL = True

    def __init__(self, config: dict, recon: dict, container=None):
        super().__init__(config, recon, container=container)
        self._engine = None

    def scan(self, target_urls: list[str] | None = None) -> list[dict]:
        """Run authorization scans across all discovered URLs.

        Discovers auth-relevant URLs from recon data, then tests
        each with every pair of configured roles.
        """
        urls = self.recon.get("urls", [])
        if not urls:
            urls = [self.base_url] if self.base_url else []

        role_sessions = build_role_sessions(self.config, self.session)
        if len(role_sessions) < 2:
            if self.verbose:
                log("[*] AuthorizationScanner needs >= 2 roles (use --auth-header)",
                    Colors.YELLOW)
            return []

        self._engine = AuthorizationEngine(
            config=self.config,
            role_sessions=role_sessions,
            validation_engine=self.validation,
            evidence_engine=self.evidence_engine,
        )

        findings = self._engine.run_scans(urls)
        for f in findings:
            self._add_finding(f)
        return self._get_findings()
