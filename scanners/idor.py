"""
IdorScannerAdapter — thin adapter wrapping modules.idor.IdorScanner.

Lifecycle:
  Delegates entirely to modules.idor.IdorScanner.

Maturity: Level 3 (Delegates to IdorScanner with ownership validation)
"""

from scanners.base import ScannerBase


class IdorScannerAdapter(ScannerBase):
    SCANNER_NAME = "idor"
    SCANNER_MATURITY = 3
    TARGET_LEVEL = False

    def __init__(self, config: dict, recon: dict, container=None):
        super().__init__(config, recon, container=container)
        self._impl = None

    def scan(self, target_urls: list[str] | None = None) -> list[dict]:
        if self._impl is None:
            from modules.idor import IdorScanner as _Idor
            self._impl = _Idor(self.config, self.recon, container=self.container)
        results = self._impl.run_all()
        for f in results:
            self._add_finding(f)
        return self._get_findings()
