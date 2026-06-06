from scanners.base import ScannerBase
from scanners.xss import XSSScanner
from scanners.headers import HeadersScanner
from scanners.sqli import SQLiScanner
from scanners.ssrf import SSRFScanner

__all__ = [
    "ScannerBase",
    "XSSScanner",
    "HeadersScanner",
    "SQLiScanner",
    "SSRFScanner",
]


def discover_scanner_classes() -> dict[str, type[ScannerBase]]:
    """Return dict of {SCANNER_NAME: ScannerBase_subclass} from the scanners package."""
    scanners: dict[str, type[ScannerBase]] = {}
    for name in dir():
        obj = globals()[name]
        if (isinstance(obj, type) and issubclass(obj, ScannerBase)
                and obj is not ScannerBase):
            scanners[obj.SCANNER_NAME] = obj
    return scanners
