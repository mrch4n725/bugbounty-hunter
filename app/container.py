import threading
from typing import Any

from engines import ValidationEngine, EvidenceEngine
from modules.utils import BrowserValidator, OOBDetectionFramework

from app.capabilities import CapabilityRegistry


class ApplicationContainer:
    """Dependency injection container.

    Lazily constructs and caches singleton service instances.
    Scanners and engines request their dependencies through this
    container rather than constructing them directly.
    """

    def __init__(self, config: dict[str, Any], capabilities: CapabilityRegistry):
        self.config = config
        self.capabilities = capabilities

        self._lock = threading.Lock()
        self._validation_engine: ValidationEngine | None = None
        self._evidence_engine: EvidenceEngine | None = None
        self._browser_validator: BrowserValidator | None = None
        self._oob_framework: OOBDetectionFramework | None = None

    # ── Service accessors (lazy, cached) ─────────────────────────────────

    @property
    def validation_engine(self) -> ValidationEngine:
        if self._validation_engine is None:
            self._validation_engine = ValidationEngine(self.config, self.capabilities)
        return self._validation_engine

    @property
    def evidence_engine(self) -> EvidenceEngine:
        if self._evidence_engine is None:
            self._evidence_engine = EvidenceEngine(self.config, self.capabilities)
        return self._evidence_engine

    @property
    def browser_validator(self) -> BrowserValidator | None:
        if self._browser_validator is None:
            if self.capabilities.browser_validation:
                self._browser_validator = BrowserValidator(self.config)
        return self._browser_validator

    @property
    def oob_framework(self) -> OOBDetectionFramework | None:
        if self._oob_framework is None:
            if self.capabilities.has("oob_validation"):
                self._oob_framework = OOBDetectionFramework(self.config)
        return self._oob_framework

    # ── Lifecycle ────────────────────────────────────────────────────────

    def cleanup(self) -> None:
        if self._browser_validator is not None:
            try:
                self._browser_validator.close()
            except Exception:
                pass
        if self._oob_framework is not None:
            try:
                self._oob_framework.clear()
            except Exception:
                pass
