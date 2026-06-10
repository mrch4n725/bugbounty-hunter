import threading
from typing import Any

from engines import ValidationEngine, EvidenceEngine, EvidenceQualityEngine
from engines.attack_chain import AttackChainEngine
from engines.investigation import InvestigationEngine, InvestigationPlanner
from engines.impact import ImpactEngine
from engines.promotion import FindingPromotionEngine
from engines.replay import ReplayEngine
from engines.scan_budget import ScanBudgetEngine
from engines.duplicate_risk import DuplicateRiskEngine
from engines.metrics import MetricsCollector
from engines.ownership_validator import OwnershipValidator
from engines.impact_validator import ImpactValidator
from engines.submission_readiness import SubmissionReadinessEngine
from engines.consensus_engine import ValidationConsensusEngine
from engines.auth_session import AuthSessionManager
from engines.waf_evasion import WafEvasionEngine
from engines.payload_intelligence import PayloadIntelligenceEngine
from engines.semantic_analyzer import SemanticResponseAnalyzer
from engines.audit_log import AuditLogger
from engines.footprint import FootprintManager
from engines.cross_scan_dedup import CrossScanDatabase
from modules.external_intel import ExternalIntelligenceGatherer
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
        self._evidence_quality_engine: EvidenceQualityEngine | None = None
        self._browser_validator: BrowserValidator | None = None
        self._oob_framework: OOBDetectionFramework | None = None
        self._attack_chain_engine: AttackChainEngine | None = None
        self._investigation_engine: InvestigationEngine | None = None
        self._investigation_planner: InvestigationPlanner | None = None
        self._impact_engine: ImpactEngine | None = None
        self._promotion_engine: FindingPromotionEngine | None = None
        self._replay_engine: ReplayEngine | None = None
        self._scan_budget_engine: ScanBudgetEngine | None = None
        self._duplicate_risk_engine: DuplicateRiskEngine | None = None
        self._metrics_collector: MetricsCollector | None = None
        self._ownership_validator: OwnershipValidator | None = None
        self._impact_validator: ImpactValidator | None = None
        self._submission_readiness_engine: SubmissionReadinessEngine | None = None
        self._validation_consensus_engine: ValidationConsensusEngine | None = None
        self._auth_session_manager: AuthSessionManager | None = None
        self._waf_evasion_engine: WafEvasionEngine | None = None
        self._payload_intelligence: PayloadIntelligenceEngine | None = None
        self._semantic_analyzer: SemanticResponseAnalyzer | None = None
        self._audit_logger: AuditLogger | None = None
        self._footprint_manager: FootprintManager | None = None
        self._external_intel: ExternalIntelligenceGatherer | None = None
        self._cross_scan_db: CrossScanDatabase | None = None

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
    def evidence_quality_engine(self) -> EvidenceQualityEngine:
        if self._evidence_quality_engine is None:
            self._evidence_quality_engine = EvidenceQualityEngine()
        return self._evidence_quality_engine

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

    @property
    def attack_chain_engine(self) -> AttackChainEngine:
        if self._attack_chain_engine is None:
            self._attack_chain_engine = AttackChainEngine()
        return self._attack_chain_engine

    @property
    def investigation_planner(self) -> InvestigationPlanner:
        if self._investigation_planner is None:
            cap_dict = self.capabilities.all() if hasattr(self.capabilities, "all") else {}
            self._investigation_planner = InvestigationPlanner(capabilities=cap_dict)
        return self._investigation_planner

    @property
    def investigation_engine(self) -> InvestigationEngine:
        if self._investigation_engine is None:
            cap_dict = self.capabilities.all() if hasattr(self.capabilities, "all") else {}
            self._investigation_engine = InvestigationEngine(
                planner=self.investigation_planner,
                capabilities=cap_dict,
            )
        return self._investigation_engine

    @property
    def impact_engine(self) -> ImpactEngine:
        if self._impact_engine is None:
            self._impact_engine = ImpactEngine()
        return self._impact_engine

    @property
    def promotion_engine(self) -> FindingPromotionEngine:
        if self._promotion_engine is None:
            self._promotion_engine = FindingPromotionEngine()
        return self._promotion_engine

    @property
    def replay_engine(self) -> ReplayEngine:
        if self._replay_engine is None:
            self._replay_engine = ReplayEngine()
        return self._replay_engine

    @property
    def scan_budget_engine(self) -> ScanBudgetEngine:
        if self._scan_budget_engine is None:
            self._scan_budget_engine = ScanBudgetEngine(self.config)
        return self._scan_budget_engine

    @property
    def duplicate_risk_engine(self) -> DuplicateRiskEngine:
        if self._duplicate_risk_engine is None:
            self._duplicate_risk_engine = DuplicateRiskEngine()
        return self._duplicate_risk_engine

    @property
    def metrics_collector(self) -> MetricsCollector:
        if self._metrics_collector is None:
            self._metrics_collector = MetricsCollector()
        return self._metrics_collector

    @property
    def ownership_validator(self) -> OwnershipValidator:
        if self._ownership_validator is None:
            self._ownership_validator = OwnershipValidator()
        return self._ownership_validator

    @property
    def impact_validator(self) -> ImpactValidator:
        if self._impact_validator is None:
            self._impact_validator = ImpactValidator()
        return self._impact_validator

    @property
    def submission_readiness_engine(self) -> SubmissionReadinessEngine:
        if self._submission_readiness_engine is None:
            self._submission_readiness_engine = SubmissionReadinessEngine()
        return self._submission_readiness_engine

    @property
    def validation_consensus_engine(self) -> ValidationConsensusEngine:
        if self._validation_consensus_engine is None:
            self._validation_consensus_engine = ValidationConsensusEngine()
        return self._validation_consensus_engine

    # ── New engine accessors ─────────────────────────────────────────────

    @property
    def auth_session_manager(self) -> AuthSessionManager:
        if self._auth_session_manager is None:
            self._auth_session_manager = AuthSessionManager(self.config)
        return self._auth_session_manager

    @property
    def waf_evasion_engine(self) -> WafEvasionEngine:
        if self._waf_evasion_engine is None:
            self._waf_evasion_engine = WafEvasionEngine(self.config)
        return self._waf_evasion_engine

    @property
    def payload_intelligence(self) -> PayloadIntelligenceEngine:
        if self._payload_intelligence is None:
            self._payload_intelligence = PayloadIntelligenceEngine(self.config)
        return self._payload_intelligence

    @property
    def semantic_analyzer(self) -> SemanticResponseAnalyzer:
        if self._semantic_analyzer is None:
            self._semantic_analyzer = SemanticResponseAnalyzer()
        return self._semantic_analyzer

    @property
    def audit_logger(self) -> AuditLogger:
        if self._audit_logger is None:
            self._audit_logger = AuditLogger(self.config.get("output", "reports"))
        return self._audit_logger

    @property
    def footprint_manager(self) -> FootprintManager:
        if self._footprint_manager is None:
            self._footprint_manager = FootprintManager(self.config)
        return self._footprint_manager

    @property
    def external_intel(self) -> ExternalIntelligenceGatherer:
        if self._external_intel is None:
            self._external_intel = ExternalIntelligenceGatherer(self.config)
        return self._external_intel

    @property
    def cross_scan_database(self) -> CrossScanDatabase | None:
        if self._cross_scan_db is None:
            db_path = self.config.get("cross_scan_db_path")
            if db_path:
                self._cross_scan_db = CrossScanDatabase(db_path)
        return self._cross_scan_db

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
