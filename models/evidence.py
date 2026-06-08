import enum
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


class EvidenceType(str, enum.Enum):
    HTTP_REQUEST = "http_request"
    HTTP_RESPONSE = "http_response"
    RESPONSE_EXCERPT = "response_excerpt"
    SCREENSHOT = "screenshot"
    OOB_CALLBACK = "oob_callback"
    TIMING_PROOF = "timing_proof"
    SECRET_VALIDATION = "secret_validation"
    BROWSER_EXECUTION = "browser_execution"
    GRAPHQL_SCHEMA = "graphql_schema"
    AUTHORIZATION_COMPARISON = "authorization_comparison"
    RESPONSE_DIFF = "response_diff"
    COMMAND_EXECUTION = "command_execution"
    COMPOSITE = "composite"


class EvidenceStatus(str, enum.Enum):
    COLLECTED = "collected"
    FAILED = "failed"
    PENDING = "pending"
    VERIFIED = "verified"


@dataclass
class EvidenceBase:
    evidence_type: EvidenceType
    status: EvidenceStatus = EvidenceStatus.COLLECTED
    description: str = ""
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "EvidenceBase":
        from models.evidence import EVIDENCE_CLASSES
        etype = EvidenceType(d["evidence_type"])
        sub_cls = EVIDENCE_CLASSES[etype]
        kwargs = dict(d)
        kwargs.pop("evidence_type", None)
        if "status" in kwargs and isinstance(kwargs["status"], str):
            kwargs["status"] = EvidenceStatus(kwargs["status"])
        # Subclass __init__ may not accept timestamp; set after construction
        timestamp = kwargs.pop("timestamp", "")
        obj = sub_cls(**kwargs)
        if timestamp:
            obj.timestamp = timestamp
        return obj

    def to_dict(self) -> dict[str, Any]:
        d = {
            "evidence_type": self.evidence_type.value,
            "status": self.status.value,
            "description": self.description,
            "timestamp": self.timestamp,
        }
        for k, v in self.__dict__.items():
            if k not in ("evidence_type", "status", "description", "timestamp"):
                if isinstance(v, enum.Enum):
                    d[k] = v.value
                else:
                    d[k] = v
        return d


@dataclass
class HttpRequestEvidence(EvidenceBase):
    method: str = ""
    url: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    curl_command: str = ""

    def __init__(self, method: str = "", url: str = "",
                 headers: dict[str, str] | None = None,
                 body: str = "", curl_command: str = "",
                 description: str = "", status: EvidenceStatus = EvidenceStatus.COLLECTED):
        super().__init__(
            evidence_type=EvidenceType.HTTP_REQUEST,
            status=status,
            description=description or f"{method.upper()} {url}",
        )
        self.method = method
        self.url = url
        self.headers = headers or {}
        self.body = body
        self.curl_command = curl_command


@dataclass
class HttpResponseEvidence(EvidenceBase):
    status_code: int = 0
    headers: dict[str, str] = field(default_factory=dict)
    body_excerpt: str = ""
    body_length: int = 0
    body_hash: str = ""

    def __init__(self, status_code: int = 0,
                 headers: dict[str, str] | None = None,
                 body_excerpt: str = "", body_length: int = 0,
                 body_hash: str = "",
                 description: str = "", status: EvidenceStatus = EvidenceStatus.COLLECTED):
        super().__init__(
            evidence_type=EvidenceType.HTTP_RESPONSE,
            status=status,
            description=description or f"HTTP {status_code} ({body_length} bytes)",
        )
        self.status_code = status_code
        self.headers = headers or {}
        self.body_excerpt = body_excerpt
        self.body_length = body_length
        self.body_hash = body_hash


@dataclass
class ResponseExcerptEvidence(EvidenceBase):
    excerpt: str = ""
    length: int = 0
    context: str = ""

    def __init__(self, excerpt: str = "", length: int = 0,
                 context: str = "",
                 description: str = "", status: EvidenceStatus = EvidenceStatus.COLLECTED):
        super().__init__(
            evidence_type=EvidenceType.RESPONSE_EXCERPT,
            status=status,
            description=description or f"Response excerpt ({length} chars)",
        )
        self.excerpt = excerpt
        self.length = length
        self.context = context


@dataclass
class ScreenshotEvidence(EvidenceBase):
    file_path: str = ""
    mime_type: str = "image/png"
    base64_data: str = ""

    def __init__(self, file_path: str = "",
                 mime_type: str = "image/png",
                 base64_data: str = "",
                 description: str = "", status: EvidenceStatus = EvidenceStatus.COLLECTED):
        super().__init__(
            evidence_type=EvidenceType.SCREENSHOT,
            status=status,
            description=description or f"Screenshot: {file_path}",
        )
        self.file_path = file_path
        self.mime_type = mime_type
        self.base64_data = base64_data


@dataclass
class OOBCallbackEvidence(EvidenceBase):
    callback_type: str = ""
    callback_host: str = ""
    callback_token: str = ""
    interaction_time: str = ""
    raw_data: str = ""

    def __init__(self, callback_type: str = "",
                 callback_host: str = "",
                 callback_token: str = "",
                 interaction_time: str = "",
                 raw_data: str = "",
                 description: str = "",
                 status: EvidenceStatus = EvidenceStatus.VERIFIED):
        super().__init__(
            evidence_type=EvidenceType.OOB_CALLBACK,
            status=status,
            description=description or f"OOB {callback_type} callback from {callback_host}",
        )
        self.callback_type = callback_type
        self.callback_host = callback_host
        self.callback_token = callback_token
        self.interaction_time = interaction_time
        self.raw_data = raw_data


@dataclass
class TimingEvidence(EvidenceBase):
    baseline_time_ms: float = 0.0
    triggered_time_ms: float = 0.0
    delay_threshold_ms: float = 0.0
    total_attempts: int = 0

    def __init__(self, baseline_time_ms: float = 0.0,
                 triggered_time_ms: float = 0.0,
                 delay_threshold_ms: float = 0.0,
                 total_attempts: int = 0,
                 description: str = "",
                 status: EvidenceStatus = EvidenceStatus.COLLECTED):
        super().__init__(
            evidence_type=EvidenceType.TIMING_PROOF,
            status=status,
            description=description or f"Timing: +{triggered_time_ms - baseline_time_ms:.0f}ms vs baseline {baseline_time_ms:.0f}ms",
        )
        self.baseline_time_ms = baseline_time_ms
        self.triggered_time_ms = triggered_time_ms
        self.delay_threshold_ms = delay_threshold_ms
        self.total_attempts = total_attempts


@dataclass
class SecretValidationEvidence(EvidenceBase):
    secret_type: str = ""
    validation_method: str = ""
    is_valid: bool = False
    api_response: str = ""

    def __init__(self, secret_type: str = "",
                 validation_method: str = "",
                 is_valid: bool = False,
                 api_response: str = "",
                 description: str = "",
                 status: EvidenceStatus = EvidenceStatus.COLLECTED):
        super().__init__(
            evidence_type=EvidenceType.SECRET_VALIDATION,
            status=status if not is_valid else EvidenceStatus.VERIFIED,
            description=description or f"Secret validation ({secret_type}): {'valid' if is_valid else 'invalid'}",
        )
        self.secret_type = secret_type
        self.validation_method = validation_method
        self.is_valid = is_valid
        self.api_response = api_response


@dataclass
class BrowserExecutionEvidence(EvidenceBase):
    alert_fired: bool = False
    dom_mutation: bool = False
    screenshot_path: str = ""
    execution_context: str = ""

    def __init__(self, alert_fired: bool = False,
                 dom_mutation: bool = False,
                 screenshot_path: str = "",
                 execution_context: str = "",
                 description: str = "",
                 status: EvidenceStatus = EvidenceStatus.COLLECTED):
        status_val = status
        if alert_fired or dom_mutation:
            status_val = EvidenceStatus.VERIFIED
        super().__init__(
            evidence_type=EvidenceType.BROWSER_EXECUTION,
            status=status_val,
            description=description or (
                "XSS executed in browser context"
                if alert_fired or dom_mutation
                else "XSS not executed in browser"
            ),
        )
        self.alert_fired = alert_fired
        self.dom_mutation = dom_mutation
        self.screenshot_path = screenshot_path
        self.execution_context = execution_context


@dataclass
class GraphQLSchemaEvidence(EvidenceBase):
    query_text: str = ""
    schema_preview: str = ""
    mutation_count: int = 0
    query_count: int = 0
    operation_name: str = ""

    def __init__(self, query_text: str = "",
                 schema_preview: str = "",
                 mutation_count: int = 0,
                 query_count: int = 0,
                 operation_name: str = "",
                 description: str = "",
                 status: EvidenceStatus = EvidenceStatus.COLLECTED):
        super().__init__(
            evidence_type=EvidenceType.GRAPHQL_SCHEMA,
            status=status,
            description=description or f"GraphQL schema: {query_count} queries, {mutation_count} mutations",
        )
        self.query_text = query_text
        self.schema_preview = schema_preview
        self.mutation_count = mutation_count
        self.query_count = query_count
        self.operation_name = operation_name


@dataclass
class AuthorizationComparisonEvidence(EvidenceBase):
    original_user: str = ""
    target_user: str = ""
    original_status: int = 0
    target_status: int = 0
    content_different: bool = False
    ownership_violated: bool = False
    original_body_excerpt: str = ""
    target_body_excerpt: str = ""

    def __init__(self, original_user: str = "",
                 target_user: str = "",
                 original_status: int = 0,
                 target_status: int = 0,
                 content_different: bool = False,
                 ownership_violated: bool = False,
                 original_body_excerpt: str = "",
                 target_body_excerpt: str = "",
                 description: str = "",
                 status: EvidenceStatus = EvidenceStatus.COLLECTED):
        status_val = EvidenceStatus.VERIFIED if ownership_violated else status
        super().__init__(
            evidence_type=EvidenceType.AUTHORIZATION_COMPARISON,
            status=status_val,
            description=description or (
                f"Authorization violation: {original_user} → {target_user} accessed differing content"
                if ownership_violated
                else f"Authorization check: {original_user} → {target_user}"
            ),
        )
        self.original_user = original_user
        self.target_user = target_user
        self.original_status = original_status
        self.target_status = target_status
        self.content_different = content_different
        self.ownership_violated = ownership_violated
        self.original_body_excerpt = original_body_excerpt
        self.target_body_excerpt = target_body_excerpt


@dataclass
class ResponseDiffEvidence(EvidenceBase):
    baseline_status: int = 0
    baseline_body_excerpt: str = ""
    triggered_status: int = 0
    triggered_body_excerpt: str = ""
    content_length_diff: int = 0
    trigger_param: str = ""

    def __init__(self, baseline_status: int = 0,
                 baseline_body_excerpt: str = "",
                 triggered_status: int = 0,
                 triggered_body_excerpt: str = "",
                 content_length_diff: int = 0,
                 trigger_param: str = "",
                 description: str = "",
                 status: EvidenceStatus = EvidenceStatus.COLLECTED):
        super().__init__(
            evidence_type=EvidenceType.RESPONSE_DIFF,
            status=status,
            description=description or f"Response diff: {baseline_status}→{triggered_status} ({content_length_diff:+d} bytes)",
        )
        self.baseline_status = baseline_status
        self.baseline_body_excerpt = baseline_body_excerpt
        self.triggered_status = triggered_status
        self.triggered_body_excerpt = triggered_body_excerpt
        self.content_length_diff = content_length_diff
        self.trigger_param = trigger_param


@dataclass
class CommandExecutionEvidence(EvidenceBase):
    command: str = ""
    shell_chars_detected: list[str] = None
    output_excerpt: str = ""
    exit_code_observed: int = -1
    timing_delay_ms: float = 0.0

    def __init__(self, command: str = "",
                 shell_chars_detected: list[str] = None,
                 output_excerpt: str = "",
                 exit_code_observed: int = -1,
                 timing_delay_ms: float = 0.0,
                 description: str = "",
                 status: EvidenceStatus = EvidenceStatus.COLLECTED):
        status_val = EvidenceStatus.VERIFIED if exit_code_observed >= 0 else status
        char_str = ", ".join(shell_chars_detected) if shell_chars_detected else "timing"
        super().__init__(
            evidence_type=EvidenceType.COMMAND_EXECUTION,
            status=status_val,
            description=description or f"Command injection via {char_str}: exit={exit_code_observed}, delay={timing_delay_ms:.0f}ms",
        )
        self.command = command
        self.shell_chars_detected = shell_chars_detected or []
        self.output_excerpt = output_excerpt
        self.exit_code_observed = exit_code_observed
        self.timing_delay_ms = timing_delay_ms


@dataclass
class CompositeEvidence(EvidenceBase):
    child_descriptions: list[str] = None
    evidence_count: int = 0

    def __init__(self, child_descriptions: list[str] = None,
                 evidence_count: int = 0,
                 description: str = "",
                 status: EvidenceStatus = EvidenceStatus.COLLECTED):
        super().__init__(
            evidence_type=EvidenceType.COMPOSITE,
            status=status,
            description=description or f"Composite evidence: {len(child_descriptions or [])} items",
        )
        self.child_descriptions = child_descriptions or []
        self.evidence_count = evidence_count


EVIDENCE_CLASSES: dict[EvidenceType, type[EvidenceBase]] = {
    EvidenceType.HTTP_REQUEST: HttpRequestEvidence,
    EvidenceType.HTTP_RESPONSE: HttpResponseEvidence,
    EvidenceType.RESPONSE_EXCERPT: ResponseExcerptEvidence,
    EvidenceType.SCREENSHOT: ScreenshotEvidence,
    EvidenceType.OOB_CALLBACK: OOBCallbackEvidence,
    EvidenceType.TIMING_PROOF: TimingEvidence,
    EvidenceType.SECRET_VALIDATION: SecretValidationEvidence,
    EvidenceType.BROWSER_EXECUTION: BrowserExecutionEvidence,
    EvidenceType.GRAPHQL_SCHEMA: GraphQLSchemaEvidence,
    EvidenceType.AUTHORIZATION_COMPARISON: AuthorizationComparisonEvidence,
    EvidenceType.RESPONSE_DIFF: ResponseDiffEvidence,
    EvidenceType.COMMAND_EXECUTION: CommandExecutionEvidence,
    EvidenceType.COMPOSITE: CompositeEvidence,
}


def evidence_from_dict(d: dict[str, Any]) -> EvidenceBase:
    etype = EvidenceType(d["evidence_type"])
    cls = EVIDENCE_CLASSES[etype]
    kwargs = dict(d)
    kwargs.pop("evidence_type", None)
    if "status" in kwargs and isinstance(kwargs["status"], str):
        kwargs["status"] = EvidenceStatus(kwargs["status"])
    # Subclass __init__ may not accept timestamp; set after construction
    timestamp = kwargs.pop("timestamp", "")
    obj = cls(**kwargs)
    if timestamp:
        obj.timestamp = timestamp
    return obj
