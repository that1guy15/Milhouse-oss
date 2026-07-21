"""Strict canonical record envelopes and typed payload contracts."""

from __future__ import annotations

import math
import re
from datetime import datetime, timedelta
from typing import Annotated, Literal, Self, TypeAlias

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

from milhouse.core.canonical import (
    MAX_CANONICAL_INT,
    MIN_CANONICAL_INT,
    CanonicalizationError,
    canonical_json_bytes,
)
from milhouse.core.immutable import freeze_dict, freeze_list
from milhouse.domain.identity import (
    InstallationIdV1,
    MachineIdV1,
    MachineNameV1,
    ObservationCoordinateV1,
    ObservationNamespaceIdV1,
    RecordDedupeV1,
    RecordIdentityV1,
    RecordTypeV1,
    RedactionVersionV1,
    ScopeV1,
    Sha256HexV1,
    SourceIdentityV1,
    derive_content_hash,
    derive_dedupe_key,
    derive_record_id,
    validate_dedupe_key,
    validate_record_id,
)

MAX_RECORD_BYTES = 262_144
MAX_FREE_TEXT_BYTES = 10_240
MAX_DIMENSIONS = 100
MAX_DIMENSION_KEY_BYTES = 128
MAX_DIMENSION_VALUE_BYTES = 2_048

SeverityV1 = Literal["debug", "info", "warning", "error", "critical"]
TrustLevelV1 = Literal["system", "authenticated", "local_untrusted", "remote_untrusted"]
PrivacyClassV1 = Literal["public", "internal", "sensitive", "restricted"]
ProducerTypeV1 = Literal["collector", "receiver", "system", "operator", "importer"]
ScalarV1: TypeAlias = bool | int | float | str

_DIMENSION_KEY = re.compile(r"^[a-z][a-z0-9_.-]*$")


class RecordError(ValueError):
    """A stable record construction or identity-verification failure."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(f"{code}: {message}")


class _StrictRecordModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        frozen=True,
        hide_input_in_errors=True,
        validate_default=True,
    )


def _validate_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError("timestamp must use an explicit zero UTC offset")
    if value.microsecond % 1000:
        raise ValueError("timestamp must have millisecond precision")
    return value


UtcTimestampV1 = Annotated[datetime, AfterValidator(_validate_utc)]


def _validate_text(value: str, *, label: str, maximum: int) -> str:
    if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
        raise ValueError(f"{label} must not contain surrogate code points")
    encoded = value.encode("utf-8", errors="strict")
    if not encoded or len(encoded) > maximum:
        raise ValueError(f"{label} must contain 1 through {maximum} UTF-8 bytes")
    for character in value:
        codepoint = ord(character)
        if (codepoint < 0x20 and character not in "\n\t") or codepoint == 0x7F:
            raise ValueError(f"{label} must not contain unsafe control characters")
    return value


def _validate_free_text(value: str) -> str:
    return _validate_text(value, label="free text", maximum=MAX_FREE_TEXT_BYTES)


def _validate_single_line_text(value: str, *, label: str, maximum: int) -> str:
    _validate_text(value, label=label, maximum=maximum)
    if "\n" in value or "\t" in value:
        raise ValueError(f"{label} must be a single line")
    return value


def _validate_title(value: str) -> str:
    return _validate_single_line_text(value, label="title", maximum=255)


def _validate_opaque_id(value: str) -> str:
    return _validate_single_line_text(value, label="identifier", maximum=256)


def _validate_short_text(value: str) -> str:
    return _validate_single_line_text(value, label="short text", maximum=128)


FreeTextV1 = Annotated[str, AfterValidator(_validate_free_text)]
TitleV1 = Annotated[str, AfterValidator(_validate_title)]
OpaqueIdV1 = Annotated[str, AfterValidator(_validate_opaque_id)]
ShortTextV1 = Annotated[str, AfterValidator(_validate_short_text)]
NonNegativeIntV1 = Annotated[int, Field(ge=0, le=MAX_CANONICAL_INT)]
PositiveIntV1 = Annotated[int, Field(ge=1, le=MAX_CANONICAL_INT)]


def _validate_scalar(value: ScalarV1, *, label: str, maximum_string_bytes: int) -> ScalarV1:
    if type(value) is int and not MIN_CANONICAL_INT <= value <= MAX_CANONICAL_INT:
        raise ValueError(f"{label} integer is outside the signed 64-bit domain")
    if type(value) is float:
        if not math.isfinite(value):
            raise ValueError(f"{label} float must be finite")
        if value.is_integer() and not MIN_CANONICAL_INT <= int(value) <= MAX_CANONICAL_INT:
            raise ValueError(f"{label} float is outside the signed 64-bit domain")
    if type(value) is str:
        _validate_text(value, label=label, maximum=maximum_string_bytes)
    return value


def _validate_dimension_key(value: str) -> str:
    if _DIMENSION_KEY.fullmatch(value) is None:
        raise ValueError("dimension key must be a lowercase machine name")
    return _validate_text(
        value,
        label="dimension key",
        maximum=MAX_DIMENSION_KEY_BYTES,
    )


DimensionKeyV1 = Annotated[str, AfterValidator(_validate_dimension_key)]


def _validate_dimensions(value: dict[DimensionKeyV1, ScalarV1]) -> dict[DimensionKeyV1, ScalarV1]:
    for scalar in value.values():
        _validate_scalar(
            scalar,
            label="dimension value",
            maximum_string_bytes=MAX_DIMENSION_VALUE_BYTES,
        )
    return freeze_dict(value)


DimensionsV1 = Annotated[
    dict[DimensionKeyV1, ScalarV1],
    Field(max_length=MAX_DIMENSIONS),
    AfterValidator(_validate_dimensions),
]


def _validate_counts(value: dict[DimensionKeyV1, NonNegativeIntV1]) -> dict[str, int]:
    return freeze_dict(dict(value))


SafeCountsV1 = Annotated[
    dict[DimensionKeyV1, NonNegativeIntV1],
    Field(max_length=MAX_DIMENSIONS),
    AfterValidator(_validate_counts),
]


def _validate_record_id(value: str) -> str:
    return validate_record_id(value)


def _validate_dedupe_key(value: str) -> str:
    return validate_dedupe_key(value)


RecordIdV1 = Annotated[str, AfterValidator(_validate_record_id)]
DedupeKeyV1 = Annotated[str, AfterValidator(_validate_dedupe_key)]


def _unique_record_ids(value: list[RecordIdV1]) -> list[RecordIdV1]:
    if len(value) != len(set(value)):
        raise ValueError("evidence_ids must not contain duplicates")
    return freeze_list(value)


EvidenceIdsV1 = Annotated[
    list[RecordIdV1],
    Field(max_length=100),
    AfterValidator(_unique_record_ids),
]


class SourceDescriptorV1(_StrictRecordModel):
    id: MachineIdV1
    type: MachineNameV1
    producer: ProducerTypeV1
    observation_namespace_id: ObservationNamespaceIdV1
    source_generation_digest: Sha256HexV1
    observation: ObservationCoordinateV1

    def identity_source(self) -> SourceIdentityV1:
        return SourceIdentityV1(
            id=self.id,
            type=self.type,
            observation_namespace_id=self.observation_namespace_id,
            source_generation_digest=self.source_generation_digest,
        )


class CollectorDescriptorV1(_StrictRecordModel):
    id: MachineIdV1
    type: MachineNameV1
    plugin_api_version: Literal["1.0"] = "1.0"
    implementation_version: ShortTextV1


class TargetDescriptorV1(_StrictRecordModel):
    id: MachineIdV1
    name: TitleV1
    kind: MachineNameV1
    environment: MachineNameV1


class CorrelationV1(_StrictRecordModel):
    trace_id: OpaqueIdV1 | None = None
    run_id: OpaqueIdV1 | None = None
    deploy_id: OpaqueIdV1 | None = None
    commit_id: OpaqueIdV1 | None = None


class ActorReferenceV1(_StrictRecordModel):
    type: Literal["system", "operator", "agent", "verifier", "importer"]
    id: OpaqueIdV1


class EventDataV1(_StrictRecordModel):
    type: Literal["event"] = "event"
    category: MachineNameV1
    status: MachineNameV1
    message: FreeTextV1 | None = None
    attributes: DimensionsV1 = Field(default_factory=dict)


class MetricDataV1(_StrictRecordModel):
    type: Literal["metric"] = "metric"
    value: int | float
    unit: ShortTextV1
    metric_semantics: Literal["gauge", "counter_delta", "window_total", "cumulative_counter"]
    window_start: UtcTimestampV1 | None = None
    window_end: UtcTimestampV1 | None = None

    @field_validator("value")
    @classmethod
    def validate_value(cls, value: int | float) -> int | float:
        _validate_scalar(value, label="metric value", maximum_string_bytes=0)
        return value

    @model_validator(mode="after")
    def validate_window(self) -> Self:
        has_window = self.window_start is not None or self.window_end is not None
        if self.metric_semantics == "window_total":
            if self.window_start is None or self.window_end is None:
                raise ValueError("window_total requires window_start and window_end")
            if self.window_end <= self.window_start:
                raise ValueError("metric window_end must be after window_start")
        elif has_window:
            raise ValueError("only window_total may define a metric window")
        return self


class SpanDataV1(_StrictRecordModel):
    type: Literal["span"] = "span"
    trace_id: OpaqueIdV1
    span_id: OpaqueIdV1
    parent_span_id: OpaqueIdV1 | None = None
    duration_ms: NonNegativeIntV1
    status: Literal["ok", "error", "cancelled"]


class RunDataV1(_StrictRecordModel):
    type: Literal["run"] = "run"
    run_id: OpaqueIdV1
    run_type: MachineNameV1
    status: Literal["success", "failure", "cancelled", "timeout", "partial"]
    started_at: UtcTimestampV1
    ended_at: UtcTimestampV1
    duration_ms: NonNegativeIntV1
    counts: SafeCountsV1 = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_time_range(self) -> Self:
        if self.ended_at < self.started_at:
            raise ValueError("run ended_at must not precede started_at")
        return self


class AlertDataV1(_StrictRecordModel):
    type: Literal["alert"] = "alert"
    alert_key: OpaqueIdV1
    rule_id: MachineIdV1
    rule_version: PositiveIntV1
    transition_id: OpaqueIdV1
    revision: PositiveIntV1
    previous_state: Literal["inactive", "firing", "resolved"]
    state: Literal["firing", "resolved"]
    triggering_observation: ObservationCoordinateV1
    severity: SeverityV1
    summary: FreeTextV1
    evidence_ids: EvidenceIdsV1 = Field(min_length=1)

    @model_validator(mode="after")
    def validate_transition(self) -> Self:
        allowed = {
            ("inactive", "firing"),
            ("firing", "resolved"),
            ("resolved", "firing"),
        }
        if (self.previous_state, self.state) not in allowed:
            raise ValueError("alert state transition is not allowed")
        return self


class IncidentDataV1(_StrictRecordModel):
    type: Literal["incident"] = "incident"
    incident_key: OpaqueIdV1
    transition_id: OpaqueIdV1
    revision: PositiveIntV1
    previous_state: Literal["open", "mitigated", "resolved"] | None = None
    transition: Literal["opened", "mitigated", "resolved", "reopened"]
    state: Literal["open", "mitigated", "resolved"]
    triggering_observation: ObservationCoordinateV1
    severity: SeverityV1
    summary: FreeTextV1
    evidence_ids: EvidenceIdsV1 = Field(min_length=1)

    @model_validator(mode="after")
    def validate_transition(self) -> Self:
        allowed = {
            (None, "opened", "open"),
            ("open", "mitigated", "mitigated"),
            ("mitigated", "resolved", "resolved"),
            ("mitigated", "reopened", "open"),
            ("resolved", "reopened", "open"),
        }
        if (self.previous_state, self.transition, self.state) not in allowed:
            raise ValueError("incident state transition is not allowed")
        return self


class StateEqualsPredicateV1(_StrictRecordModel):
    type: Literal["state_equals"] = "state_equals"
    state: MachineNameV1


class NoRecurrencePredicateV1(_StrictRecordModel):
    type: Literal["no_recurrence"] = "no_recurrence"


class CountAtMostPredicateV1(_StrictRecordModel):
    type: Literal["count_at_most"] = "count_at_most"
    threshold: NonNegativeIntV1


class RatioAtLeastPredicateV1(_StrictRecordModel):
    type: Literal["ratio_at_least"] = "ratio_at_least"
    threshold: Annotated[float, Field(ge=0.0, le=1.0)]

    @field_validator("threshold", mode="before")
    @classmethod
    def validate_threshold(cls, value: object) -> float:
        if type(value) is not float or not math.isfinite(value):
            raise ValueError("ratio threshold must be a finite float")
        return value


class LatencyAtMostPredicateV1(_StrictRecordModel):
    type: Literal["latency_at_most"] = "latency_at_most"
    threshold: NonNegativeIntV1
    unit: Literal["ms"] = "ms"


class ValidationPassedPredicateV1(_StrictRecordModel):
    type: Literal["validation_passed"] = "validation_passed"


VerificationPredicateV1 = Annotated[
    StateEqualsPredicateV1
    | NoRecurrencePredicateV1
    | CountAtMostPredicateV1
    | RatioAtLeastPredicateV1
    | LatencyAtMostPredicateV1
    | ValidationPassedPredicateV1,
    Field(discriminator="type"),
]


class VerificationSpecV1(_StrictRecordModel):
    schema_version: Literal["1.0"] = "1.0"
    rule_id: MachineIdV1
    rule_version: PositiveIntV1
    target_id: MachineIdV1
    signal_class: Literal[
        "canary", "error", "deploy", "workflow", "metric", "agent_summary", "validation"
    ]
    record_names: Annotated[list[MachineNameV1], Field(min_length=1, max_length=32)]
    dimensions: DimensionsV1 = Field(default_factory=dict)
    predicate: VerificationPredicateV1
    minimum_observations: Annotated[int, Field(ge=1, le=1_000_000)]
    observation_window_seconds: Annotated[int, Field(ge=1, le=31_536_000)]
    deadline: UtcTimestampV1
    allowed_lateness_seconds: Annotated[int, Field(ge=0, le=2_592_000)] = 0

    @field_validator("record_names")
    @classmethod
    def validate_record_names(cls, value: list[MachineNameV1]) -> list[MachineNameV1]:
        if len(value) != len(set(value)):
            raise ValueError("record_names must not contain duplicates")
        return freeze_list(value)


class FeedbackItemDataV1(_StrictRecordModel):
    type: Literal["feedback_item"] = "feedback_item"
    item_id: OpaqueIdV1
    fingerprint: Sha256HexV1
    created_at: UtcTimestampV1
    state: Literal["open"] = "open"
    revision: Literal[0] = 0
    target_id: MachineIdV1
    title: TitleV1
    summary: FreeTextV1
    recommendation: FreeTextV1
    severity: SeverityV1
    priority: Literal["P0", "P1", "P2", "P3"]
    actionability: Literal["observe", "investigate", "agent_safe", "needs_approval"]
    confidence: Literal["low", "medium", "high"]
    owner: ActorReferenceV1 | None = None
    evidence_ids: EvidenceIdsV1 = Field(min_length=1)
    verification_spec: VerificationSpecV1
    trust_level: TrustLevelV1
    privacy_class: PrivacyClassV1


FeedbackStateV1 = Literal["open", "accepted", "shipped", "verified", "regressed", "rejected"]


class FeedbackTransitionDataV1(_StrictRecordModel):
    type: Literal["feedback_transition"] = "feedback_transition"
    transition_id: OpaqueIdV1
    item_id: OpaqueIdV1
    from_state: FeedbackStateV1
    to_state: FeedbackStateV1
    revision: PositiveIntV1
    expected_revision: NonNegativeIntV1
    actor: ActorReferenceV1
    timestamp: UtcTimestampV1
    rationale: FreeTextV1
    request_id: OpaqueIdV1
    evidence_ids: EvidenceIdsV1 = Field(default_factory=list)
    owner: ActorReferenceV1 | None = None
    clear_owner: bool = False
    change_reference: OpaqueIdV1 | None = None
    validation_evidence_ids: EvidenceIdsV1 = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_transition(self) -> Self:
        allowed = {
            ("open", "accepted"),
            ("open", "rejected"),
            ("accepted", "open"),
            ("accepted", "shipped"),
            ("accepted", "rejected"),
            ("shipped", "verified"),
            ("shipped", "regressed"),
            ("regressed", "accepted"),
            ("regressed", "rejected"),
            ("rejected", "open"),
            ("verified", "regressed"),
        }
        if (self.from_state, self.to_state) not in allowed:
            raise ValueError("feedback state transition is not allowed")
        if self.revision != self.expected_revision + 1:
            raise ValueError("feedback revision must equal expected_revision plus one")
        if self.to_state == "accepted" and self.owner is None:
            raise ValueError("accepting feedback requires an owner")
        if self.to_state != "accepted" and self.owner is not None:
            raise ValueError("only an acceptance transition may assign an owner")
        if self.clear_owner and (self.from_state, self.to_state) != ("accepted", "open"):
            raise ValueError(
                "owner clearing is valid only when returning accepted feedback to open"
            )
        if self.to_state == "shipped" and (
            self.change_reference is None or not self.validation_evidence_ids
        ):
            raise ValueError("shipping feedback requires a change and validation evidence")
        if self.to_state in {"verified", "regressed"} and self.actor.type != "verifier":
            raise ValueError("only a verifier may create verified or regressed feedback")
        if self.to_state in {"verified", "regressed"} and not self.evidence_ids:
            raise ValueError("verification transitions require verification evidence")
        return self


class AuditDataV1(_StrictRecordModel):
    type: Literal["audit"] = "audit"
    action: MachineNameV1
    actor: ActorReferenceV1
    resource_ids: Annotated[list[OpaqueIdV1], Field(max_length=100)] = Field(default_factory=list)
    outcome: Literal["success", "failure", "denied", "noop"]
    reason_code: MachineNameV1 | None = None
    counts: SafeCountsV1 = Field(default_factory=dict)

    @field_validator("resource_ids")
    @classmethod
    def validate_resource_ids(cls, value: list[OpaqueIdV1]) -> list[OpaqueIdV1]:
        if len(value) != len(set(value)):
            raise ValueError("resource_ids must not contain duplicates")
        return freeze_list(value)


RecordDataV1 = Annotated[
    EventDataV1
    | MetricDataV1
    | SpanDataV1
    | RunDataV1
    | AlertDataV1
    | IncidentDataV1
    | FeedbackItemDataV1
    | FeedbackTransitionDataV1
    | AuditDataV1,
    Field(discriminator="type"),
]


class RecordDraftV1(_StrictRecordModel):
    """A fully redacted record before deterministic identifiers are assigned."""

    schema_version: Literal["1.0"] = "1.0"
    record_type: RecordTypeV1
    name: MachineNameV1
    occurred_at: UtcTimestampV1
    observed_at: UtcTimestampV1
    ingested_at: UtcTimestampV1
    expires_at: UtcTimestampV1
    source_event_id: OpaqueIdV1 | None = None
    source_entity_id: OpaqueIdV1 | None = None
    operation_id: OpaqueIdV1
    collector_run_id: OpaqueIdV1 | None = None
    scope: ScopeV1
    source: SourceDescriptorV1
    collector: CollectorDescriptorV1 | None = None
    target: TargetDescriptorV1 | None = None
    severity: SeverityV1
    trust_level: TrustLevelV1
    privacy_class: PrivacyClassV1
    redaction_version: RedactionVersionV1
    correlation: CorrelationV1 = Field(default_factory=CorrelationV1)
    dimensions: DimensionsV1 = Field(default_factory=dict)
    data: RecordDataV1

    @model_validator(mode="after")
    def validate_contract(self) -> Self:
        if self.record_type != self.data.type:
            raise ValueError("record_type must match the data discriminator")
        if self.scope == "target":
            if self.target is None:
                raise ValueError("target scope requires a target descriptor")
        elif self.target is not None:
            raise ValueError("installation scope forbids a target descriptor")
        if self.source.producer == "collector":
            if self.collector is None or self.collector_run_id is None:
                raise ValueError("collector-produced records require collector provenance")
        elif self.collector is not None or self.collector_run_id is not None:
            raise ValueError("non-collector records forbid collector provenance")
        if self.privacy_class == "restricted":
            raise ValueError("restricted input cannot become a canonical record")
        if self.ingested_at < self.observed_at:
            raise ValueError("ingested_at must not precede observed_at")
        if self.expires_at <= self.ingested_at:
            raise ValueError("expires_at must be after ingested_at")
        if isinstance(self.data, (AlertDataV1, IncidentDataV1, FeedbackItemDataV1)):
            if self.severity != self.data.severity:
                raise ValueError("envelope severity must match payload severity")
        if isinstance(self.data, FeedbackItemDataV1):
            if self.target is None or self.data.target_id != self.target.id:
                raise ValueError("feedback target must match the envelope target")
            if self.trust_level != self.data.trust_level:
                raise ValueError("feedback trust level must match the envelope")
            if self.privacy_class != self.data.privacy_class:
                raise ValueError("feedback privacy class must match the envelope")
            if self.data.created_at != self.occurred_at:
                raise ValueError("feedback created_at must match occurred_at")
        if isinstance(self.data, FeedbackTransitionDataV1):
            if self.data.timestamp != self.occurred_at:
                raise ValueError("feedback transition timestamp must match occurred_at")
        try:
            canonical_json_bytes(
                self.model_dump(mode="python", exclude_none=True),
                max_bytes=MAX_RECORD_BYTES,
            )
        except CanonicalizationError as error:
            raise ValueError("record is outside the canonical record bounds") from error
        return self

    def identity(self, installation_id: InstallationIdV1) -> RecordIdentityV1:
        return RecordIdentityV1(
            installation_id=installation_id,
            redaction_version=self.redaction_version,
            source=self.source.identity_source(),
            scope=self.scope,
            target_id=self.target.id if self.target is not None else None,
            record_type=self.record_type,
            name=self.name,
            source_event_id=self.source_event_id,
            source_entity_id=self.source_entity_id,
            observation=self.source.observation,
        )


def _content_projection(values: dict[str, object]) -> dict[str, object]:
    projection = dict(values)
    for excluded in (
        "record_id",
        "dedupe_key",
        "content_hash",
        "operation_id",
        "collector_run_id",
        "observed_at",
        "ingested_at",
        "expires_at",
    ):
        projection.pop(excluded, None)
    collector = projection.get("collector")
    if type(collector) is dict:
        collector = dict(collector)
        collector.pop("implementation_version", None)
        projection["collector"] = collector
    return projection


class RecordEnvelopeV1(RecordDraftV1):
    """A finalized immutable canonical record suitable for durable storage."""

    record_id: RecordIdV1
    dedupe_key: DedupeKeyV1
    content_hash: Sha256HexV1

    @model_validator(mode="after")
    def validate_content_hash(self) -> Self:
        values = self.model_dump(mode="python", exclude_none=True)
        expected_hash = derive_content_hash(_content_projection(values))
        if self.content_hash != expected_hash:
            raise ValueError("content_hash does not match the canonical content projection")
        return self

    def content_projection(self) -> dict[str, object]:
        return _content_projection(self.model_dump(mode="python", exclude_none=True))


def finalize_record(
    draft: RecordDraftV1,
    *,
    installation_id: InstallationIdV1,
) -> RecordEnvelopeV1:
    """Assign deterministic identity and content digests to one validated record draft."""

    identity = draft.identity(installation_id)
    values = draft.model_dump(mode="python", exclude_none=True)
    values.update(
        record_id=derive_record_id(identity),
        dedupe_key=derive_dedupe_key(RecordDedupeV1.from_identity(identity)),
        content_hash=derive_content_hash(_content_projection(values)),
    )
    record = RecordEnvelopeV1.model_validate(values)
    verify_record_identity(record, installation_id=installation_id)
    return record


def verify_record_identity(
    record: RecordEnvelopeV1,
    *,
    installation_id: InstallationIdV1,
) -> None:
    """Fail safely when a parsed record's deterministic identity does not match its body."""

    identity = record.identity(installation_id)
    if record.record_id != derive_record_id(identity):
        raise RecordError("MH_RECORD_ID_MISMATCH", "record_id does not match record identity")
    dedupe = RecordDedupeV1.from_identity(identity)
    if record.dedupe_key != derive_dedupe_key(dedupe):
        raise RecordError("MH_RECORD_DEDUPE_MISMATCH", "dedupe_key does not match record identity")
