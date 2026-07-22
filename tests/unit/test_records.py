import json
from datetime import UTC, datetime, timedelta, timezone, tzinfo

import pytest
from pydantic import ValidationError

from milhouse.domain._validation import RECORD_VALIDATION_ERROR_MESSAGE
from milhouse.domain.records import (
    ActorReferenceV1,
    AlertDataV1,
    AuditDataV1,
    CollectorDescriptorV1,
    CorrelationV1,
    EventDataV1,
    FeedbackItemDataV1,
    FeedbackTransitionDataV1,
    IncidentDataV1,
    MetricDataV1,
    RatioAtLeastPredicateV1,
    RecordDraftV1,
    RecordEnvelopeV1,
    RecordError,
    RunDataV1,
    SourceDescriptorV1,
    SpanDataV1,
    TargetDescriptorV1,
    ValidationPassedPredicateV1,
    VerificationSpecV1,
    finalize_record,
    verify_record_identity,
)

INSTALLATION_ID = "mh_in1_00000000000040008000000000000000"
EVIDENCE_ID = "mh_g3hdcz3y6hf7wf5puc2h77nm554bfl3e45vrdfyyartayjdogdga"
NOW = datetime(2026, 7, 21, 15, 0, tzinfo=UTC)
RECORD_VALIDATION_MESSAGE = RECORD_VALIDATION_ERROR_MESSAGE


def _source(
    *,
    producer: str = "collector",
    revision: int = 1,
    generation: str = "0" * 64,
) -> SourceDescriptorV1:
    return SourceDescriptorV1.model_validate(
        {
            "id": "example-source",
            "type": "source.event",
            "producer": producer,
            "observation_namespace_id": "mh_ns1_00000000000040008000000000000000",
            "source_generation_digest": generation,
            "observation": {
                "kind": "source.revision",
                "parts": {"revision": revision},
            },
        }
    )


def _target() -> TargetDescriptorV1:
    return TargetDescriptorV1(
        id="example-target",
        name="Example target",
        kind="web.service",
        environment="test",
    )


def _collector(*, implementation_version: str = "1.2.3") -> CollectorDescriptorV1:
    return CollectorDescriptorV1(
        id="example-collector",
        type="site.canary",
        implementation_version=implementation_version,
    )


def _draft(data: object | None = None, **overrides: object) -> RecordDraftV1:
    payload = data or EventDataV1(
        category="availability",
        status="healthy",
        message="Synthetic check passed",
        attributes={"status_code": 200},
    )
    values: dict[str, object] = {
        "record_type": payload.type,  # type: ignore[attr-defined]
        "name": "source.event",
        "occurred_at": NOW,
        "observed_at": NOW + timedelta(seconds=1),
        "ingested_at": NOW + timedelta(seconds=2),
        "expires_at": NOW + timedelta(days=30),
        "source_event_id": "event-1",
        "source_entity_id": "entity-1",
        "operation_id": "operation-1",
        "collector_run_id": "collector-run-1",
        "scope": "target",
        "source": _source(),
        "collector": _collector(),
        "target": _target(),
        "severity": "info",
        "trust_level": "authenticated",
        "privacy_class": "internal",
        "redaction_version": "r1-e1",
        "correlation": {"run_id": "run-1", "commit_id": "abc123"},
        "dimensions": {"route": "home", "attempt": 1},
        "data": payload,
    }
    values.update(overrides)
    return RecordDraftV1.model_validate(values)


def _verification_spec() -> VerificationSpecV1:
    return VerificationSpecV1(
        rule_id="example-rule",
        rule_version=1,
        target_id="example-target",
        signal_class="validation",
        record_names=["validation.result"],
        dimensions={"suite": "unit"},
        predicate=ValidationPassedPredicateV1(),
        minimum_observations=1,
        observation_window_seconds=3600,
        deadline=NOW + timedelta(days=7),
    )


def test_finalize_record_assigns_deterministic_verified_identity_and_content() -> None:
    first = finalize_record(_draft(), installation_id=INSTALLATION_ID)
    second = finalize_record(_draft(), installation_id=INSTALLATION_ID)

    assert first == second
    assert first.record_id == "mh_g3hdcz3y6hf7wf5puc2h77nm554bfl3e45vrdfyyartayjdogdga"
    assert first.dedupe_key == ("mh_d1_yfzuu5qthlz3ocli7jeuybxump5uxg4a2ibabe6frvzohslqhwyq")
    assert first.content_hash == (
        "dbeb343e6d50d902f1bf85282633eae7b78b0189256a30dcc0255db3a08fe228"
    )
    assert first.data.type == "event"
    assert first.content_projection()["record_type"] == "event"
    assert first.model_dump(mode="json")["occurred_at"] == "2026-07-21T15:00:00Z"
    verify_record_identity(first, installation_id=INSTALLATION_ID)

    with pytest.raises(ValidationError):
        first.record_type = "metric"  # type: ignore[misc]
    with pytest.raises(TypeError, match="immutable"):
        first.dimensions["attempt"] = 2
    with pytest.raises(TypeError, match="immutable"):
        first.source.observation.parts["revision"] = 2
    assert isinstance(first.data, EventDataV1)
    with pytest.raises(TypeError, match="immutable"):
        first.data.attributes["status_code"] = 500
    assert first.model_copy(deep=True) == first


def test_raw_json_omitted_correlation_uses_the_validated_empty_default() -> None:
    document = _draft().model_dump(mode="json")
    document.pop("correlation")

    parsed = RecordDraftV1.model_validate_json(json.dumps(document))

    assert parsed.correlation == CorrelationV1()


class _MutableUtc(tzinfo):
    def __init__(self) -> None:
        self.offset = timedelta(0)

    def utcoffset(self, value: datetime | None) -> timedelta:
        return self.offset

    def dst(self, value: datetime | None) -> timedelta:
        return timedelta(0)


def test_timestamps_are_detached_into_exact_immutable_utc_values() -> None:
    caller_tz = _MutableUtc()
    caller_value = datetime(2026, 7, 21, 15, 0, tzinfo=caller_tz)
    draft = _draft(
        occurred_at=caller_value,
        observed_at=caller_value,
        ingested_at=caller_value,
        expires_at=datetime(2026, 8, 20, 15, 0, tzinfo=caller_tz),
    )
    record = finalize_record(draft, installation_id=INSTALLATION_ID)
    wire_before = record.model_dump_json()
    record_id_before = record.record_id

    caller_tz.offset = timedelta(hours=12)

    for value in (
        draft.occurred_at,
        draft.observed_at,
        draft.ingested_at,
        draft.expires_at,
    ):
        assert type(value) is datetime
        assert value.tzinfo is UTC
    assert record.model_dump_json() == wire_before
    assert record.record_id == record_id_before
    assert record.model_copy(deep=True) == record


def test_delivery_and_observation_metadata_do_not_change_logical_hashes() -> None:
    first = finalize_record(_draft(), installation_id=INSTALLATION_ID)
    moved = _draft(
        observed_at=NOW + timedelta(minutes=1),
        ingested_at=NOW + timedelta(minutes=2),
        expires_at=NOW + timedelta(days=60),
        operation_id="operation-2",
        collector_run_id="collector-run-2",
        collector=_collector(implementation_version="9.9.9"),
    )
    second = finalize_record(moved, installation_id=INSTALLATION_ID)

    assert second.record_id == first.record_id
    assert second.dedupe_key == first.dedupe_key
    assert second.content_hash == first.content_hash


def test_redaction_policy_revision_separates_changed_normalization_identity() -> None:
    legacy = finalize_record(
        _draft(
            EventDataV1(
                category="privacy",
                status="redacted",
                message="token [redacted:secret]",
            ),
            redaction_version="r1-e4",
        ),
        installation_id=INSTALLATION_ID,
    )
    current = finalize_record(
        _draft(
            EventDataV1(
                category="privacy",
                status="redacted",
                message="token [mh:s]",
            ),
            redaction_version="r2-e4",
        ),
        installation_id=INSTALLATION_ID,
    )
    repeated = finalize_record(
        _draft(
            EventDataV1(
                category="privacy",
                status="redacted",
                message="token [mh:s]",
            ),
            redaction_version="r2-e4",
        ),
        installation_id=INSTALLATION_ID,
    )

    assert current.record_id != legacy.record_id
    assert current.dedupe_key == legacy.dedupe_key
    assert current.content_hash != legacy.content_hash
    assert repeated == current


def test_meaningful_content_change_preserves_identity_but_creates_conflict_hash() -> None:
    first = finalize_record(_draft(), installation_id=INSTALLATION_ID)
    changed = _draft(
        EventDataV1(
            category="availability",
            status="healthy",
            message="Meaningfully different redacted content",
            attributes={"status_code": 200},
        )
    )
    second = finalize_record(changed, installation_id=INSTALLATION_ID)

    assert second.record_id == first.record_id
    assert second.dedupe_key == first.dedupe_key
    assert second.content_hash != first.content_hash


def test_record_parser_rejects_tampered_content() -> None:
    record = finalize_record(_draft(), installation_id=INSTALLATION_ID)
    values = record.model_dump(mode="python")
    values["dimensions"] = {"route": "other"}

    with pytest.raises(ValidationError, match=RECORD_VALIDATION_MESSAGE):
        RecordEnvelopeV1.model_validate(values)

    other = finalize_record(
        _draft(source=_source(revision=2)),
        installation_id=INSTALLATION_ID,
    )
    values = record.model_dump(mode="python")
    values["record_id"] = other.record_id
    parsed = RecordEnvelopeV1.model_validate(values)

    with pytest.raises(RecordError, match="MH_RECORD_ID_MISMATCH"):
        verify_record_identity(parsed, installation_id=INSTALLATION_ID)

    values = record.model_dump(mode="python")
    values["dedupe_key"] = other.dedupe_key
    parsed = RecordEnvelopeV1.model_validate(values)
    with pytest.raises(RecordError, match="MH_RECORD_DEDUPE_MISMATCH"):
        verify_record_identity(parsed, installation_id=INSTALLATION_ID)


@pytest.mark.parametrize(
    ("overrides", "_message"),
    [
        ({"target": None}, "target scope requires"),
        ({"scope": "installation"}, "installation scope forbids"),
        ({"collector": None}, "collector-produced records require"),
        ({"collector_run_id": None}, "collector-produced records require"),
        ({"privacy_class": "restricted"}, "restricted input"),
        ({"ingested_at": NOW}, "ingested_at must not precede"),
        ({"expires_at": NOW + timedelta(seconds=2)}, "expires_at must be after"),
    ],
)
def test_record_draft_fails_closed_on_cross_field_contracts(
    overrides: dict[str, object], _message: str
) -> None:
    with pytest.raises(ValidationError, match=RECORD_VALIDATION_MESSAGE):
        _draft(**overrides)


def test_non_collector_records_require_no_collector_provenance() -> None:
    draft = _draft(
        source=_source(producer="system"),
        collector=None,
        collector_run_id=None,
    )
    assert finalize_record(draft, installation_id=INSTALLATION_ID).source.producer == "system"

    with pytest.raises(ValidationError, match=RECORD_VALIDATION_MESSAGE):
        _draft(source=_source(producer="system"))

    installation = _draft(
        source=_source(producer="system"),
        collector=None,
        collector_run_id=None,
        scope="installation",
        target=None,
    )
    assert finalize_record(installation, installation_id=INSTALLATION_ID).target is None


def test_record_type_must_match_discriminated_payload() -> None:
    with pytest.raises(ValidationError, match=RECORD_VALIDATION_MESSAGE):
        _draft(record_type="metric")

    values = _draft().model_dump(mode="python")
    values["data"] = {"type": "unknown"}
    with pytest.raises(ValidationError, match=RECORD_VALIDATION_MESSAGE):
        RecordDraftV1.model_validate(values)


def test_metric_window_and_numeric_contracts_are_strict() -> None:
    metric = MetricDataV1(
        value=12.5,
        unit="requests",
        metric_semantics="window_total",
        window_start=NOW,
        window_end=NOW + timedelta(minutes=5),
    )
    assert (
        finalize_record(
            _draft(metric, record_type="metric", name="requests.total"),
            installation_id=INSTALLATION_ID,
        ).data.type
        == "metric"
    )

    with pytest.raises(ValidationError, match=RECORD_VALIDATION_MESSAGE):
        MetricDataV1(value=1, unit="requests", metric_semantics="window_total")
    with pytest.raises(ValidationError, match=RECORD_VALIDATION_MESSAGE):
        MetricDataV1(
            value=1,
            unit="requests",
            metric_semantics="gauge",
            window_start=NOW,
        )
    with pytest.raises(ValidationError, match=RECORD_VALIDATION_MESSAGE):
        MetricDataV1(
            value=1,
            unit="requests",
            metric_semantics="window_total",
            window_start=NOW,
            window_end=NOW,
        )
    for invalid in (True, float("nan"), float("inf"), 2**63):
        with pytest.raises(ValidationError):
            MetricDataV1(value=invalid, unit="ms", metric_semantics="gauge")
    with pytest.raises(ValidationError, match=RECORD_VALIDATION_MESSAGE):
        MetricDataV1(value=float(2**63), unit="ms", metric_semantics="gauge")
    assert MetricDataV1(value=1, unit="count", metric_semantics="gauge").value == 1


def test_span_run_and_audit_payloads_finalize() -> None:
    payloads = (
        SpanDataV1(
            trace_id="trace-1",
            span_id="span-1",
            duration_ms=20,
            status="ok",
        ),
        RunDataV1(
            run_id="run-1",
            run_type="collector.run",
            status="success",
            started_at=NOW,
            ended_at=NOW + timedelta(seconds=1),
            duration_ms=1000,
            counts={"records": 1},
        ),
        AuditDataV1(
            action="config.validate",
            actor=ActorReferenceV1(type="operator", id="operator-1"),
            resource_ids=["config-1"],
            outcome="success",
            counts={"files": 1},
        ),
    )

    for index, payload in enumerate(payloads, start=1):
        record = finalize_record(
            _draft(
                payload,
                record_type=payload.type,
                name=f"example.{payload.type}",
                source=_source(revision=index),
            ),
            installation_id=INSTALLATION_ID,
        )
        assert record.data.type == payload.type

    with pytest.raises(ValidationError, match=RECORD_VALIDATION_MESSAGE):
        RunDataV1(
            run_id="run-1",
            run_type="collector.run",
            status="failure",
            started_at=NOW,
            ended_at=NOW - timedelta(seconds=1),
            duration_ms=1,
        )


def test_alert_and_incident_transitions_are_append_only_and_consistent() -> None:
    alert = AlertDataV1(
        alert_key="alert-1",
        rule_id="availability-rule",
        rule_version=1,
        transition_id="alert-transition-1",
        revision=1,
        previous_state="inactive",
        state="firing",
        triggering_observation=_source().observation,
        severity="error",
        summary="Synthetic availability signal failed",
        evidence_ids=[EVIDENCE_ID],
    )
    incident = IncidentDataV1(
        incident_key="incident-1",
        transition_id="incident-transition-1",
        revision=1,
        previous_state=None,
        transition="opened",
        state="open",
        triggering_observation=_source().observation,
        severity="error",
        summary="Synthetic incident opened",
        evidence_ids=[EVIDENCE_ID],
    )

    for payload in (alert, incident):
        record = finalize_record(
            _draft(
                payload,
                record_type=payload.type,
                name=f"example.{payload.type}",
                severity="error",
            ),
            installation_id=INSTALLATION_ID,
        )
        assert record.severity == record.data.severity  # type: ignore[union-attr]

    with pytest.raises(ValidationError, match=RECORD_VALIDATION_MESSAGE):
        AlertDataV1.model_validate(
            {**alert.model_dump(), "state": "firing", "previous_state": "firing"}
        )
    with pytest.raises(ValidationError, match=RECORD_VALIDATION_MESSAGE):
        IncidentDataV1.model_validate(
            {**incident.model_dump(), "transition": "resolved", "state": "resolved"}
        )
    with pytest.raises(ValidationError, match=RECORD_VALIDATION_MESSAGE):
        _draft(alert, record_type="alert", severity="warning")


def test_feedback_item_and_transition_contracts_enforce_authority_and_evidence() -> None:
    item = FeedbackItemDataV1(
        item_id="feedback-1",
        fingerprint="a" * 64,
        created_at=NOW,
        target_id="example-target",
        title="Synthetic feedback",
        summary="A bounded synthetic observation",
        recommendation="Apply the synthetic correction",
        severity="warning",
        priority="P2",
        actionability="needs_approval",
        confidence="high",
        evidence_ids=[EVIDENCE_ID],
        verification_spec=_verification_spec(),
        trust_level="authenticated",
        privacy_class="internal",
    )
    record = finalize_record(
        _draft(
            item,
            record_type="feedback_item",
            name="feedback.item_created",
            occurred_at=NOW,
            severity="warning",
        ),
        installation_id=INSTALLATION_ID,
    )
    assert record.data.type == "feedback_item"
    assert isinstance(record.data, FeedbackItemDataV1)
    assert record.data.state == "open"
    assert record.data.revision == 0

    owner = ActorReferenceV1(type="agent", id="agent-1")
    accepted = FeedbackTransitionDataV1(
        transition_id="transition-1",
        item_id="feedback-1",
        from_state="open",
        to_state="accepted",
        revision=1,
        expected_revision=0,
        actor=ActorReferenceV1(type="operator", id="operator-1"),
        timestamp=NOW,
        rationale="Synthetic approval",
        request_id="request-1",
        owner=owner,
    )
    assert accepted.owner == owner
    accepted_record = finalize_record(
        _draft(
            accepted,
            record_type="feedback_transition",
            name="feedback.accepted",
            occurred_at=NOW,
        ),
        installation_id=INSTALLATION_ID,
    )
    assert accepted_record.data.type == "feedback_transition"

    with pytest.raises(ValidationError, match=RECORD_VALIDATION_MESSAGE):
        FeedbackTransitionDataV1.model_validate({**accepted.model_dump(), "owner": None})
    returned_open = FeedbackTransitionDataV1.model_validate(
        {
            **accepted.model_dump(),
            "from_state": "accepted",
            "to_state": "open",
            "revision": 2,
            "expected_revision": 1,
            "owner": None,
            "clear_owner": True,
        }
    )
    assert returned_open.clear_owner is True
    with pytest.raises(ValidationError, match=RECORD_VALIDATION_MESSAGE):
        FeedbackTransitionDataV1.model_validate(
            {
                **accepted.model_dump(),
                "from_state": "open",
                "to_state": "rejected",
                "owner": None,
                "clear_owner": True,
            }
        )
    with pytest.raises(ValidationError, match=RECORD_VALIDATION_MESSAGE):
        FeedbackTransitionDataV1.model_validate(
            {
                **accepted.model_dump(),
                "from_state": "open",
                "to_state": "rejected",
            }
        )
    with pytest.raises(ValidationError, match=RECORD_VALIDATION_MESSAGE):
        FeedbackTransitionDataV1.model_validate(
            {
                **accepted.model_dump(),
                "from_state": "accepted",
                "to_state": "shipped",
                "revision": 2,
                "expected_revision": 1,
                "owner": None,
            }
        )
    with pytest.raises(ValidationError, match=RECORD_VALIDATION_MESSAGE):
        FeedbackTransitionDataV1.model_validate(
            {
                **accepted.model_dump(),
                "from_state": "shipped",
                "to_state": "verified",
                "revision": 2,
                "expected_revision": 1,
                "owner": None,
            }
        )
    with pytest.raises(ValidationError, match=RECORD_VALIDATION_MESSAGE):
        FeedbackTransitionDataV1.model_validate(
            {
                **accepted.model_dump(),
                "from_state": "shipped",
                "to_state": "verified",
                "revision": 2,
                "expected_revision": 1,
                "actor": {"type": "verifier", "id": "verifier-1"},
                "owner": None,
            }
        )
    with pytest.raises(ValidationError, match=RECORD_VALIDATION_MESSAGE):
        FeedbackTransitionDataV1.model_validate(
            {**accepted.model_dump(), "from_state": "open", "to_state": "verified"}
        )
    with pytest.raises(ValidationError, match=RECORD_VALIDATION_MESSAGE):
        FeedbackTransitionDataV1.model_validate({**accepted.model_dump(), "revision": 3})


def test_verification_spec_is_typed_bounded_and_non_executable() -> None:
    spec = _verification_spec()
    assert spec.predicate.type == "validation_passed"

    with pytest.raises(ValidationError, match=RECORD_VALIDATION_MESSAGE):
        VerificationSpecV1.model_validate(
            {**spec.model_dump(), "record_names": ["validation.result", "validation.result"]}
        )
    with pytest.raises(ValidationError, match=RECORD_VALIDATION_MESSAGE):
        VerificationSpecV1.model_validate({**spec.model_dump(), "sql": "SELECT 1"})
    with pytest.raises(ValidationError, match=RECORD_VALIDATION_MESSAGE):
        VerificationSpecV1.model_validate(
            {**spec.model_dump(), "predicate": {"type": "run_command", "command": "false"}}
        )
    assert RatioAtLeastPredicateV1(threshold=0.95).threshold == 0.95
    for invalid_ratio in (1, float("nan"), 1.1):
        with pytest.raises(ValidationError):
            RatioAtLeastPredicateV1(threshold=invalid_ratio)  # type: ignore[arg-type]


def test_feedback_envelope_rejects_mismatched_embedded_contract_fields() -> None:
    item = FeedbackItemDataV1(
        item_id="feedback-1",
        fingerprint="a" * 64,
        created_at=NOW,
        target_id="example-target",
        title="Synthetic feedback",
        summary="Synthetic summary",
        recommendation="Synthetic recommendation",
        severity="warning",
        priority="P2",
        actionability="investigate",
        confidence="medium",
        evidence_ids=[EVIDENCE_ID],
        verification_spec=_verification_spec(),
        trust_level="authenticated",
        privacy_class="internal",
    )
    base = {
        "record_type": "feedback_item",
        "name": "feedback.item_created",
        "occurred_at": NOW,
        "severity": "warning",
    }
    for replacement, _message in (
        ({"target_id": "another-target"}, "feedback target must match"),
        ({"trust_level": "system"}, "feedback trust level must match"),
        ({"privacy_class": "public"}, "feedback privacy class must match"),
        ({"created_at": NOW + timedelta(seconds=1)}, "created_at must match"),
    ):
        changed = FeedbackItemDataV1.model_validate({**item.model_dump(), **replacement})
        with pytest.raises(ValidationError, match=RECORD_VALIDATION_MESSAGE):
            _draft(changed, **base)

    transition = FeedbackTransitionDataV1(
        transition_id="transition-1",
        item_id="feedback-1",
        from_state="open",
        to_state="rejected",
        revision=1,
        expected_revision=0,
        actor=ActorReferenceV1(type="operator", id="operator-1"),
        timestamp=NOW + timedelta(seconds=1),
        rationale="Synthetic rejection",
        request_id="request-1",
    )
    with pytest.raises(ValidationError, match=RECORD_VALIDATION_MESSAGE):
        _draft(
            transition,
            record_type="feedback_transition",
            name="feedback.rejected",
            occurred_at=NOW,
        )


def test_record_bounds_timestamps_and_value_safe_errors() -> None:
    secret = "secret_token_0123456789abcdef"
    with pytest.raises(ValidationError) as error:
        EventDataV1(
            category="availability",
            status="failed",
            message=secret + ("x" * 10_240),
        )
    assert secret not in str(error.value)

    with pytest.raises(ValidationError, match=RECORD_VALIDATION_MESSAGE):
        _draft(dimensions={"value": "x" * 2_049})
    with pytest.raises(ValidationError, match=RECORD_VALIDATION_MESSAGE):
        _draft(dimensions={"value": float("nan")})
    with pytest.raises(ValidationError, match=RECORD_VALIDATION_MESSAGE):
        _draft(EventDataV1(category="availability", status="failed", message="bad\x1bvalue"))
    with pytest.raises(ValidationError, match=RECORD_VALIDATION_MESSAGE):
        ActorReferenceV1(type="operator", id="operator\nspoofed")
    with pytest.raises(ValidationError, match=RECORD_VALIDATION_MESSAGE):
        EventDataV1(category="availability", status="failed", message="bad\ud800value")
    with pytest.raises(ValidationError, match=RECORD_VALIDATION_MESSAGE):
        _draft(dimensions={"Bad Key": "value"})
    with pytest.raises(ValidationError, match=RECORD_VALIDATION_MESSAGE):
        AlertDataV1(
            alert_key="alert-1",
            rule_id="availability-rule",
            rule_version=1,
            transition_id="transition-1",
            revision=1,
            previous_state="inactive",
            state="firing",
            triggering_observation=_source().observation,
            severity="error",
            summary="Synthetic alert",
            evidence_ids=[EVIDENCE_ID, EVIDENCE_ID],
        )
    with pytest.raises(ValidationError, match=RECORD_VALIDATION_MESSAGE):
        AuditDataV1(
            action="config.validate",
            actor=ActorReferenceV1(type="operator", id="operator-1"),
            resource_ids=["config-1", "config-1"],
            outcome="success",
        )

    for invalid_time in (
        NOW.replace(tzinfo=None),
        NOW.astimezone(timezone(timedelta(hours=-5))),
        NOW.replace(microsecond=1),
    ):
        with pytest.raises(ValidationError):
            _draft(occurred_at=invalid_time)

    large = {f"key_{index}": "x" * 2_048 for index in range(100)}
    with pytest.raises(ValidationError, match=RECORD_VALIDATION_MESSAGE):
        _draft(
            EventDataV1(
                category="availability",
                status="healthy",
                attributes=large,
            ),
            dimensions=large,
        )
