"""Reusable builders for finalized domain records (shared by the storage exporter/CLI tests).

These mirror the canonical construction in ``test_records.py`` but expose public factories that
return finalized :class:`RecordEnvelopeV1` objects, so the storage tests exercise the real domain →
row mapping instead of hand-rolling envelopes.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from milhouse.domain.records import (
    ActorReferenceV1,
    CollectorDescriptorV1,
    EventDataV1,
    FeedbackItemDataV1,
    FeedbackTransitionDataV1,
    RecordDraftV1,
    RecordEnvelopeV1,
    SourceDescriptorV1,
    TargetDescriptorV1,
    ValidationPassedPredicateV1,
    VerificationSpecV1,
    finalize_record,
)

INSTALLATION_ID = "mh_in1_00000000000040008000000000000000"
EVIDENCE_ID = "mh_g3hdcz3y6hf7wf5puc2h77nm554bfl3e45vrdfyyartayjdogdga"
NOW = datetime(2026, 7, 21, 15, 0, tzinfo=UTC)


def _source() -> SourceDescriptorV1:
    return SourceDescriptorV1.model_validate(
        {
            "id": "example-source",
            "type": "source.event",
            "producer": "collector",
            "observation_namespace_id": "mh_ns1_00000000000040008000000000000000",
            "source_generation_digest": "0" * 64,
            "observation": {"kind": "source.revision", "parts": {"revision": 1}},
        }
    )


def _target() -> TargetDescriptorV1:
    return TargetDescriptorV1(
        id="example-target", name="Example target", kind="web.service", environment="test"
    )


def _collector() -> CollectorDescriptorV1:
    return CollectorDescriptorV1(
        id="example-collector", type="site.canary", implementation_version="1.2.3"
    )


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


def _draft(data: object, **overrides: object) -> RecordDraftV1:
    values: dict[str, object] = {
        "record_type": data.type,  # type: ignore[attr-defined]
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
        "data": data,
    }
    values.update(overrides)
    return RecordDraftV1.model_validate(values)


def event_record(**overrides: object) -> RecordEnvelopeV1:
    """A finalized ``event`` record (the common case)."""

    payload = EventDataV1(category="availability", status="healthy", message="ok")
    return finalize_record(_draft(payload, **overrides), installation_id=INSTALLATION_ID)


def feedback_item_record() -> RecordEnvelopeV1:
    """A finalized ``feedback_item`` record (opens a feedback item at revision 0)."""

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
    return finalize_record(
        _draft(
            item,
            record_type="feedback_item",
            name="feedback.item_created",
            severity="warning",
        ),
        installation_id=INSTALLATION_ID,
    )


def feedback_transition_record() -> RecordEnvelopeV1:
    """A finalized ``feedback_transition`` record (open → accepted, revision 1)."""

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
        owner=ActorReferenceV1(type="agent", id="agent-1"),
    )
    return finalize_record(
        _draft(accepted, record_type="feedback_transition", name="feedback.accepted"),
        installation_id=INSTALLATION_ID,
    )
