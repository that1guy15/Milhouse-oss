from datetime import UTC, datetime, timedelta

from milhouse.core.canonical import canonical_json_bytes
from milhouse.domain import RecordDraftV1, RecordEnvelopeV1, finalize_record


def test_record_envelope_canonical_json_round_trip_preserves_wire_identity() -> None:
    now = datetime(2026, 7, 21, 15, 0, tzinfo=UTC)
    draft = RecordDraftV1.model_validate(
        {
            "record_type": "event",
            "name": "canary.result",
            "occurred_at": now,
            "observed_at": now + timedelta(seconds=1),
            "ingested_at": now + timedelta(seconds=2),
            "expires_at": now + timedelta(days=30),
            "source_event_id": "canary-20260721t150000z",
            "source_entity_id": "canary-example-target",
            "operation_id": "operation-1",
            "collector_run_id": "collector-run-1",
            "scope": "target",
            "source": {
                "id": "example-source",
                "type": "site.canary",
                "producer": "collector",
                "observation_namespace_id": "mh_ns1_00000000000040008000000000000000",
                "source_generation_digest": "0" * 64,
                "observation": {
                    "kind": "scheduled.route",
                    "parts": {"scheduled_at": "2026-07-21T15:00:00.000Z", "route": "home"},
                },
            },
            "collector": {
                "id": "example-canary",
                "type": "site.canary",
                "plugin_api_version": "1.0",
                "implementation_version": "1.0.0",
            },
            "target": {
                "id": "example-target",
                "name": "Example target",
                "kind": "web.service",
                "environment": "test",
            },
            "severity": "info",
            "trust_level": "authenticated",
            "privacy_class": "internal",
            "redaction_version": "r1-e1",
            "dimensions": {"route": "home"},
            "data": {
                "type": "event",
                "category": "availability",
                "status": "healthy",
                "message": "Synthetic check passed",
                "attributes": {"status_code": 200},
            },
        }
    )
    record = finalize_record(
        draft,
        installation_id="mh_in1_00000000000040008000000000000000",
    )
    encoded = canonical_json_bytes(record.model_dump(mode="python", exclude_none=True))
    parsed = RecordEnvelopeV1.model_validate_json(encoded)

    assert parsed == record
    assert parsed.model_dump(mode="json")["occurred_at"] == "2026-07-21T15:00:00Z"
    assert b"implementation_version" in encoded
    collector = parsed.content_projection()["collector"]
    assert isinstance(collector, dict)
    assert "implementation_version" not in collector
