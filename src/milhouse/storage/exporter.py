"""Record → ClickHouse exporter (W04 G04b, plan section 4.5).

:func:`export_records` writes finalized :class:`RecordEnvelopeV1` objects into the analytical store.
Every record is authorized against ``EgressSurface.LOCAL_CLICKHOUSE`` before it is written (fail
closed — a ``restricted`` record can never reach persistence, defense in depth over the record
contract and the spool egress guard), then projected to the ``records`` table; feedback records are
additionally projected to ``feedback_items`` / ``feedback_transitions`` so the current-state views
resolve. Rows are transmitted as native column data through :meth:`ClickHouseClient.insert`, never
interpolated into SQL, so untrusted free-text fields (name, title, rationale) cannot form a
statement.

Every projection deduplicates a re-export: ``records`` (``ReplacingMergeTree`` on ``ingested_at``)
collapses a re-inserted ``record_id``, ``feedback_items`` collapses on ``item_id``, and
``feedback_transitions`` collapses on the deterministic, globally-unique ``transition_id`` —
migration 0005 recreated it as a ``ReplacingMergeTree`` (``ORDER BY (item_id, transition_id)``),
closing the one table a plain ``MergeTree`` left non-idempotent. So a re-export changes no logical
state (``feedback_current`` derives via ``argMax`` / ``max`` over the locked total order) and leaves
no lasting duplicate row. The production ``storage export`` path drives :func:`export_records`
through the segment delivery ledger (:class:`~milhouse.storage.delivery.ClickHouseExporter` under
:func:`~milhouse.spooling.exporter.deliver_segment` /
:func:`~milhouse.spooling.replay.replay_segments`), whose fenced compare-and-set makes delivery
*logically* exactly-once: it reports one delivery per segment and skips a segment already
``delivered`` (re-inserting nothing). It is not a distributed lock, so at-least-once delivery still
holds — an interrupted retry (a crash after the ClickHouse write but before the ledger checkpoint)
or two concurrent drains DO write a transient duplicate ``feedback_transitions`` row. That physical
duplicate is exactly what the 0005 ``ReplacingMergeTree`` collapses on merge, so the logical state
is unchanged either way.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from milhouse.domain.records import (
    FeedbackItemDataV1,
    FeedbackTransitionDataV1,
    RecordEnvelopeV1,
)
from milhouse.privacy.egress import EgressSurface, require_egress
from milhouse.storage._identifiers import require_identifier
from milhouse.storage.client import ClickHouseClient

_RECORDS_TABLE = "records"
_FEEDBACK_ITEMS_TABLE = "feedback_items"
_FEEDBACK_TRANSITIONS_TABLE = "feedback_transitions"

_RECORD_COLUMNS: tuple[str, ...] = (
    "schema_version",
    "record_id",
    "record_type",
    "name",
    "target_id",
    "occurred_at",
    "observed_at",
    "ingested_at",
    "expires_at",
    "source_event_id",
    "source_entity_id",
    "operation_id",
    "dedupe_key",
    "content_hash",
    "severity",
    "privacy_class",
)
_FEEDBACK_ITEM_COLUMNS: tuple[str, ...] = (
    "item_id",
    "fingerprint",
    "created_at",
    "target_id",
    "title",
    "severity",
    "priority",
    "actionability",
    "confidence",
    "privacy_class",
)
_FEEDBACK_TRANSITION_COLUMNS: tuple[str, ...] = (
    "transition_id",
    "item_id",
    "revision",
    "from_state",
    "to_state",
    "occurred_at",
    "actor_type",
    "rationale",
)


@dataclass(frozen=True, slots=True)
class ExportSummary:
    """How many rows one :func:`export_records` pass wrote to each table."""

    records: int
    feedback_items: int
    feedback_transitions: int


def _record_row(record: RecordEnvelopeV1) -> tuple[object, ...]:
    # ``target``/``source_*`` are optional in the domain but non-nullable ``String`` columns; the
    # analytical convention is the empty string for "absent" (installation-scoped or no source).
    return (
        record.schema_version,
        record.record_id,
        record.record_type,
        record.name,
        record.target.id if record.target is not None else "",
        record.occurred_at,
        record.observed_at,
        record.ingested_at,
        record.expires_at,
        record.source_event_id or "",
        record.source_entity_id or "",
        record.operation_id,
        record.dedupe_key,
        record.content_hash,
        record.severity,
        record.privacy_class,
    )


def _feedback_item_row(data: FeedbackItemDataV1) -> tuple[object, ...]:
    return (
        data.item_id,
        data.fingerprint,
        data.created_at,
        data.target_id,
        data.title,
        data.severity,
        data.priority,
        data.actionability,
        data.confidence,
        data.privacy_class,
    )


def _feedback_transition_row(data: FeedbackTransitionDataV1) -> tuple[object, ...]:
    return (
        data.transition_id,
        data.item_id,
        data.revision,
        data.from_state,
        data.to_state,
        data.timestamp,
        data.actor.type,
        data.rationale,
    )


def export_records(
    client: ClickHouseClient, database: str, records: Sequence[RecordEnvelopeV1]
) -> ExportSummary:
    """Authorize and write ``records`` into ``database``; return the per-table row counts."""

    require_identifier(
        database,
        code="MH_STORAGE_CONFIG",
        message="a bounded ClickHouse database identifier is required",
    )
    record_rows: list[tuple[object, ...]] = []
    item_rows: list[tuple[object, ...]] = []
    transition_rows: list[tuple[object, ...]] = []
    for record in records:
        # Fail closed at the persistence boundary; ``restricted`` never reaches the store.
        require_egress(surface=EgressSurface.LOCAL_CLICKHOUSE, privacy_class=record.privacy_class)
        record_rows.append(_record_row(record))
        data = record.data
        if isinstance(data, FeedbackItemDataV1):
            item_rows.append(_feedback_item_row(data))
        elif isinstance(data, FeedbackTransitionDataV1):
            transition_rows.append(_feedback_transition_row(data))

    client.insert(database, _RECORDS_TABLE, record_rows, column_names=_RECORD_COLUMNS)
    client.insert(database, _FEEDBACK_ITEMS_TABLE, item_rows, column_names=_FEEDBACK_ITEM_COLUMNS)
    client.insert(
        database,
        _FEEDBACK_TRANSITIONS_TABLE,
        transition_rows,
        column_names=_FEEDBACK_TRANSITION_COLUMNS,
    )
    return ExportSummary(
        records=len(record_rows),
        feedback_items=len(item_rows),
        feedback_transitions=len(transition_rows),
    )


__all__ = ["ExportSummary", "export_records"]
