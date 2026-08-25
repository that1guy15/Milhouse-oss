"""Query repository over the deduplicating current-state views (W04 G04b, plan section 4.5).

Reads go through the ``records_current`` / ``feedback_current`` views, which apply ``FINAL``
deduplication, query-time retention (``expires_at > now64``), and the locked ``argMax`` feedback
derivation — so callers see current state without re-implementing any of it. The repository returns
privacy-safe *metadata* projections (never a raw payload; the ``records`` table stores none) as
JSON-serializable dataclasses. Every database name is validated as a bounded identifier and every
caller-supplied filter value is bound as a server-side ``{name:Type}`` parameter, never formatted
into SQL.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime

from milhouse.core.clock import format_timestamp
from milhouse.storage._identifiers import require_identifier
from milhouse.storage.client import ClickHouseClient

_RECORD_SELECT = (
    "record_id, record_type, name, target_id, "
    "occurred_at, ingested_at, expires_at, severity, privacy_class"
)
_FEEDBACK_SELECT = "item_id, current_state, current_revision, last_transition_at"


@dataclass(frozen=True, slots=True)
class StoredRecordV1:
    """One deduplicated, non-expired record's privacy-safe metadata from ``records_current``."""

    record_id: str
    record_type: str
    name: str
    target_id: str
    occurred_at: str
    ingested_at: str
    expires_at: str
    severity: str
    privacy_class: str


@dataclass(frozen=True, slots=True)
class FeedbackStateRow:
    """One feedback item's derived current state from ``feedback_current``."""

    item_id: str
    current_state: str
    current_revision: int
    last_transition_at: str


def _iso(value: object) -> str:
    # ClickHouse ``DateTime64(3,'UTC')`` returns a datetime; normalize to the canonical RFC3339
    # millisecond string used everywhere else (EventSummary, the spool ledger, canonical JSON).
    if isinstance(value, datetime):
        aware = value if value.tzinfo is not None else value.replace(tzinfo=UTC)
        return format_timestamp(aware)
    return str(value)


def _require_database(database: str) -> str:
    return require_identifier(
        database,
        code="MH_STORAGE_CONFIG",
        message="a bounded ClickHouse database identifier is required",
    )


def fetch_current_records(
    client: ClickHouseClient, database: str, *, target_id: str | None = None
) -> tuple[StoredRecordV1, ...]:
    """Return the current (deduplicated, non-expired) records, optionally filtered by target."""

    _require_database(database)
    statement = "SELECT " + _RECORD_SELECT + " FROM " + database + ".records_current"
    parameters: Mapping[str, object] | None = None
    if target_id is not None:
        statement += " WHERE target_id = {target:String}"
        parameters = {"target": target_id}
    statement += " ORDER BY ingested_at DESC, record_id"
    rows = client.query(statement, parameters=parameters)
    return tuple(
        StoredRecordV1(
            record_id=str(row[0]),
            record_type=str(row[1]),
            name=str(row[2]),
            target_id=str(row[3]),
            occurred_at=_iso(row[4]),
            ingested_at=_iso(row[5]),
            expires_at=_iso(row[6]),
            severity=str(row[7]),
            privacy_class=str(row[8]),
        )
        for row in rows
    )


def fetch_current_feedback(client: ClickHouseClient, database: str) -> tuple[FeedbackStateRow, ...]:
    """Return the transition-derived current state of each feedback item, ordered by item id.

    ``feedback_current`` derives state from the append-only transition log, so an item that has been
    created but never transitioned (still ``open`` at revision 0) does not appear here — it is
    visible as its ``feedback_item`` record via :func:`fetch_current_records`. Folding those
    untriaged-open items into a single current-state surface is the feedback service's concern
    (W08); this repository intentionally exposes exactly what the view derives.
    """

    _require_database(database)
    statement = (
        "SELECT " + _FEEDBACK_SELECT + " FROM " + database + ".feedback_current ORDER BY item_id"
    )
    rows = client.query(statement)
    return tuple(
        FeedbackStateRow(
            item_id=str(row[0]),
            current_state=str(row[1]),
            current_revision=int(row[2]),
            last_transition_at=_iso(row[3]),
        )
        for row in rows
    )


__all__ = [
    "FeedbackStateRow",
    "StoredRecordV1",
    "fetch_current_feedback",
    "fetch_current_records",
]
