"""ClickHouse delivery exporter over the segment delivery ledger (W04 G04b, plan section 4.5).

The spool owns a complete, G03-certified exactly-once-logical delivery machine — the
``_segment_exporters`` ledger, :func:`~milhouse.spooling.exporter.deliver_segment` (a fenced
compare-and-set over ``pending``/``failed`` → ``delivered``), and
:func:`~milhouse.spooling.replay.replay_segments` (the drain) — all keyed on an exporter id.
:class:`ClickHouseExporter` is the concrete destination for the ``"clickhouse"`` id: it satisfies
the :class:`~milhouse.spooling.exporter.Exporter` protocol so the ledger machine can drive it.

``deliver`` reuses :func:`~milhouse.storage.exporter.export_records` over the committed segment's
frames — the same per-record ``LOCAL_CLICKHOUSE`` egress authorization and native-column insert used
by the direct export path — and raises on any failure, so ``deliver_segment`` records a retryable
``failed`` and a terminal ``delivered`` is only ever set after ClickHouse confirms the write.
Because ``deliver_segment`` never re-delivers a segment already ``delivered``, re-running the
drain after an outage is a no-op compare-and-set: each committed segment reaches ClickHouse
exactly once *logically*, so the append-only ``feedback_transitions`` table stops accumulating a
duplicate row per re-export (the cost the direct exporter's docstring flags). Delivery is
at-least-once and this exporter is idempotent, as the protocol requires: a crash between the
ClickHouse write and the ledger checkpoint leaves the segment retryable, and the next drain
re-delivers into the deduplicating ``records`` table and the transition-derived
``feedback_current`` view without changing logical state.
"""

from __future__ import annotations

from collections.abc import Sequence

from milhouse.spooling.ledger import SegmentRecord
from milhouse.spooling.segment import SpoolFrameV1
from milhouse.storage.client import ClickHouseClient
from milhouse.storage.exporter import export_records

# The established delivery-ledger exporter id (see the demo's ``required_exporters``); it is what a
# committed segment records as a pending exporter and what the drain looks up this destination
# under.
CLICKHOUSE_EXPORTER_ID = "clickhouse"


class ClickHouseExporter:
    """Forward a committed segment's records to ClickHouse, satisfying the spool ``Exporter``
    protocol.

    Constructed with an authenticated :class:`ClickHouseClient` and the target database name; a
    single instance is passed to :func:`~milhouse.spooling.replay.replay_segments` as
    ``{CLICKHOUSE_EXPORTER_ID: exporter}``. It holds no per-segment state — the delivery ledger owns
    all checkpointing — so one instance safely serves an entire drain pass.
    """

    __slots__ = ("_client", "_database")

    def __init__(self, client: ClickHouseClient, database: str) -> None:
        self._client = client
        self._database = database

    @property
    def exporter_id(self) -> str:
        return CLICKHOUSE_EXPORTER_ID

    def deliver(self, record: SegmentRecord, frames: Sequence[SpoolFrameV1]) -> None:
        """Write ``frames``' records to ClickHouse; raise on any failure so the ledger records it.

        ``record`` (the reloaded ledger row) is already validated against ``frames`` by
        ``deliver_segment`` before this runs, so delivery only needs the records the frames carry.
        :func:`export_records` re-authorizes each record against ``LOCAL_CLICKHOUSE`` (fail closed)
        and inserts as native column data, so an unexpected ``restricted`` record fails the whole
        delivery closed rather than leaking.
        """

        export_records(self._client, self._database, tuple(frame.record for frame in frames))


__all__ = ["CLICKHOUSE_EXPORTER_ID", "ClickHouseExporter"]
