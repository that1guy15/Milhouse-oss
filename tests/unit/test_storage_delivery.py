"""Delivery-ledger guarantees for the ClickHouse exporter (W04 G04b, plan section 4.5).

Mirrors the ``test_spool_exporter`` harness — a real ``ControlDatabase`` + ``GlobalCommitBarrier`` +
``DurableSpool`` on ``tmp_path`` — and drives the G03-certified ``deliver_segment`` /
``replay_segments`` machine through the concrete :class:`ClickHouseExporter` over an in-memory
``FakeClickHouseClient``. It proves the exporter satisfies the spool ``Exporter`` protocol, that a
re-drain is a compare-and-set no-op (so the append-only ``feedback_transitions`` table never gains a
duplicate row per re-export — the cost the direct exporter flagged), and that a delivery that raised
stays retryable while the next drain delivers exactly once (the outage kernel). A
``feedback_transition`` record exercises the ``feedback_transitions`` path.

The retry (crash-after-confirm-before-CAS) and concurrency (two drains) tests prove the INPUTS to
physical idempotency — that an at-least-once redelivery re-inserts rows carrying the SAME
deterministic ``transition_id`` / ``record_id`` / ``item_id`` while the ledger advances to
``delivered`` exactly once. The physical collapse of those duplicate rows is a property of the 0005
``ReplacingMergeTree`` and is only observable against a live ClickHouse (E06 / host-gated), because
``FakeClickHouseClient`` records inserts verbatim and does not model merges.
"""

from __future__ import annotations

import os
import threading
from datetime import timedelta
from pathlib import Path

import pytest
from _record_factories import INSTALLATION_ID, NOW, feedback_transition_record
from _storage_fakes import FakeClickHouseClient

from milhouse.domain.records import RecordEnvelopeV1
from milhouse.spooling import (
    DurableSpool,
    Exporter,
    SegmentHeaderV1,
    SegmentRecord,
    SpoolError,
    SpoolFrameV1,
    deliver_segment,
    replay_segments,
    spool_content_sha256,
    spool_frame_line,
)
from milhouse.spooling import exporter as exporter_module
from milhouse.state import (
    GlobalCommitBarrier,
    initialize_control_state,
    open_control_database,
)
from milhouse.storage import CLICKHOUSE_EXPORTER_ID, ClickHouseExporter
from milhouse.storage.schema import CLICKHOUSE_MIGRATIONS

_DATABASE = "milhouse"
_GENERATION = "a" * 64


class _RaisingClient(FakeClickHouseClient):
    """A fake whose ``insert`` raises so the delivery is contained as a retryable failure."""

    def insert(self, *args: object, **kwargs: object) -> None:
        raise RuntimeError("clickhouse insert unavailable")


class _RendezvousExporter:
    """A ClickHouse exporter that makes two drains rendezvous at a barrier before inserting.

    Both threads reload the ledger as ``pending`` (before ``deliver`` runs), then wait here so both
    insert BEFORE either advances the compare-and-set — the exact concurrent-drain interleaving.
    """

    def __init__(
        self, client: FakeClickHouseClient, database: str, gate: threading.Barrier
    ) -> None:
        self._inner = ClickHouseExporter(client, database)
        self._gate = gate

    @property
    def exporter_id(self) -> str:
        return CLICKHOUSE_EXPORTER_ID

    def deliver(self, record: SegmentRecord, frames: object) -> None:
        self._gate.wait(timeout=20)
        self._inner.deliver(record, frames)  # type: ignore[arg-type]


def _frames(batch_id: str, records: tuple[RecordEnvelopeV1, ...]) -> list[SpoolFrameV1]:
    return [
        SpoolFrameV1(batch_id=batch_id, sequence=index, record=record)
        for index, record in enumerate(records, start=1)
    ]


def _header(batch_id: str, frames: list[SpoolFrameV1]) -> SegmentHeaderV1:
    lines = [spool_frame_line(frame) for frame in frames]
    return SegmentHeaderV1(
        batch_id=batch_id,
        config_generation=_GENERATION,
        scope="target",
        target_id="example-target",
        privacy_class="internal",
        retention_days=30,
        required_exporters=(CLICKHOUSE_EXPORTER_ID,),
        record_count=len(frames),
        content_sha256=spool_content_sha256(lines),
    )


def _spool(tmp_path: Path):
    control = tmp_path / "control"
    control.mkdir(mode=0o700)
    os.chmod(control, 0o700)
    database = open_control_database(control / "milhouse.sqlite3")
    barrier = GlobalCommitBarrier(control / "commit.lock")
    initialize_control_state(database, barrier=barrier, applied_at=NOW)
    spool_root = tmp_path / "spool"
    spool_root.mkdir(mode=0o700)
    os.chmod(spool_root, 0o700)
    store = DurableSpool(
        database=database, barrier=barrier, spool_root=spool_root, installation_id=INSTALLATION_ID
    )
    return database, barrier, spool_root, store


def _commit(
    store: DurableSpool, batch_id: str, records: tuple[RecordEnvelopeV1, ...]
) -> tuple[SegmentRecord, list[SpoolFrameV1]]:
    frames = _frames(batch_id, records)
    record = store.commit_segment(_header(batch_id, frames), frames, committed_at=NOW)
    return record, frames


def _status(database, batch_id: str, exporter_id: str = CLICKHOUSE_EXPORTER_ID) -> str | None:
    row = database.connection.execute(
        "SELECT delivery_status FROM _segment_exporters WHERE batch_id = ? AND exporter_id = ?",
        (batch_id, exporter_id),
    ).fetchone()
    return None if row is None else str(row[0])


def _drain(database, barrier, spool_root, exporter, *, now, delivery_status=None):
    return replay_segments(
        database,
        barrier,
        spool_root=spool_root,
        installation_id=INSTALLATION_ID,
        exporters={CLICKHOUSE_EXPORTER_ID: exporter},
        now=now,
        delivery_status=delivery_status,
    )


def _tables(client: FakeClickHouseClient) -> list[str]:
    return [table for _db, table, *_ in client.inserts]


def _inserts_for(
    client: FakeClickHouseClient, table: str
) -> list[tuple[list[list[object]], tuple[str, ...]]]:
    return [(rows, columns) for _db, tbl, rows, columns in client.inserts if tbl == table]


def _cell(rows: list[list[object]], columns: tuple[str, ...], name: str) -> object:
    return dict(zip(columns, rows[0], strict=True))[name]


def test_exporter_id_and_direct_deliver_inserts_the_records_once(tmp_path: Path) -> None:
    database, _barrier, _spool_root, store = _spool(tmp_path)
    try:
        record, frames = _commit(store, "batch-a", (feedback_transition_record(),))
        fake = FakeClickHouseClient()
        exporter = ClickHouseExporter(fake, _DATABASE)
        assert isinstance(exporter, Exporter)  # satisfies the spool protocol
        assert exporter.exporter_id == CLICKHOUSE_EXPORTER_ID
        exporter.deliver(record, frames)
        # A feedback transition projects to the deduplicating records table AND the append-only
        # feedback_transitions table — inserted once each by this single deliver.
        assert _tables(fake) == ["records", "feedback_transitions"]
    finally:
        database.close()


def test_first_drain_delivers_then_a_redrain_is_a_no_op_without_duplicate_transitions(
    tmp_path: Path,
) -> None:
    database, barrier, spool_root, store = _spool(tmp_path)
    try:
        _commit(store, "batch-a", (feedback_transition_record(),))
        fake = FakeClickHouseClient()
        exporter = ClickHouseExporter(fake, _DATABASE)

        first = _drain(database, barrier, spool_root, exporter, now=NOW, delivery_status="pending")
        assert [a.outcome for a in first.delivery_attempts] == ["delivered"]
        assert _status(database, "batch-a") == "delivered"
        assert _tables(fake) == ["records", "feedback_transitions"]  # forwarded once
        inserts_after_first = len(fake.inserts)

        # A full re-drain re-reads the same segment, but the terminal ledger row makes delivery a
        # compare-and-set no-op: already_delivered, and NOT one more feedback_transitions row.
        second = _drain(database, barrier, spool_root, exporter, now=NOW)
        assert [a.outcome for a in second.delivery_attempts] == ["already_delivered"]
        assert len(fake.inserts) == inserts_after_first  # zero new inserts
    finally:
        database.close()


def test_a_failed_delivery_stays_retryable_and_the_next_drain_delivers_exactly_once(
    tmp_path: Path,
) -> None:
    database, barrier, spool_root, store = _spool(tmp_path)
    try:
        _commit(store, "batch-a", (feedback_transition_record(),))

        outage = _drain(
            database,
            barrier,
            spool_root,
            ClickHouseExporter(_RaisingClient(), _DATABASE),
            now=NOW,
            delivery_status="pending",
        )
        assert [a.outcome for a in outage.delivery_attempts] == ["failed"]
        assert _status(database, "batch-a") == "failed"  # retryable, never terminal-delivered

        # The outage clears; a full replay (the recovery/rebuild path, delivery_status=None) at ~24h
        # visits the segment and redelivers the retryable failed row — delivered exactly once, since
        # deliver_segment's compare-and-set advances any row that is not already terminal-delivered.
        healthy = FakeClickHouseClient()
        recovered = _drain(
            database,
            barrier,
            spool_root,
            ClickHouseExporter(healthy, _DATABASE),
            now=NOW + timedelta(hours=24),
        )
        assert [a.outcome for a in recovered.delivery_attempts] == ["delivered"]
        assert _status(database, "batch-a") == "delivered"
        assert _tables(healthy) == ["records", "feedback_transitions"]  # delivered exactly once
    finally:
        database.close()


def test_crash_after_confirm_before_cas_redelivers_the_same_ids_exactly_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The at-least-once retry boundary: a crash AFTER the ClickHouse insert confirms but BEFORE the
    # ledger compare-and-set advances leaves the row not-delivered, so the next drain re-inserts.
    # Prove the retry re-inserts the SAME deterministic ids (which 0005's ReplacingMergeTree
    # collapses on a live ClickHouse) and that the ledger advances to delivered exactly once.
    database, barrier, _spool_root, store = _spool(tmp_path)
    try:
        record, frames = _commit(store, "batch-a", (feedback_transition_record(),))
        fake = FakeClickHouseClient()
        exporter = ClickHouseExporter(fake, _DATABASE)

        real_cas = exporter_module._advance_status_locked
        calls = {"n": 0}

        def _flaky_cas(database: object, batch_id: str, exporter_id: str, status: str) -> str:
            calls["n"] += 1
            if calls["n"] == 1:  # the insert already confirmed; the ledger write is lost (crash)
                raise SpoolError("MH_SPOOL_EXPORT", "the delivery status could not be recorded")
            return real_cas(database, batch_id, exporter_id, status)

        monkeypatch.setattr(exporter_module, "_advance_status_locked", _flaky_cas)

        with pytest.raises(SpoolError):
            deliver_segment(
                database, barrier, record, frames, {CLICKHOUSE_EXPORTER_ID: exporter}, now=NOW
            )
        assert _status(database, "batch-a") == "pending"  # CAS never advanced → still retryable

        attempts = deliver_segment(
            database, barrier, record, frames, {CLICKHOUSE_EXPORTER_ID: exporter}, now=NOW
        )
        assert [a.outcome for a in attempts] == ["delivered"]
        assert _status(database, "batch-a") == "delivered"  # delivered exactly once at the ledger

        # The transition was physically inserted twice (the retry), both rows with identical ids.
        transitions = _inserts_for(fake, "feedback_transitions")
        assert len(transitions) == 2
        assert {_cell(rows, cols, "transition_id") for rows, cols in transitions} == {
            "transition-1"
        }
        assert {_cell(rows, cols, "item_id") for rows, cols in transitions} == {"feedback-1"}
        record_ids = {
            _cell(rows, cols, "record_id") for rows, cols in _inserts_for(fake, "records")
        }
        assert len(record_ids) == 1  # both records-table inserts carry the same record_id
    finally:
        database.close()


def test_concurrent_drains_insert_identical_ids_but_deliver_exactly_once(tmp_path: Path) -> None:
    # The concurrency boundary: two independent drains (each its own control connection + barrier,
    # sharing the commit lock) both pass the pending check and both insert the transition, but the
    # fenced compare-and-set advances exactly one to delivered. Both physical rows carry identical
    # deterministic ids (which 0005's ReplacingMergeTree collapses on a live ClickHouse).
    database, _barrier, _spool_root, store = _spool(tmp_path)
    control_path = database.path
    try:
        record, frames = _commit(store, "batch-a", (feedback_transition_record(),))
        fake = FakeClickHouseClient()
        gate = threading.Barrier(2)
        lock = threading.Lock()
        outcomes: list[str] = []
        errors: list[BaseException] = []

        def _worker() -> None:
            try:
                db = open_control_database(control_path)
                try:
                    barrier = GlobalCommitBarrier(control_path.parent / "commit.lock")
                    exporter = _RendezvousExporter(fake, _DATABASE, gate)
                    attempts = deliver_segment(
                        db, barrier, record, frames, {CLICKHOUSE_EXPORTER_ID: exporter}, now=NOW
                    )
                    with lock:
                        outcomes.extend(a.outcome for a in attempts)
                finally:
                    db.close()
            except BaseException as exc:  # surface a thread failure in the assertion, never hang
                gate.abort()
                with lock:
                    errors.append(exc)

        threads = [threading.Thread(target=_worker) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)

        assert errors == []
        assert sorted(outcomes) == ["already_delivered", "delivered"]  # exactly one delivered
        verify = open_control_database(control_path)
        try:
            assert _status(verify, "batch-a") == "delivered"  # ledger ends delivered once
        finally:
            verify.close()
        # Both drains inserted the transition; the identical deterministic id is what lets 0005
        # collapse the two physical rows into one on a live ClickHouse.
        transitions = _inserts_for(fake, "feedback_transitions")
        assert len(transitions) == 2
        assert {_cell(rows, cols, "transition_id") for rows, cols in transitions} == {
            "transition-1"
        }
    finally:
        database.close()


def test_migration_0005_makes_feedback_transitions_replacing_on_transition_id() -> None:
    # The packaged 0005 SQL is what makes the redeliveries above collapse physically.
    dedup = next(m for m in CLICKHOUSE_MIGRATIONS if m.version == 5)
    assert dedup.name == "feedback_transition_dedup"
    assert "feedback_transitions" in dedup.sql
    assert "ReplacingMergeTree" in dedup.sql
    assert "ORDER BY (item_id, transition_id)" in dedup.sql  # transition_id in the sort key
