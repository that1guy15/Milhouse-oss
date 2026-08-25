"""Shared crash/concurrency/failure-injection harness for the W03 G03 gate (slice 7).

Reusable building blocks used by the ``test_g03_*`` suites: a spool builder, a deterministic
record/segment generator, a no-op exporter, and a fault-injecting SQLite connection proxy that
forces a chosen durable-write statement to fail so a boundary's atomic rollback and fixed-code
fail-closed behaviour can be exercised without a real crash. This module is intentionally not a
``test_`` file, so pytest imports it as a helper rather than collecting it.
"""

from __future__ import annotations

import os
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from milhouse.domain.records import (
    CollectorDescriptorV1,
    EventDataV1,
    RecordDraftV1,
    RecordEnvelopeV1,
    SourceDescriptorV1,
    TargetDescriptorV1,
    finalize_record,
)
from milhouse.spooling import (
    DurableSpool,
    SegmentHeaderV1,
    SegmentRecord,
    SpoolFrameV1,
    spool_content_sha256,
    spool_frame_line,
)
from milhouse.state import (
    GlobalCommitBarrier,
    initialize_control_state,
    open_control_database,
)

INSTALLATION_ID = "mh_in1_00000000000040008000000000000000"
NOW = datetime(2026, 7, 28, 12, 0, 0, tzinfo=UTC)
DAY = "2026-07-28"
GENERATION = "a" * 64
LIVE_AT = NOW + timedelta(days=30)


class NoopExporter:
    """An exporter that confirms delivery by returning, for exercising the delivery/replay path."""

    def __init__(self, exporter_id: str = "clickhouse") -> None:
        self._exporter_id = exporter_id

    @property
    def exporter_id(self) -> str:
        return self._exporter_id

    def deliver(self, record: SegmentRecord, frames: object) -> None:
        return None


def build_spool(tmp_path: Path) -> tuple[Any, GlobalCommitBarrier, Path, DurableSpool]:
    """Create an initialized database, barrier, spool root, and durable spool in tmp_path."""

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


def open_writer(
    database_path: Path, barrier: GlobalCommitBarrier, spool_root: Path
) -> tuple[Any, DurableSpool]:
    """Open an INDEPENDENT durable spool (its own DB connection) on an already-initialized state.

    Constructing the spool runs mandatory reconciliation, so this doubles as a "restart". Returns
    the database and the store; the caller closes the database. Used by the crash-recovery and
    concurrency suites so each writer has its own connection, coordinated only through the
    cross-process commit barrier and SQLite file locking.
    """

    database = open_control_database(database_path)
    store = DurableSpool(
        database=database, barrier=barrier, spool_root=spool_root, installation_id=INSTALLATION_ID
    )
    return database, store


def fresh_writer(
    database_path: Path, spool_root: Path
) -> tuple[Any, GlobalCommitBarrier, DurableSpool]:
    """Open a fully independent writer — its own DB connection AND its own barrier instance.

    Each concurrent thread needs its own connection (SQLite ``check_same_thread``) and its own
    barrier instance (the barrier's in-process reentrancy is per-instance/thread), coordinated only
    through the cross-process ``commit.lock`` flock and SQLite's busy timeout.
    """

    database = open_control_database(database_path)
    barrier = GlobalCommitBarrier(database_path.parent / "commit.lock")
    store = DurableSpool(
        database=database, barrier=barrier, spool_root=spool_root, installation_id=INSTALLATION_ID
    )
    return database, barrier, store


# The record's non-identity sub-models are identical for every generated record, so they are built
# once and reused; only source_event_id (which drives the derived record identity) and expires_at
# vary per record. The domain forbids an unchecked model_copy, so the draft is still fully validated
# per record — but reusing the sub-models keeps a 10,000-record scale test tractable.
_SOURCE = SourceDescriptorV1.model_validate(
    {
        "id": "example-source",
        "type": "source.event",
        "producer": "collector",
        "observation_namespace_id": "mh_ns1_00000000000040008000000000000000",
        "source_generation_digest": "0" * 64,
        "observation": {"kind": "source.revision", "parts": {"revision": 1}},
    }
)
_COLLECTOR = CollectorDescriptorV1(id="c", type="site.canary", implementation_version="1.0.0")
_TARGET = TargetDescriptorV1(id="example-target", name="E", kind="web.service", environment="test")
_DATA = EventDataV1(category="availability", status="healthy", message="ok")


def make_envelope(source_event_id: str, *, expires_at: datetime = LIVE_AT) -> RecordEnvelopeV1:
    values: dict[str, object] = {
        "record_type": "event",
        "name": "source.event",
        "occurred_at": NOW,
        "observed_at": NOW + timedelta(seconds=1),
        "ingested_at": NOW + timedelta(seconds=2),
        "expires_at": expires_at,
        "source_event_id": source_event_id,
        "operation_id": "operation-1",
        "collector_run_id": "collector-run-1",
        "scope": "target",
        "source": _SOURCE,
        "collector": _COLLECTOR,
        "target": _TARGET,
        "severity": "info",
        "trust_level": "authenticated",
        "privacy_class": "internal",
        "redaction_version": "r1-e1",
        "data": _DATA,
    }
    return finalize_record(RecordDraftV1.model_validate(values), installation_id=INSTALLATION_ID)


def make_frames(
    batch_id: str, event_ids: list[str], *, expires_at: datetime = LIVE_AT
) -> list[SpoolFrameV1]:
    return [
        SpoolFrameV1(
            batch_id=batch_id, sequence=index, record=make_envelope(e, expires_at=expires_at)
        )
        for index, e in enumerate(event_ids, start=1)
    ]


def make_header(
    batch_id: str, frames: list[SpoolFrameV1], exporters: tuple[str, ...] = ("clickhouse",)
) -> SegmentHeaderV1:
    lines = [spool_frame_line(frame) for frame in frames]
    return SegmentHeaderV1(
        batch_id=batch_id,
        config_generation=GENERATION,
        scope="target",
        target_id="example-target",
        privacy_class="internal",
        retention_days=30,
        required_exporters=exporters,
        record_count=len(frames),
        content_sha256=spool_content_sha256(lines),
    )


def commit_segment(
    store: DurableSpool,
    batch_id: str,
    event_ids: list[str],
    *,
    exporters: tuple[str, ...] = ("clickhouse",),
    expires_at: datetime = LIVE_AT,
) -> tuple[SegmentRecord, list[SpoolFrameV1]]:
    frames = make_frames(batch_id, event_ids, expires_at=expires_at)
    record = store.commit_segment(
        make_header(batch_id, frames, exporters), frames, committed_at=NOW
    )
    return record, frames


def segment_file(spool_root: Path, batch_id: str) -> Path:
    return spool_root / "pending" / DAY / f"{batch_id}.jsonl"


def segment_rows(database: Any) -> set[str]:
    return {
        row[0] for row in database.connection.execute("SELECT batch_id FROM _segments").fetchall()
    }


def staged_temp_files(spool_root: Path) -> list[Path]:
    day_dir = spool_root / "pending" / DAY
    if not day_dir.exists():
        return []
    return [p for p in day_dir.iterdir() if p.name.startswith(".milhouse-stage-")]


class FaultyConnection:
    """Wrap a ``sqlite3.Connection`` and raise a chosen error when a target statement executes.

    Installed on ``ControlDatabase._connection`` (a declared slot) so that a specific durable-write
    statement inside a transaction fails, proving the boundary rolls back atomically and normalizes
    to a fixed code. All other attributes and methods delegate to the real connection.
    """

    def __init__(
        self,
        real: sqlite3.Connection,
        *,
        fail_when: str,
        skip: int = 0,
        error: Exception | None = None,
    ) -> None:
        self._real = real
        self._fail_when = fail_when
        self._skip = skip
        self._error = error or sqlite3.OperationalError("injected durable-write fault")

    def execute(self, sql: str, *args: Any, **kwargs: Any) -> Any:
        if self._fail_when in sql:
            if self._skip <= 0:
                raise self._error
            self._skip -= 1
        return self._real.execute(sql, *args, **kwargs)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._real, name)


def inject_sql_fault(database: Any, fail_when: str, *, skip: int = 0) -> None:
    """Force the next matching (after ``skip``) durable-write statement on ``database`` to fail.

    The proxy stays installed for the rest of the database's life; tests use a fresh database, so no
    explicit teardown is required.
    """

    database._connection = FaultyConnection(database.connection, fail_when=fail_when, skip=skip)
