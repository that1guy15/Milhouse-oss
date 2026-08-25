"""End-to-end: the ``file_outbox`` collector driven through the real W07 runtime pipeline.

These offline tests exercise the highest-risk increment of W07 -- the durable cursor advance and the
frame->record mapping -- through a REAL :class:`~milhouse.runtime.pipeline.RuntimePipeline` over a
temp outbox, control database, and spool. They prove the three load-bearing invariants directly:

* **(a)** a segment commits BEFORE the cursor/ack advance, and an empty/unchanged read advances
  nothing;
* **(b)** a commit-then-crash-before-advance replay re-reads the same frame and produces the SAME
  ``record_id`` (deterministic identity -> downstream dedup collapses the duplicate) -- the
  load-bearing test;
* **(c)** a data-loss read commits and advances NOTHING and surfaces the fixed loss code.

Plus the generic opt-in (a non-cursor collector never touches a cursor or ack) and the post-commit
advance-failure isolation (a failed advance never unwinds the durable commit).
"""

from __future__ import annotations

import json
import os
from datetime import timedelta
from pathlib import Path

import pytest
from _record_factories import INSTALLATION_ID, NOW
from _runtime_harness import (
    KNOWN_SECRET,
    SECRET_MARKER,
    FakeCollector,
    build_control,
    make_pipeline,
    registry_with,
    target_config,
)

from milhouse.collectors.file_outbox import FileOutboxBinding, register_file_outbox
from milhouse.config._models import FileOutboxCollector as FileOutboxConfig
from milhouse.core.clock import FixedClock
from milhouse.domain.records import MAX_DIMENSION_VALUE_BYTES, CollectorDescriptorV1
from milhouse.outbox import read_outbox_ack
from milhouse.runtime import CollectorRegistry
from milhouse.spooling import read_trusted_segment
from milhouse.state import read_cursor

_OUTBOX_NAME = "feedback-outbox.jsonl"
_ACK_NAME = "outbox-ack.json"
_COLLECTOR_ID = "app-outbox"
_TARGET_ID = "t1"
_DAY = NOW.date().isoformat()
_TS = "2026-08-17T12:00:00.000Z"


# --- helpers ------------------------------------------------------------------------------------


def _frame_document(**overrides: object) -> dict[str, object]:
    document: dict[str, object] = {
        "schema_version": "1.0",
        "producer_id": "web-ci",
        "occurred_at": _TS,
        "target": "web-service",
        "kind": "deploy.completed",
        "actionability": "observe",
        "evidence_references": ["ev-1"],
        "data": {"count": 3},
    }
    document.update(overrides)
    return document


def _frame_line(**overrides: object) -> bytes:
    return json.dumps(_frame_document(**overrides)).encode("utf-8") + b"\n"


def _milhouse_dir(tmp_path: Path) -> Path:
    """Create the owner-only 0700 ``.milhouse`` directory the ack read/writer requires."""

    directory = tmp_path / ".milhouse"
    directory.mkdir(mode=0o700)
    os.chmod(directory, 0o700)
    return directory


def _outbox_config(**overrides: object) -> FileOutboxConfig:
    body: dict[str, object] = {
        "id": _COLLECTOR_ID,
        "target": _TARGET_ID,
        "type": "file_outbox",
        "path": _OUTBOX_NAME,
        "producer_allowlist": [],
        "ack_filename": _ACK_NAME,
    }
    body.update(overrides)
    return FileOutboxConfig.model_validate(body)


def _registry(outbox_path: Path, ack_directory: Path) -> CollectorRegistry:
    registry = CollectorRegistry()
    register_file_outbox(
        registry,
        outbox_paths={
            _COLLECTOR_ID: FileOutboxBinding(outbox_path=outbox_path, ack_directory=ack_directory)
        },
    )
    return registry


def _record_ids(spool_root: Path, batch_id: str) -> list[str]:
    path = spool_root / "pending" / _DAY / f"{batch_id}.jsonl"
    parsed = read_trusted_segment(path, installation_id=INSTALLATION_ID)
    return [frame.record.record_id for frame in parsed.frames]


# --- (a) happy path -----------------------------------------------------------------------------


def test_happy_path_commits_then_advances_cursor_and_writes_ack(tmp_path: Path) -> None:
    directory = _milhouse_dir(tmp_path)
    outbox = directory / _OUTBOX_NAME
    body = _frame_line(kind="deploy.completed", data={"count": 3}) + _frame_line(
        kind="deploy.started", data={"count": 1}
    )
    outbox.write_bytes(body)

    database, barrier, spool_root = build_control(tmp_path)
    try:
        pipeline = make_pipeline(
            mode="spool_only",
            registry=_registry(outbox, directory),
            control=database,
            barrier=barrier,
            spool_root=spool_root,
            clock=FixedClock(instant=NOW),
        )
        summary = pipeline.run([_outbox_config()], [target_config(_TARGET_ID)])

        assert summary.records_committed == 2
        item = summary.collectors[0]
        assert item.status == "ok"
        assert item.error_code is None
        assert item.batch_id is not None

        # The cursor advanced exactly once against the committed segment, past the whole file.
        cursor = read_cursor(database, source=_COLLECTOR_ID)
        assert cursor is not None
        assert cursor.revision == 1
        assert cursor.batch_id == item.batch_id
        position = json.loads(cursor.position)
        assert position["offset"] == len(body)

        # The ack Milhouse owns records the committed file identity and offset.
        ack = read_outbox_ack(directory, _ACK_NAME)
        assert ack is not None
        assert ack.committed_offset == len(body)
        assert ack.last_sequence is None  # no rotation seen
        assert ack.producer_id == _COLLECTOR_ID

        # The committed records mirror the frames (kind->category, actionability->status).
        path = spool_root / "pending" / _DAY / f"{item.batch_id}.jsonl"
        records = [
            frame.record
            for frame in read_trusted_segment(path, installation_id=INSTALLATION_ID).frames
        ]
        assert [r.record_type for r in records] == ["event", "event"]
        assert {r.data.category for r in records} == {"deploy.completed", "deploy.started"}
        assert all(r.data.status == "observe" for r in records)
        assert {dict(r.data.attributes)["count"] for r in records} == {3, 1}
    finally:
        database.close()


# --- (a) idempotency / no-dup -------------------------------------------------------------------


def test_rerun_over_unchanged_file_commits_nothing_then_only_the_new_frame(
    tmp_path: Path,
) -> None:
    directory = _milhouse_dir(tmp_path)
    outbox = directory / _OUTBOX_NAME
    outbox.write_bytes(_frame_line(kind="deploy.completed"))

    database, barrier, spool_root = build_control(tmp_path)
    try:
        pipeline = make_pipeline(
            mode="spool_only",
            registry=_registry(outbox, directory),
            control=database,
            barrier=barrier,
            spool_root=spool_root,
            clock=FixedClock(instant=NOW),
        )
        config = [_outbox_config()]
        targets = [target_config(_TARGET_ID)]

        first = pipeline.run(config, targets)
        assert first.records_committed == 1
        cursor_after_first = read_cursor(database, source=_COLLECTOR_ID)
        assert cursor_after_first is not None and cursor_after_first.revision == 1

        # Second run over the byte-identical file: NOTHING new, cursor unchanged (no advance).
        second = pipeline.run(config, targets)
        assert second.records_committed == 0
        assert second.collectors[0].status == "ok"
        cursor_after_second = read_cursor(database, source=_COLLECTOR_ID)
        assert cursor_after_second == cursor_after_first  # revision + position identical

        # Append ONE frame: only the new frame becomes a record; the cursor advances once more.
        with outbox.open("ab") as handle:
            handle.write(_frame_line(kind="deploy.rolled_back"))
        third = pipeline.run(config, targets)
        assert third.records_committed == 1
        item = third.collectors[0]
        records = [
            frame.record
            for frame in read_trusted_segment(
                spool_root / "pending" / _DAY / f"{item.batch_id}.jsonl",
                installation_id=INSTALLATION_ID,
            ).frames
        ]
        assert [r.data.category for r in records] == ["deploy.rolled_back"]
        cursor_after_third = read_cursor(database, source=_COLLECTOR_ID)
        assert cursor_after_third is not None and cursor_after_third.revision == 2
    finally:
        database.close()


# --- (b) commit-before-advance replay (the load-bearing test) -----------------------------------


def test_replay_before_advance_reproduces_identical_record_ids(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    directory = _milhouse_dir(tmp_path)
    outbox = directory / _OUTBOX_NAME
    outbox.write_bytes(_frame_line(kind="deploy.completed", data={"count": 7}))

    database, barrier, spool_root = build_control(tmp_path)
    try:
        config = [_outbox_config()]
        targets = [target_config(_TARGET_ID)]

        # Run 1 CRASHES between commit and advance: the segment commits durably, but advance_cursor
        # raises so the cursor + ack are NEVER written (isolated -> the run continues).
        import milhouse.runtime.pipeline as pipeline_module
        from milhouse.state import StateError

        def _boom(*args: object, **kwargs: object) -> None:
            raise StateError("MH_STATE_CURSOR", "simulated crash before advance")

        monkeypatch.setattr(pipeline_module, "advance_cursor", _boom)
        crashed = make_pipeline(
            mode="spool_only",
            registry=_registry(outbox, directory),
            control=database,
            barrier=barrier,
            spool_root=spool_root,
            clock=FixedClock(instant=NOW),
        ).run(config, targets)
        first_item = crashed.collectors[0]
        assert first_item.records_committed == 1  # committed despite the advance failure
        assert first_item.error_code == "MH_STATE_CURSOR"
        assert read_cursor(database, source=_COLLECTOR_ID) is None  # never advanced
        first_ids = _record_ids(spool_root, first_item.batch_id or "")
        monkeypatch.undo()

        # Run 2 replays with a LATER clock (a real re-run): the cursor is still unadvanced, so the
        # SAME frame is re-read and re-committed under a DISTINCT batch_id -- but the record_id is
        # derived from the frame bytes, so it is IDENTICAL. Downstream dedup collapses it.
        replay = make_pipeline(
            mode="spool_only",
            registry=_registry(outbox, directory),
            control=database,
            barrier=barrier,
            spool_root=spool_root,
            clock=FixedClock(instant=NOW + timedelta(hours=1)),
        ).run(config, targets)
        second_item = replay.collectors[0]
        assert second_item.records_committed == 1
        assert second_item.error_code is None
        second_ids = _record_ids(spool_root, second_item.batch_id or "")

        assert second_item.batch_id != first_item.batch_id  # a genuinely distinct replay segment
        assert first_ids == second_ids  # ... yet identical record identity -> dedup collapses it

        # The replay's advance DID land this time.
        cursor = read_cursor(database, source=_COLLECTOR_ID)
        assert cursor is not None and cursor.revision == 1
    finally:
        database.close()


# --- (c) loss short-circuits --------------------------------------------------------------------


def test_data_loss_commits_nothing_and_leaves_the_cursor_unchanged(tmp_path: Path) -> None:
    directory = _milhouse_dir(tmp_path)
    outbox = directory / _OUTBOX_NAME
    outbox.write_bytes(_frame_line(kind="deploy.completed") + _frame_line(kind="deploy.started"))

    database, barrier, spool_root = build_control(tmp_path)
    try:
        registry = _registry(outbox, directory)
        config = [_outbox_config()]
        targets = [target_config(_TARGET_ID)]

        first = make_pipeline(
            mode="spool_only",
            registry=registry,
            control=database,
            barrier=barrier,
            spool_root=spool_root,
            clock=FixedClock(instant=NOW),
        ).run(config, targets)
        assert first.records_committed == 2
        cursor_before = read_cursor(database, source=_COLLECTOR_ID)
        assert cursor_before is not None

        segments_before = list((spool_root / "pending" / _DAY).glob("*.jsonl"))

        # Truncate already-consumed bytes IN PLACE (same inode) below the cursor offset: an
        # un-recoverable P1 data loss the reader must refuse to resume past.
        with outbox.open("r+b") as handle:
            handle.truncate(10)

        lost = make_pipeline(
            mode="spool_only",
            registry=registry,
            control=database,
            barrier=barrier,
            spool_root=spool_root,
            clock=FixedClock(instant=NOW + timedelta(hours=1)),
        ).run(config, targets)
        item = lost.collectors[0]
        assert item.status == "failed"
        assert item.error_code == "MH_OUTBOX_LOSS_TRUNCATED"
        assert item.records_committed == 0
        # Nothing committed and nothing advanced: the cursor is byte-for-byte what it was.
        assert read_cursor(database, source=_COLLECTOR_ID) == cursor_before
        assert list((spool_root / "pending" / _DAY).glob("*.jsonl")) == segments_before
    finally:
        database.close()


# --- generic opt-in: a non-cursor collector never touches a cursor or ack -----------------------


def test_non_cursor_collector_leaves_no_cursor_or_ack(tmp_path: Path) -> None:
    directory = _milhouse_dir(tmp_path)
    database, barrier, spool_root = build_control(tmp_path)
    try:
        descriptor = CollectorDescriptorV1(
            id="canary1", type="site.canary", implementation_version="1.0.0"
        )

        def factory(config: object) -> FakeCollector:
            return FakeCollector(descriptor=descriptor, messages=("probe ok",))

        pipeline = make_pipeline(
            mode="spool_only",
            registry=registry_with("site_canary", factory),
            control=database,
            barrier=barrier,
            spool_root=spool_root,
            clock=FixedClock(instant=NOW),
        )
        from _runtime_harness import canary_config

        summary = pipeline.run([canary_config("canary1")], [target_config(_TARGET_ID)])
        assert summary.records_committed == 1  # the collector still commits its event
        assert summary.collectors[0].error_code is None
        # ... but no cursor advanced and no ack was written for a non-cursor collector.
        assert read_cursor(database, source="canary1") is None
        assert not (directory / _ACK_NAME).exists()
    finally:
        database.close()


# --- post-commit advance-failure isolation ------------------------------------------------------


def test_advance_failure_does_not_unwind_the_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    directory = _milhouse_dir(tmp_path)
    outbox = directory / _OUTBOX_NAME
    outbox.write_bytes(_frame_line(kind="deploy.completed"))

    database, barrier, spool_root = build_control(tmp_path)
    try:
        import milhouse.runtime.pipeline as pipeline_module
        from milhouse.state import StateError

        def _boom(*args: object, **kwargs: object) -> None:
            raise StateError("MH_STATE_CURSOR_CONFLICT", "simulated concurrent advance")

        monkeypatch.setattr(pipeline_module, "advance_cursor", _boom)
        summary = make_pipeline(
            mode="spool_only",
            registry=_registry(outbox, directory),
            control=database,
            barrier=barrier,
            spool_root=spool_root,
            clock=FixedClock(instant=NOW),
        ).run([_outbox_config()], [target_config(_TARGET_ID)])

        item = summary.collectors[0]
        # The commit is durable (records committed, segment readable) even though advance failed.
        assert item.records_committed == 1
        assert item.batch_id is not None
        assert item.error_code == "MH_STATE_CURSOR_CONFLICT"
        path = spool_root / "pending" / _DAY / f"{item.batch_id}.jsonl"
        assert len(read_trusted_segment(path, installation_id=INSTALLATION_ID).frames) == 1
        # The cursor stayed un-advanced AND no ack was written (advance failed before the ack).
        assert read_cursor(database, source=_COLLECTOR_ID) is None
        assert not (directory / _ACK_NAME).exists()
    finally:
        database.close()


# --- FIX 1 (P1): a first run (cursor None) ingests retained rotations, not just the active file ---


def test_first_run_ingests_retained_rotations_when_cursor_is_none(tmp_path: Path) -> None:
    directory = _milhouse_dir(tmp_path)
    outbox = directory / _OUTBOX_NAME
    # A rotated file already exists BEFORE Milhouse's first successful read (cursor still None): run
    # 1 saw an empty/all-rejected outbox and the producer rotated before run 2.
    (directory / "feedback-outbox.00000001.jsonl").write_bytes(_frame_line(kind="deploy.older"))
    outbox.write_bytes(_frame_line(kind="deploy.newer"))

    database, barrier, spool_root = build_control(tmp_path)
    try:
        config = [_outbox_config(rotation_glob="feedback-outbox.*.jsonl")]
        summary = make_pipeline(
            mode="spool_only",
            registry=_registry(outbox, directory),
            control=database,
            barrier=barrier,
            spool_root=spool_root,
            clock=FixedClock(instant=NOW),
        ).run(config, [target_config(_TARGET_ID)])

        # BOTH the retained rotated frame and the active frame are ingested, in order.
        assert summary.records_committed == 2
        item = summary.collectors[0]
        assert item.error_code is None
        records = [
            frame.record
            for frame in read_trusted_segment(
                spool_root / "pending" / _DAY / f"{item.batch_id}.jsonl",
                installation_id=INSTALLATION_ID,
            ).frames
        ]
        assert [r.data.category for r in records] == ["deploy.older", "deploy.newer"]
        cursor = read_cursor(database, source=_COLLECTOR_ID)
        assert cursor is not None and cursor.revision == 1
        # The rotation high-water is persisted in the ack for later top-run detection.
        ack = read_outbox_ack(directory, _ACK_NAME)
        assert ack is not None and ack.last_sequence == 1
    finally:
        database.close()


# --- FIX 2 (P2): distinct byte-identical frames get distinct record ids (byte-offset fallback) ----


def test_distinct_byte_identical_frames_get_distinct_record_ids(tmp_path: Path) -> None:
    directory = _milhouse_dir(tmp_path)
    outbox = directory / _OUTBOX_NAME
    # Two BYTE-IDENTICAL frames (same producer, same-millisecond occurred_at, same kind + data): a
    # content-ONLY identity would derive one record_id and ReplacingMergeTree would collapse them,
    # losing an observation. The per-file byte offset in the coordinate keeps them distinct.
    line = _frame_line(kind="deploy.completed", data={"count": 1})
    outbox.write_bytes(line + line)

    database, barrier, spool_root = build_control(tmp_path)
    try:
        summary = make_pipeline(
            mode="spool_only",
            registry=_registry(outbox, directory),
            control=database,
            barrier=barrier,
            spool_root=spool_root,
            clock=FixedClock(instant=NOW),
        ).run([_outbox_config()], [target_config(_TARGET_ID)])

        assert summary.records_committed == 2
        ids = _record_ids(spool_root, summary.collectors[0].batch_id or "")
        assert len(ids) == 2
        assert len(set(ids)) == 2  # two DISTINCT record ids -> neither observation is merged away
    finally:
        database.close()


# --- FIX 3 (P2 privacy): untrusted producer attributes are redacted before durable commit ---------


def test_producer_attributes_are_redacted_in_the_committed_record(tmp_path: Path) -> None:
    directory = _milhouse_dir(tmp_path)
    outbox = directory / _OUTBOX_NAME
    outbox.write_bytes(
        _frame_line(
            kind="deploy.completed",
            data={
                "note": f"leaked {KNOWN_SECRET} here",
                "contact": "oncall@secret.example",
                "log": "/var/log/deploy/private/token.txt",
                "count": 5,
            },
        )
    )

    database, barrier, spool_root = build_control(tmp_path)
    try:
        summary = make_pipeline(
            mode="spool_only",
            registry=_registry(outbox, directory),
            control=database,
            barrier=barrier,
            spool_root=spool_root,
            clock=FixedClock(instant=NOW),
        ).run([_outbox_config()], [target_config(_TARGET_ID)])

        assert summary.records_committed == 1
        item = summary.collectors[0]
        record = (
            read_trusted_segment(
                spool_root / "pending" / _DAY / f"{item.batch_id}.jsonl",
                installation_id=INSTALLATION_ID,
            )
            .frames[0]
            .record
        )
        attributes = dict(record.data.attributes)
        # The pipeline's defense-in-depth pass does NOT scan structured attributes, so ONLY the
        # collector's redaction can have produced these markers -- proving FIX 3 is wired.
        assert KNOWN_SECRET not in attributes["note"]
        assert SECRET_MARKER in attributes["note"]
        # A producer email and a filesystem path in structured attributes are redacted too.
        assert "oncall@secret.example" not in attributes["contact"]
        assert "secret.example" not in attributes["contact"]
        assert "/var/log/deploy/private" not in attributes["log"]
        # A non-string scalar passes through unchanged.
        assert attributes["count"] == 5
    finally:
        database.close()


# --- P2: redaction expansion must NOT poison-stall the outbox (clamp to the dimension bound) ---


def test_redaction_expansion_is_clamped_and_does_not_stall(tmp_path: Path) -> None:
    directory = _milhouse_dir(tmp_path)
    outbox = directory / _OUTBOX_NAME
    # A value that PARSES within the dimension bound (<= 2048 bytes) but whose redacted form EXPANDS
    # past it: many short emails, each redacting to a ~40-byte marker. Without the clamp,
    # EventDataV1.attributes would raise -> the frame never commits -> the cursor never advances ->
    # the identical frame re-fails forever (a permanent outbox stall / denial-of-ingestion).
    packed = "user@host.example " * 100  # ~1800 bytes raw (<= 2048), ~5000 bytes once redacted
    assert len(packed.encode("utf-8")) <= MAX_DIMENSION_VALUE_BYTES
    outbox.write_bytes(_frame_line(kind="deploy.completed", data={"blob": packed}))

    database, barrier, spool_root = build_control(tmp_path)
    try:
        registry = _registry(outbox, directory)
        config = [_outbox_config()]
        targets = [target_config(_TARGET_ID)]

        first = make_pipeline(
            mode="spool_only",
            registry=registry,
            control=database,
            barrier=barrier,
            spool_root=spool_root,
            clock=FixedClock(instant=NOW),
        ).run(config, targets)

        # The frame COMMITS (no stall) and the cursor ADVANCES.
        assert first.records_committed == 1
        item = first.collectors[0]
        assert item.error_code is None
        cursor = read_cursor(database, source=_COLLECTOR_ID)
        assert cursor is not None and cursor.revision == 1

        record = (
            read_trusted_segment(
                spool_root / "pending" / _DAY / f"{item.batch_id}.jsonl",
                installation_id=INSTALLATION_ID,
            )
            .frames[0]
            .record
        )
        blob = dict(record.data.attributes)["blob"]
        assert isinstance(blob, str)
        # Clamped within the dimension bound, still redacted (no raw email), and marked as clamped.
        assert len(blob.encode("utf-8")) <= MAX_DIMENSION_VALUE_BYTES
        assert "user@host.example" not in blob
        assert blob.endswith("[mh:clamp]")

        # No stall: a second run over the unchanged file commits nothing and the cursor is unmoved.
        second = make_pipeline(
            mode="spool_only",
            registry=registry,
            control=database,
            barrier=barrier,
            spool_root=spool_root,
            clock=FixedClock(instant=NOW + timedelta(hours=1)),
        ).run(config, targets)
        assert second.records_committed == 0
        assert read_cursor(database, source=_COLLECTOR_ID) == cursor
    finally:
        database.close()


# --- P3: cross-path replay-offset equality (_read_same_file == _recover_rotation offset) ---


def test_replay_across_rotation_matches_offset_from_same_file_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    directory = _milhouse_dir(tmp_path)
    outbox = directory / _OUTBOX_NAME
    line_a = _frame_line(kind="deploy.a")
    outbox.write_bytes(line_a)

    database, barrier, spool_root = build_control(tmp_path)
    try:
        config = [_outbox_config(rotation_glob="feedback-outbox.*.jsonl")]
        targets = [target_config(_TARGET_ID)]

        def _pipeline(instant: object) -> object:
            return make_pipeline(
                mode="spool_only",
                registry=_registry(outbox, directory),
                control=database,
                barrier=barrier,
                spool_root=spool_root,
                clock=FixedClock(instant=instant),  # type: ignore[arg-type]
            )

        # Run 1: commit frame A (offset 0) and advance -> the cursor now sits at offset len(line_a).
        _pipeline(NOW).run(config, targets)
        assert read_cursor(database, source=_COLLECTOR_ID).revision == 1  # type: ignore[union-attr]

        # Run 2: append B (at offset len(line_a)); it is read via _read_same_file
        # (base_offset=start=len(line_a)) and committed, but a crash before advance keeps cursor.
        with outbox.open("ab") as handle:
            handle.write(_frame_line(kind="deploy.b"))
        import milhouse.runtime.pipeline as pipeline_module
        from milhouse.state import StateError

        def _boom(*args: object, **kwargs: object) -> None:
            raise StateError("MH_STATE_CURSOR", "crash before advance")

        monkeypatch.setattr(pipeline_module, "advance_cursor", _boom)
        crashed = _pipeline(NOW).run(config, targets)
        b_id_same_file = _record_ids(spool_root, crashed.collectors[0].batch_id or "")[0]
        assert read_cursor(database, source=_COLLECTOR_ID).revision == 1  # type: ignore[union-attr]
        monkeypatch.undo()

        # Rotate the file the cursor points into (A+B) and start a fresh active file. Now the
        # cursor's inode differs from the active inode, so run 3 re-reads B via _recover_rotation's
        # cursor-file region with base_offset=prior.offset=len(line_a) -- the SAME absolute per-file
        # offset as the _read_same_file path in run 2. If both paths agree, the id is identical.
        os.rename(outbox, directory / "feedback-outbox.00000001.jsonl")
        outbox.write_bytes(b"")

        replay = _pipeline(NOW + timedelta(hours=1)).run(config, targets)
        item = replay.collectors[0]
        assert item.records_committed == 1  # only B is re-read (A is before the cursor)
        b_id_rotation = _record_ids(spool_root, item.batch_id or "")[0]

        assert b_id_rotation == b_id_same_file  # cross-path offsets agree -> identical identity
        assert read_cursor(database, source=_COLLECTOR_ID).revision == 2  # type: ignore[union-attr]
    finally:
        database.close()
