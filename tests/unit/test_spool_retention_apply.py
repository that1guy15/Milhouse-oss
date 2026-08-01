"""Behavioural + crash guarantees for destructive retention apply (W03 slice 5b part 2).

retention_apply prunes fully-expired committed segments under exclusive maintenance authority with a
confirm token. It re-verifies each segment under the lock, prunes row-first (ledger row + audit +
a retirement tombstone in one transaction, then the durable file), leaves
mixed/live/unreadable/disagreeing segments alone, and converges after an interrupted prune: a
leftover orphan file plus its tombstone is FINISHED by mandatory reconciliation (unlinked and the
tombstone cleared) within one acquisition cycle, never re-adopted as a live segment (finding #1).
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from milhouse.config.filesystem import SecureFileError, SecureFileErrorKind
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
    SpoolFrameV1,
    deliver_segment,
    retention_apply,
    spool_content_sha256,
    spool_frame_line,
)
from milhouse.spooling import reconcile as reconcile_module
from milhouse.spooling import retention as retention_module
from milhouse.spooling.errors import SpoolError
from milhouse.state import (
    GlobalCommitBarrier,
    advance_cursor,
    initialize_control_state,
    list_audit,
    open_control_database,
    read_cursor,
)

_INSTALLATION_ID = "mh_in1_00000000000040008000000000000000"
_NOW = datetime(2026, 7, 28, 12, 0, 0, tzinfo=UTC)
_DAY = "2026-07-28"
_STAMP = "2026-07-28T12:00:00.000Z"
_GENERATION = "a" * 64
_EXPIRED_AT = _NOW + timedelta(hours=1)
_LIVE_AT = _NOW + timedelta(days=30)
_APPLY_NOW = _NOW + timedelta(days=1)


class _FakeExporter:
    def __init__(self, exporter_id: str) -> None:
        self._exporter_id = exporter_id

    @property
    def exporter_id(self) -> str:
        return self._exporter_id

    def deliver(self, record, frames) -> None:
        return None


def _envelope(source_event_id: str, expires_at: datetime) -> RecordEnvelopeV1:
    values: dict[str, object] = {
        "record_type": "event",
        "name": "source.event",
        "occurred_at": _NOW,
        "observed_at": _NOW + timedelta(seconds=1),
        "ingested_at": _NOW + timedelta(seconds=2),
        "expires_at": expires_at,
        "source_event_id": source_event_id,
        "operation_id": "operation-1",
        "collector_run_id": "collector-run-1",
        "scope": "target",
        "source": SourceDescriptorV1.model_validate(
            {
                "id": "example-source",
                "type": "source.event",
                "producer": "collector",
                "observation_namespace_id": "mh_ns1_00000000000040008000000000000000",
                "source_generation_digest": "0" * 64,
                "observation": {"kind": "source.revision", "parts": {"revision": 1}},
            }
        ),
        "collector": CollectorDescriptorV1(
            id="c", type="site.canary", implementation_version="1.0.0"
        ),
        "target": TargetDescriptorV1(
            id="example-target", name="E", kind="web.service", environment="test"
        ),
        "severity": "info",
        "trust_level": "authenticated",
        "privacy_class": "internal",
        "redaction_version": "r1-e1",
        "data": EventDataV1(category="availability", status="healthy", message="ok"),
    }
    return finalize_record(RecordDraftV1.model_validate(values), installation_id=_INSTALLATION_ID)


def _frames(batch_id: str, specs: list[tuple[str, datetime]]) -> list[SpoolFrameV1]:
    return [
        SpoolFrameV1(batch_id=batch_id, sequence=index, record=_envelope(event_id, expires_at))
        for index, (event_id, expires_at) in enumerate(specs, start=1)
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
        required_exporters=("clickhouse",),
        record_count=len(frames),
        content_sha256=spool_content_sha256(lines),
    )


def _spool(tmp_path: Path):
    control = tmp_path / "control"
    control.mkdir(mode=0o700)
    os.chmod(control, 0o700)
    database = open_control_database(control / "milhouse.sqlite3")
    barrier = GlobalCommitBarrier(control / "commit.lock")
    initialize_control_state(database, barrier=barrier, applied_at=_NOW)
    spool_root = tmp_path / "spool"
    spool_root.mkdir(mode=0o700)
    os.chmod(spool_root, 0o700)
    store = DurableSpool(
        database=database, barrier=barrier, spool_root=spool_root, installation_id=_INSTALLATION_ID
    )
    return database, barrier, spool_root, store


def _commit(store, batch_id: str, specs: list[tuple[str, datetime]]):
    frames = _frames(batch_id, specs)
    return store.commit_segment(_header(batch_id, frames), frames, committed_at=_NOW), frames


def _segment_file(spool_root: Path, batch_id: str) -> Path:
    return spool_root / "pending" / _DAY / f"{batch_id}.jsonl"


def _segment_rows(database) -> set[str]:
    return {
        row[0] for row in database.connection.execute("SELECT batch_id FROM _segments").fetchall()
    }


def _retirements(database) -> set[str]:
    return {
        row[0]
        for row in database.connection.execute("SELECT batch_id FROM _retirements").fetchall()
    }


def _reconcile(database, barrier, spool_root):
    # A fresh writer acquisition runs mandatory reconciliation; return its report.
    return DurableSpool(
        database=database, barrier=barrier, spool_root=spool_root, installation_id=_INSTALLATION_ID
    ).last_reconciliation


def _insert_tombstone(database, batch_id: str, file_sha256: str) -> None:
    with database.transaction() as connection:
        connection.execute(
            "INSERT INTO _retirements (batch_id, day, file_sha256, retired_at) VALUES (?, ?, ?, ?)",
            (batch_id, _DAY, file_sha256, _STAMP),
        )


def _apply(database, barrier, spool_root, *, now=_APPLY_NOW, confirm=True):
    return retention_apply(
        database,
        barrier,
        spool_root=spool_root,
        installation_id=_INSTALLATION_ID,
        now=now,
        confirm=confirm,
    )


def test_confirm_is_required(tmp_path: Path) -> None:
    database, barrier, spool_root, store = _spool(tmp_path)
    try:
        _commit(store, "batch-a", [("a1", _EXPIRED_AT)])
        with pytest.raises(SpoolError) as captured:
            _apply(database, barrier, spool_root, confirm=False)
        assert captured.value.code == "MH_SPOOL_RETENTION"
        assert _segment_rows(database) == {"batch-a"}  # nothing pruned
        assert _segment_file(spool_root, "batch-a").exists()
    finally:
        database.close()


def test_prunes_a_fully_expired_delivered_segment(tmp_path: Path) -> None:
    database, barrier, spool_root, store = _spool(tmp_path)
    try:
        record, frames = _commit(store, "batch-a", [("a1", _EXPIRED_AT), ("a2", _EXPIRED_AT)])
        deliver_segment(
            database, barrier, record, frames, {"clickhouse": _FakeExporter("clickhouse")}, now=_NOW
        )
        result = _apply(database, barrier, spool_root)
        assert [p.batch_id for p in result.pruned] == ["batch-a"]
        assert result.pruned_records == 2
        assert result.pruned_bytes == record.byte_size
        assert result.pruned[0].file_outcome == "removed"
        assert result.pruned[0].delivered is True
        assert _segment_rows(database) == set()  # ledger row gone
        assert not _segment_file(spool_root, "batch-a").exists()  # file gone
        exporter_rows = database.connection.execute(
            "SELECT count(*) FROM _segment_exporters WHERE batch_id = 'batch-a'"
        ).fetchone()[0]
        assert exporter_rows == 0
        audit = list_audit(database)
        assert len(audit) == 1
        assert (audit[0].action, audit[0].outcome, audit[0].resource) == (
            "retention_prune",
            "pruned",
            None,  # no keyed pseudonymizer wired → identifier omitted (PR #69 review)
        )
        assert (audit[0].record_count, audit[0].byte_size) == (2, record.byte_size)
    finally:
        database.close()


def test_prunes_an_undelivered_expired_segment_as_a_critical_event(tmp_path: Path) -> None:
    database, barrier, spool_root, store = _spool(tmp_path)
    try:
        _commit(store, "batch-a", [("a1", _EXPIRED_AT)])  # never delivered
        result = _apply(database, barrier, spool_root)
        assert [p.batch_id for p in result.pruned] == ["batch-a"]
        assert result.pruned[0].delivered is False
        assert [p.batch_id for p in result.undelivered_pruned] == ["batch-a"]
        audit = list_audit(database)
        assert audit[0].outcome == "pruned_undelivered"  # the critical case
        assert audit[0].reason == "expired_undelivered"
    finally:
        database.close()


def test_leaves_live_and_mixed_segments(tmp_path: Path) -> None:
    database, barrier, spool_root, store = _spool(tmp_path)
    try:
        _commit(store, "batch-expired", [("e1", _EXPIRED_AT)])
        _commit(store, "batch-mixed", [("m1", _EXPIRED_AT), ("m2", _LIVE_AT)])
        _commit(store, "batch-live", [("l1", _LIVE_AT)])
        result = _apply(database, barrier, spool_root)
        assert [p.batch_id for p in result.pruned] == ["batch-expired"]
        skipped = {s.batch_id: s.status for s in result.skipped}
        assert skipped == {"batch-mixed": "mixed", "batch-live": "live"}
        # The non-expired segments and their files survive.
        assert _segment_rows(database) == {"batch-mixed", "batch-live"}
        assert _segment_file(spool_root, "batch-mixed").exists()
        assert _segment_file(spool_root, "batch-live").exists()
    finally:
        database.close()


def test_skips_an_unreadable_segment(tmp_path: Path) -> None:
    database, barrier, spool_root, store = _spool(tmp_path)
    try:
        _commit(store, "batch-a", [("a1", _EXPIRED_AT)])
        _segment_file(spool_root, "batch-a").unlink()  # the file is gone before apply
        result = _apply(database, barrier, spool_root)
        assert result.pruned == ()
        assert [s.status for s in result.skipped] == ["unreadable"]
        assert result.skipped[0].code == "MH_SPOOL_NOT_FOUND"
        assert _segment_rows(database) == {"batch-a"}  # the ledger row is NOT pruned blind
    finally:
        database.close()


def test_skips_a_ledger_disagreeing_segment(tmp_path: Path) -> None:
    database, barrier, spool_root, store = _spool(tmp_path)
    try:
        _commit(store, "batch-a", [("a1", _EXPIRED_AT)])
        # Corrupt the ledger's recorded count so the durable file no longer agrees with its row.
        with database.transaction() as connection:
            connection.execute("UPDATE _segments SET record_count = 99 WHERE batch_id = 'batch-a'")
        result = _apply(database, barrier, spool_root)
        assert result.pruned == ()
        assert [s.status for s in result.skipped] == ["disagreeing"]
        assert _segment_file(spool_root, "batch-a").exists()  # never pruned on disagreement
    finally:
        database.close()


def test_rerun_is_idempotent(tmp_path: Path) -> None:
    database, barrier, spool_root, store = _spool(tmp_path)
    try:
        _commit(store, "batch-a", [("a1", _EXPIRED_AT)])
        first = _apply(database, barrier, spool_root)
        assert len(first.pruned) == 1
        second = _apply(database, barrier, spool_root)
        assert second.pruned == ()  # nothing left to prune
        assert second.skipped == ()
    finally:
        database.close()


def test_rejects_an_unbound_or_invalid_barrier(tmp_path: Path) -> None:
    database, _barrier, spool_root, store = _spool(tmp_path)
    try:
        _commit(store, "batch-a", [("a1", _EXPIRED_AT)])
        foreign = GlobalCommitBarrier(tmp_path / "unrelated.lock")
        with pytest.raises(SpoolError) as unbound:
            _apply(database, foreign, spool_root)
        assert unbound.value.code == "MH_SPOOL_RETENTION"
        with pytest.raises(SpoolError) as bad_type:
            retention_apply(
                database,
                object(),  # type: ignore[arg-type]
                spool_root=spool_root,
                installation_id=_INSTALLATION_ID,
                now=_APPLY_NOW,
                confirm=True,
            )
        assert bad_type.value.code == "MH_SPOOL_RETENTION"
        assert _segment_rows(database) == {"batch-a"}  # nothing pruned under a bad barrier
    finally:
        database.close()


def test_rejects_a_spool_root_not_bound_to_the_state_root(tmp_path: Path) -> None:
    database, barrier, _spool_root, _store = _spool(tmp_path)
    try:
        with pytest.raises(SpoolError) as captured:
            retention_apply(
                database,
                barrier,
                spool_root=tmp_path / "wrong-spool",  # not <state_root>/spool
                installation_id=_INSTALLATION_ID,
                now=_APPLY_NOW,
                confirm=True,
            )
        assert captured.value.code == "MH_SPOOL_RETENTION"
    finally:
        database.close()


class _HostilePath:
    """A path-like whose __fspath__ raises — an unresolvable spool root."""

    def __fspath__(self) -> str:
        raise ValueError("hostile fspath")


def test_rejects_a_malformed_spool_root_path(tmp_path: Path) -> None:
    database, barrier, _spool_root, _store = _spool(tmp_path)
    try:
        with pytest.raises(SpoolError) as captured:
            retention_apply(
                database,
                barrier,
                spool_root=_HostilePath(),  # a PathLike that cannot be resolved
                installation_id=_INSTALLATION_ID,
                now=_APPLY_NOW,
                confirm=True,
            )
        assert captured.value.code == "MH_SPOOL_RETENTION"
    finally:
        database.close()


def test_rejects_a_closed_database(tmp_path: Path) -> None:
    database, barrier, spool_root, _store = _spool(tmp_path)
    database.close()
    with pytest.raises(SpoolError) as captured:
        retention_apply(
            database,
            barrier,
            spool_root=spool_root,
            installation_id=_INSTALLATION_ID,
            now=_APPLY_NOW,
            confirm=True,
        )
    assert captured.value.code == "MH_SPOOL_RETENTION"


def test_rejects_invalid_common_arguments(tmp_path: Path) -> None:
    database, barrier, spool_root, _store = _spool(tmp_path)
    try:
        with pytest.raises(SpoolError) as bad_id:
            retention_apply(
                database,
                barrier,
                spool_root=spool_root,
                installation_id="nope",
                now=_APPLY_NOW,
                confirm=True,
            )
        assert bad_id.value.code == "MH_SPOOL_IDENTITY"
        with pytest.raises(SpoolError) as bad_now:
            retention_apply(
                database,
                barrier,
                spool_root=spool_root,
                installation_id=_INSTALLATION_ID,
                now=datetime(2026, 7, 28, 12),  # naive
                confirm=True,
            )
        assert bad_now.value.code == "MH_SPOOL_RETENTION"
    finally:
        database.close()


def test_a_failed_transactional_prune_leaves_the_segment_intact(tmp_path: Path) -> None:
    database, barrier, spool_root, store = _spool(tmp_path)
    try:
        _commit(store, "batch-a", [("a1", _EXPIRED_AT)])
        # Drop the audit table so the in-transaction record_audit fails AFTER the two DELETEs.
        # Because the prune is one transaction, the DELETEs roll back and the segment stays intact
        # (row AND file) — never a half-prune.
        with database.transaction() as connection:
            connection.execute("DROP TABLE _audit")
        result = _apply(database, barrier, spool_root)
        assert result.pruned == ()
        assert [s.status for s in result.skipped] == ["fully_expired"]
        assert result.skipped[0].code == "MH_SPOOL_RETENTION"
        assert _segment_rows(database) == {"batch-a"}  # the ledger row was rolled back
        assert _segment_file(spool_root, "batch-a").exists()
    finally:
        database.close()


def test_a_crash_before_unlink_self_completes_via_reconciliation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # P1 (review finding #1): retention deletes the ledger row and writes a retirement tombstone in
    # one transaction, BEFORE unlinking the durable file. A crash between the commit and the unlink
    # leaves an orphan file, but mandatory reconciliation recognizes the tombstone and FINISHES the
    # deletion (unlink + clear tombstone) within one acquisition cycle — repeated restart alone
    # completes it, with NO separate retention pass — so the privacy-expired bytes can never be
    # re-adopted as a live segment and outlive their hard privacy deadline (the reviewer's exact
    # kill-after-commit/before-unlink reproduction).
    database, barrier, spool_root, store = _spool(tmp_path)
    try:
        _commit(store, "batch-a", [("a1", _EXPIRED_AT)])

        # Kill AFTER the ledger row + tombstone commit but BEFORE the unlink.
        def failing_remove(*args: object, **kwargs: object) -> None:
            raise SecureFileError(SecureFileErrorKind.WRITE_FAILED)

        monkeypatch.setattr(retention_module, "remove_regular_file_no_follow", failing_remove)
        first = _apply(database, barrier, spool_root)
        assert len(first.pruned) == 1
        assert first.pruned[0].file_outcome == "orphaned"  # the durable file lingers
        assert [p.batch_id for p in first.orphaned_files] == ["batch-a"]
        # Row-first: the ledger row is gone but the file remains — NOT a row-without-file — and the
        # tombstone durably records the intent to finish removing it.
        assert _segment_rows(database) == set()
        assert _segment_file(spool_root, "batch-a").exists()
        assert _retirements(database) == {"batch-a"}

        # Only normal restart/reconciliation (a fresh writer acquisition) — NO retention pass.
        monkeypatch.undo()
        DurableSpool(
            database=database,
            barrier=barrier,
            spool_root=spool_root,
            installation_id=_INSTALLATION_ID,
        )
        # The expired file and row are gone within the bound, and the segment was NOT re-adopted.
        assert _segment_rows(database) == set()  # never re-registered as a live segment
        assert not _segment_file(spool_root, "batch-a").exists()  # expired bytes removed
        assert _retirements(database) == set()  # tombstone cleared

        # A second reconciliation is a stable no-op (idempotent convergence).
        DurableSpool(
            database=database,
            barrier=barrier,
            spool_root=spool_root,
            installation_id=_INSTALLATION_ID,
        )
        assert _segment_rows(database) == set()
        assert _retirements(database) == set()
    finally:
        database.close()


def test_reconciliation_clears_a_stale_tombstone_whose_file_is_gone(tmp_path: Path) -> None:
    # The crash-after-unlink/before-tombstone-delete window: a tombstone lingers with no file.
    # Reconciliation clears it (there is nothing to unlink) — the retirement is already complete.
    database, barrier, spool_root, store = _spool(tmp_path)
    try:
        _commit(store, "batch-a", [("a1", _EXPIRED_AT)])
        _apply(database, barrier, spool_root)  # normal prune: row + file gone, tombstone cleared
        assert _retirements(database) == set()
        _insert_tombstone(database, "batch-a", "0" * 64)  # re-create the stale tombstone
        _reconcile(database, barrier, spool_root)
        assert _retirements(database) == set()  # stale tombstone with no file is cleared
    finally:
        database.close()


def test_reconciliation_clears_a_tombstone_when_the_id_was_reused(tmp_path: Path) -> None:
    # A stale tombstone whose id was reused by a now-committed segment must be cleared WITHOUT
    # touching the new segment's file (the retired file is long gone; the digest would not match).
    database, barrier, spool_root, store = _spool(tmp_path)
    try:
        _commit(store, "batch-a", [("a1", _LIVE_AT)])  # a live committed segment reusing the id
        _insert_tombstone(database, "batch-a", "0" * 64)  # stale tombstone for a prior retired file
        _reconcile(database, barrier, spool_root)
        assert _retirements(database) == set()  # stale tombstone cleared
        assert _segment_rows(database) == {"batch-a"}  # committed segment untouched
        assert _segment_file(spool_root, "batch-a").exists()
    finally:
        database.close()


def test_reconciliation_keeps_a_different_orphan_and_clears_a_mismatched_tombstone(
    tmp_path: Path,
) -> None:
    # A tombstone plus a DIFFERENT orphan file at the same name (the retired file is gone, this is a
    # reused-id orphan whose digest does not match): reconciliation clears the stale tombstone and
    # reconciles the orphan normally (registers it) rather than deleting live bytes.
    database, barrier, spool_root, store = _spool(tmp_path)
    try:
        _commit(store, "batch-a", [("a1", _LIVE_AT)])
        with database.transaction() as connection:
            connection.execute("DELETE FROM _segment_exporters WHERE batch_id = ?", ("batch-a",))
            connection.execute("DELETE FROM _segments WHERE batch_id = ?", ("batch-a",))
        _insert_tombstone(database, "batch-a", "0" * 64)  # digest does NOT match the orphan file
        _reconcile(database, barrier, spool_root)
        assert _retirements(database) == set()  # stale tombstone cleared
        assert _segment_rows(database) == {"batch-a"}  # the different orphan is registered
        assert _segment_file(spool_root, "batch-a").exists()  # its bytes are preserved
    finally:
        database.close()


def test_a_retirement_completion_unlink_failure_keeps_the_tombstone_for_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # If reconciliation's own unlink of a retired orphan fails, the tombstone is KEPT (reported as
    # retirement_incomplete) so the NEXT mandatory reconciliation retries — intent is not lost.
    database, barrier, spool_root, store = _spool(tmp_path)
    try:
        _commit(store, "batch-a", [("a1", _EXPIRED_AT)])

        def failing_remove(*args: object, **kwargs: object) -> None:
            raise SecureFileError(SecureFileErrorKind.WRITE_FAILED)

        monkeypatch.setattr(retention_module, "remove_regular_file_no_follow", failing_remove)
        _apply(database, barrier, spool_root)  # crash before unlink -> tombstone + orphan
        assert _retirements(database) == {"batch-a"}

        # Reconciliation's unlink ALSO fails: keep the tombstone and the file, report the anomaly.
        monkeypatch.setattr(reconcile_module, "remove_regular_file_no_follow", failing_remove)
        report = _reconcile(database, barrier, spool_root)
        assert _retirements(database) == {"batch-a"}  # kept for retry
        assert _segment_file(spool_root, "batch-a").exists()
        assert any(a.kind == "retirement_incomplete" for a in report.anomalies)

        # With the unlink working again, the next reconciliation completes the retirement.
        monkeypatch.undo()
        _reconcile(database, barrier, spool_root)
        assert _retirements(database) == set()
        assert not _segment_file(spool_root, "batch-a").exists()
    finally:
        database.close()


def test_a_commit_uncertain_retirement_completion_keeps_the_tombstone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A commit-uncertain unlink during reconciliation (the entry may be gone but not durably) keeps
    # the tombstone (reported ``uncertain``) so the next mandatory reconciliation reconfirms it and
    # the intent is never dropped on an unconfirmed removal.
    database, barrier, spool_root, store = _spool(tmp_path)
    try:
        _commit(store, "batch-a", [("a1", _EXPIRED_AT)])

        def write_fail(*args: object, **kwargs: object) -> None:
            raise SecureFileError(SecureFileErrorKind.WRITE_FAILED)

        monkeypatch.setattr(retention_module, "remove_regular_file_no_follow", write_fail)
        _apply(database, barrier, spool_root)  # crash before unlink -> tombstone + orphan
        monkeypatch.undo()

        def uncertain_remove(*args: object, **kwargs: object) -> None:
            raise SecureFileError(SecureFileErrorKind.COMMIT_UNCERTAIN)

        monkeypatch.setattr(reconcile_module, "remove_regular_file_no_follow", uncertain_remove)
        report = _reconcile(database, barrier, spool_root)
        assert _retirements(database) == {"batch-a"}  # kept for reconfirmation
        assert any(
            a.kind == "retirement_incomplete" and a.detail == "uncertain" for a in report.anomalies
        )
    finally:
        database.close()


def test_retirement_completion_does_not_unlink_a_file_changed_since_classification(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Defense-in-depth: if the orphan file's digest matches the tombstone at classification but has
    # CHANGED by the time reconciliation re-verifies it before unlinking (only reachable via a
    # hostile same-UID swap), the retired bytes are no longer here — reconciliation must NOT unlink
    # the now-different file; it clears the stale tombstone and leaves the file untouched.
    database, barrier, spool_root, store = _spool(tmp_path)
    try:
        _commit(store, "batch-a", [("a1", _EXPIRED_AT)])

        def failing_remove(*args: object, **kwargs: object) -> None:
            raise SecureFileError(SecureFileErrorKind.WRITE_FAILED)

        monkeypatch.setattr(retention_module, "remove_regular_file_no_follow", failing_remove)
        _apply(database, barrier, spool_root)  # crash before unlink -> tombstone + orphan
        monkeypatch.undo()

        # Match at classification (call 1), then a DIFFERENT digest at the mutation re-verify.
        real = reconcile_module._raw_sha256
        calls = {"n": 0}

        def counting(path: Path) -> str | None:
            calls["n"] += 1
            return real(path) if calls["n"] == 1 else "f" * 64

        monkeypatch.setattr(reconcile_module, "_raw_sha256", counting)
        _reconcile(database, barrier, spool_root)

        assert _retirements(database) == set()  # stale tombstone cleared
        assert _segment_file(spool_root, "batch-a").exists()  # the changed file was NOT unlinked
    finally:
        database.close()


def test_prunes_a_cursor_referenced_undelivered_expired_segment(tmp_path: Path) -> None:
    # D05: a privacy-expired segment referenced by an idle source's cursor must still be pruned; the
    # cursor is detached (batch_id -> NULL) while its resumable position/revision survive.
    database, barrier, spool_root, store = _spool(tmp_path)
    try:
        _commit(store, "batch-a", [("a1", _EXPIRED_AT)])
        advance_cursor(
            database, "github", position="page-7", batch_id="batch-a", now=_NOW, expected_revision=0
        )
        result = _apply(database, barrier, spool_root)
        assert [p.batch_id for p in result.pruned] == ["batch-a"]  # NOT skipped by the FK anymore
        assert _segment_rows(database) == set()
        assert not _segment_file(spool_root, "batch-a").exists()
        cursor = read_cursor(database, "github")
        assert cursor is not None
        assert cursor.batch_id is None  # detached
        assert (cursor.position, cursor.revision) == ("page-7", 1)  # resumable state preserved
        assert list_audit(database)[0].outcome == "pruned_undelivered"
    finally:
        database.close()


def test_prunes_a_cursor_referenced_delivered_expired_segment(tmp_path: Path) -> None:
    database, barrier, spool_root, store = _spool(tmp_path)
    try:
        record, frames = _commit(store, "batch-a", [("a1", _EXPIRED_AT)])
        deliver_segment(
            database, barrier, record, frames, {"clickhouse": _FakeExporter("clickhouse")}, now=_NOW
        )
        advance_cursor(
            database, "github", position="page-7", batch_id="batch-a", now=_NOW, expected_revision=0
        )
        result = _apply(database, barrier, spool_root)
        assert [p.batch_id for p in result.pruned] == ["batch-a"]
        assert _segment_rows(database) == set()
        cursor = read_cursor(database, "github")
        assert cursor is not None and cursor.batch_id is None
        assert (cursor.position, cursor.revision) == ("page-7", 1)
        assert list_audit(database)[0].outcome == "pruned"
    finally:
        database.close()


def test_a_detached_cursor_survives_crash_and_reconciliation_self_completion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A privacy-expired segment referenced by an idle source's cursor is detached (batch_id -> NULL,
    # position/revision preserved) at prune time. If the prune crashes before the unlink, mandatory
    # reconciliation self-completes the retirement (finding #1) and the detached cursor checkpoint
    # stays intact and resumable throughout — the segment is never re-adopted.
    database, barrier, spool_root, store = _spool(tmp_path)
    try:
        _commit(store, "batch-a", [("a1", _EXPIRED_AT)])
        advance_cursor(
            database, "github", position="page-7", batch_id="batch-a", now=_NOW, expected_revision=0
        )

        def failing_remove(*args: object, **kwargs: object) -> None:
            raise SecureFileError(SecureFileErrorKind.WRITE_FAILED)

        monkeypatch.setattr(retention_module, "remove_regular_file_no_follow", failing_remove)
        first = _apply(database, barrier, spool_root)
        assert first.pruned[0].file_outcome == "orphaned"  # orphan file lingers; ledger row gone
        assert _segment_rows(database) == set()
        assert _retirements(database) == {"batch-a"}
        detached = read_cursor(database, "github")
        assert detached is not None and detached.batch_id is None
        assert (detached.position, detached.revision) == ("page-7", 1)

        # Reconciliation FINISHES the retirement (no separate retention pass): the file and row are
        # gone, the segment is never re-registered, and the detached cursor checkpoint is preserved.
        monkeypatch.undo()
        DurableSpool(
            database=database,
            barrier=barrier,
            spool_root=spool_root,
            installation_id=_INSTALLATION_ID,
        )
        assert _segment_rows(database) == set()
        assert not _segment_file(spool_root, "batch-a").exists()
        assert _retirements(database) == set()
        final = read_cursor(database, "github")
        assert final is not None and final.batch_id is None
        assert (final.position, final.revision) == ("page-7", 1)
    finally:
        database.close()


def test_a_post_unlink_uncertainty_is_reported_as_uncertain_not_orphaned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # D05 P2: an unlink that succeeded but whose durability fsync failed is commit-uncertain, not a
    # lingering orphan; retention must report it distinctly (the reconciler re-inspects).
    database, barrier, spool_root, store = _spool(tmp_path)
    try:
        _commit(store, "batch-a", [("a1", _EXPIRED_AT)])

        def uncertain_remove(*args: object, **kwargs: object) -> None:
            raise SecureFileError(SecureFileErrorKind.COMMIT_UNCERTAIN)

        monkeypatch.setattr(retention_module, "remove_regular_file_no_follow", uncertain_remove)
        result = _apply(database, barrier, spool_root)
        assert result.pruned[0].file_outcome == "uncertain"
        assert [p.batch_id for p in result.uncertain_files] == ["batch-a"]
        assert result.orphaned_files == ()
        assert _segment_rows(database) == set()  # the ledger row is still pruned row-first
    finally:
        database.close()
