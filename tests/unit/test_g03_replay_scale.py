"""G03 scale proof: replaying 10,000 records twice yields identical logical IDs and counts.

This exercises the deterministic, idempotent replay path at the gate-mandated scale — the largest
prior replay test used three records — so drift, reordering, or nondeterminism in record identity
would surface here.
"""

from __future__ import annotations

import os
from pathlib import Path

from _g03_harness import INSTALLATION_ID, NOW, NoopExporter, build_spool, commit_segment

from milhouse.spooling import replay_segments

# The G03 gate mandates 10,000; the count is overridable only to shrink the run for fast local
# iteration (CI leaves it at the gate-literal default).
# Few, large segments: mandatory reconciliation on each commit re-scans all prior pending segments,
# which is O(segments^2), so a handful of large segments keeps the 10,000-record commit tractable
# while still proving cross-segment replay ordering (fine-grained multi-segment ordering is covered
# by test_spool_replay.py).
_TOTAL = int(os.environ.get("MILHOUSE_G03_SCALE_RECORDS", "10000"))
_PER_SEGMENT = 5000


def test_replaying_10000_records_twice_yields_identical_ids_and_counts(tmp_path: Path) -> None:
    database, barrier, spool_root, store = build_spool(tmp_path)
    try:
        expected_ids: list[str] = []
        emitted = 0
        segment = 0
        while emitted < _TOTAL:
            count = min(_PER_SEGMENT, _TOTAL - emitted)
            event_ids = [f"e{emitted + i:05d}" for i in range(count)]
            _record, frames = commit_segment(store, f"batch-{segment:04d}", event_ids)
            expected_ids.extend(str(frame.record.record_id) for frame in frames)
            emitted += count
            segment += 1

        exporters = {"clickhouse": NoopExporter()}
        first = replay_segments(
            database,
            barrier,
            spool_root=spool_root,
            installation_id=INSTALLATION_ID,
            exporters=exporters,
            now=NOW,
        )
        second = replay_segments(
            database,
            barrier,
            spool_root=spool_root,
            installation_id=INSTALLATION_ID,
            exporters=exporters,
            now=NOW,
        )

        assert first.record_count == _TOTAL
        assert len(set(first.record_ids)) == _TOTAL  # every logical id is distinct
        assert list(first.record_ids) == expected_ids  # deterministic order and identity
        assert list(second.record_ids) == list(first.record_ids)  # identical across the two passes
        # Idempotent delivery: the first pass delivers, the second re-emits the same ids without
        # re-delivering (the exporter compare-and-set makes an already-delivered segment a no-op).
        assert {a.outcome for a in second.delivery_attempts} == {"already_delivered"}
    finally:
        database.close()
