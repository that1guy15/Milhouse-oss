"""G03 concurrency proof: concurrent writers produce valid, non-interleaved segments.

Several independent writers (each with its own connection and barrier instance) commit segments at
the same time, coordinated only through the cross-process commit barrier and SQLite's busy timeout.
Every segment must land as its own atomic, internally consistent file with a distinct batch id — no
lost, duplicated, or interleaved segment.
"""

from __future__ import annotations

import threading
from pathlib import Path

from _g03_harness import (
    INSTALLATION_ID,
    build_spool,
    commit_segment,
    fresh_writer,
    segment_file,
    segment_rows,
)

from milhouse.spooling import read_trusted_segment
from milhouse.state import open_control_database

_WORKERS = 4
_PER_WORKER = 12


def test_concurrent_writers_produce_valid_noninterleaved_segments(tmp_path: Path) -> None:
    database, _barrier, spool_root, _store = build_spool(tmp_path)
    database_path = database.path
    database.close()  # each worker opens its own connection (SQLite check_same_thread)

    errors: list[BaseException] = []

    def work(worker: int) -> None:
        try:
            worker_db, _worker_barrier, store = fresh_writer(database_path, spool_root)
            try:
                for seg in range(_PER_WORKER):
                    commit_segment(
                        store,
                        f"w{worker}s{seg:02d}",
                        [f"w{worker}s{seg}r0", f"w{worker}s{seg}r1"],
                    )
            finally:
                worker_db.close()
        except BaseException as exc:
            errors.append(exc)

    threads = [threading.Thread(target=work, args=(worker,)) for worker in range(_WORKERS)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []  # every concurrent commit succeeded

    expected = {f"w{w}s{s:02d}" for w in range(_WORKERS) for s in range(_PER_WORKER)}
    verify = open_control_database(database_path)
    try:
        # Every segment committed exactly once — none lost, duplicated, or interleaved.
        assert segment_rows(verify) == expected
        # Each durable file is a valid segment whose frames belong ONLY to it.
        for batch_id in sorted(expected):
            parsed = read_trusted_segment(
                segment_file(spool_root, batch_id), installation_id=INSTALLATION_ID
            )
            assert [frame.batch_id for frame in parsed.frames] == [batch_id, batch_id]
    finally:
        verify.close()
