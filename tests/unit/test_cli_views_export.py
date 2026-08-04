"""Direct tests for views.read_trusted_records — the whole-record reader behind `storage export`.

Unlike the metadata display views, this reader feeds a persistence path, so its skip-on-unreadable
behavior must be observable (it records the skipped batch id) rather than a silent drop.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
from _record_factories import event_record

from milhouse.cli import views
from milhouse.spooling import SpoolError


def _segment(batch_id: str) -> SimpleNamespace:
    return SimpleNamespace(batch_id=batch_id, day="2026-07-21")


def test_read_trusted_records_collects_readable_and_records_skips(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    record = event_record()
    monkeypatch.setattr(views, "_segments", lambda paths: (_segment("good"), _segment("bad")))
    monkeypatch.setattr(
        views, "_segment_path", lambda paths, seg: Path(f"/spool/{seg.batch_id}.jsonl")
    )

    def _read(path: Path, *, installation_id: str) -> SimpleNamespace:
        if "bad" in str(path):
            raise SpoolError("MH_SPOOL_CHANGED", "unreadable")
        return SimpleNamespace(frames=[SimpleNamespace(record=record)])

    monkeypatch.setattr(views, "read_trusted_segment", _read)

    scan = views.read_trusted_records(cast(Any, object()), "mh_installation")
    assert scan.records == (record,)  # the readable segment's record is collected
    assert scan.skipped == ("bad",)  # the unreadable segment is surfaced, not silently dropped


def test_read_trusted_records_empty_spool(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(views, "_segments", lambda paths: ())
    scan = views.read_trusted_records(cast(Any, object()), "mh_installation")
    assert scan.records == ()
    assert scan.skipped == ()
