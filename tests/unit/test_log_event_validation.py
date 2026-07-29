"""P1-6: exact CanonicalJSONV1/A05 validation of complete stored event lines.

A COMPLETE but noncanonical or privacy-invalid event line must be refused at every read surface —
reopen, recovery, and retention — with a fixed value-free code, never digested or certified as
durable history. These tests mutate each event field independently and prove the shared validator
and all three surfaces fail closed without leaking the offending bytes.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from milhouse.core.canonical import canonical_json_bytes
from milhouse.core.errors import UNEXPECTED_ERROR_CODE
from milhouse.core.log_store import (
    StructuredLogStore,
    recover_structured_logs,
    retention_preview,
)
from milhouse.core.log_wire import (
    MAX_EVENT_LINE_BYTES,
    StructuredLogHeaderV1,
    StructuredLogTrailerV1,
    structured_log_header_line,
    structured_log_trailer_line,
    validate_structured_log_event_line,
)
from milhouse.core.logging import LoggingError
from milhouse.state import GlobalCommitBarrier, initialize_control_state, open_control_database

_NOW = datetime(2026, 7, 26, 12, 0, 0, tzinfo=UTC)
_LF = b"\n"
_CANARY = "SECRETCANARY"
_VALID_FINGERPRINT = "mh_fp1_e1_repo_" + "a" * 52


def _monotonic() -> float:
    return 0.0


def _payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema": 1,
        "line": "event",
        "privacy": "internal",
        "ts": "2026-07-26T12:00:00.000Z",
        "name": "collector.completed",
        "level": "INFO",
        "metrics": [{"kind": "count", "name": "records", "value": 1}],
        "error": None,
        "fingerprint": None,
    }
    payload.update(overrides)
    return payload


def _canonical_line(**overrides: object) -> bytes:
    return canonical_json_bytes(_payload(**overrides), max_bytes=MAX_EVENT_LINE_BYTES - 1) + _LF


def _canonical_missing(key: str) -> bytes:
    payload = _payload()
    del payload[key]
    return canonical_json_bytes(payload, max_bytes=MAX_EVENT_LINE_BYTES - 1) + _LF


# --- accept path ---------------------------------------------------------------------------------


def test_a_canonical_event_line_validates_and_returns_its_timestamp() -> None:
    assert validate_structured_log_event_line(_canonical_line()) == _NOW


def test_a_canonical_line_with_a_coded_error_and_keyed_fingerprint_validates() -> None:
    line = _canonical_line(error=UNEXPECTED_ERROR_CODE, fingerprint=_VALID_FINGERPRINT)
    assert validate_structured_log_event_line(line) == _NOW


def test_an_empty_metrics_array_validates() -> None:
    assert validate_structured_log_event_line(_canonical_line(metrics=[])) == _NOW


_VALID_METRIC_SHAPES: list[tuple[str, object]] = [
    ("flag", True),
    ("count", 3),
    ("bytes", 4096),
    ("duration_milliseconds", 12),
    ("gauge", 7),
    ("gauge", 1.5),
]


@pytest.mark.parametrize(
    "kind,value", _VALID_METRIC_SHAPES, ids=[f"{k}-{v}" for k, v in _VALID_METRIC_SHAPES]
)
def test_every_metric_shape_validates(kind: str, value: object) -> None:
    line = _canonical_line(metrics=[{"kind": kind, "name": "measure", "value": value}])
    assert validate_structured_log_event_line(line) == _NOW


# --- field-value mutations (canonical shape, invalid content) ------------------------------------

_BAD_CANONICAL: list[tuple[str, bytes]] = [
    ("name-path-traversal", _canonical_line(name=f"../../{_CANARY}/path")),
    ("name-uppercase", _canonical_line(name="Collector.Completed")),
    ("name-empty", _canonical_line(name="")),
    ("level-unknown", _canonical_line(level="BOGUS")),
    ("level-integer", _canonical_line(level=20)),
    ("metrics-not-array", _canonical_line(metrics=_CANARY)),
    (
        "metric-bad-kind",
        _canonical_line(metrics=[{"kind": "bogus", "name": "records", "value": 1}]),
    ),
    (
        "metric-flag-non-bool",
        _canonical_line(metrics=[{"kind": "flag", "name": "records", "value": 1}]),
    ),
    (
        "metric-count-negative",
        _canonical_line(metrics=[{"kind": "count", "name": "records", "value": -1}]),
    ),
    (
        "metric-extra-key",
        _canonical_line(metrics=[{"kind": "count", "name": "records", "value": 1, "x": 2}]),
    ),
    (
        "metrics-unsorted",
        _canonical_line(
            metrics=[
                {"kind": "count", "name": "zeta", "value": 1},
                {"kind": "count", "name": "alpha", "value": 1},
            ]
        ),
    ),
    (
        "metrics-duplicate",
        _canonical_line(
            metrics=[
                {"kind": "count", "name": "records", "value": 1},
                {"kind": "count", "name": "records", "value": 2},
            ]
        ),
    ),
    ("ts-non-string", _canonical_line(ts=123)),
    ("ts-unparseable", _canonical_line(ts="not-a-timestamp")),
    (
        "metric-nonstring-kind",
        _canonical_line(metrics=[{"kind": 1, "name": "records", "value": 1}]),
    ),
    (
        "metric-bad-name",
        _canonical_line(metrics=[{"kind": "count", "name": "Bad Name", "value": 1}]),
    ),
    (
        "gauge-non-numeric",
        _canonical_line(metrics=[{"kind": "gauge", "name": "ratio", "value": "x"}]),
    ),
    ("error-arbitrary-text", _canonical_line(error=f"{_CANARY}-secret-text")),
    ("fingerprint-numeric", _canonical_line(fingerprint=123)),
    ("fingerprint-bad-pattern", _canonical_line(fingerprint="mh_fp1_bad")),
    ("extra-field", _canonical_line(**{f"{_CANARY}_extra": 1})),
    ("missing-fingerprint", _canonical_missing("fingerprint")),
    ("schema-wrong", _canonical_line(schema=2)),
    ("line-wrong", _canonical_line(line="header")),
    ("privacy-wrong", _canonical_line(privacy="restricted")),
]

# --- byte-form mutations (valid content, noncanonical bytes) rejected by the round-trip ----------

_BAD_NONCANONICAL: list[tuple[str, bytes]] = [
    ("whitespace", json.dumps(_payload()).encode("utf-8") + _LF),
    (
        "key-order",
        b'{"ts":"2026-07-26T12:00:00.000Z","schema":1,"line":"event","privacy":"internal",'
        b'"name":"collector.completed","level":"INFO",'
        b'"metrics":[{"kind":"count","name":"records","value":1}],"error":null,"fingerprint":null}\n',
    ),
    ("ts-short-precision", _canonical_line(ts="2026-07-26T12:00:00.5Z")),
    ("ts-sub-millisecond", _canonical_line(ts="2026-07-26T12:00:00.123456Z")),
    (
        "gauge-noncanonical-float",
        b'{"error":null,"fingerprint":null,"level":"INFO","line":"event",'
        b'"metrics":[{"kind":"gauge","name":"ratio","value":2.0}],"name":"collector.completed",'
        b'"privacy":"internal","schema":1,"ts":"2026-07-26T12:00:00.000Z"}\n',
    ),
]


@pytest.mark.parametrize(
    "line",
    [c[1] for c in _BAD_CANONICAL + _BAD_NONCANONICAL],
    ids=[c[0] for c in _BAD_CANONICAL + _BAD_NONCANONICAL],
)
def test_a_complete_invalid_event_line_is_refused_value_free(line: bytes) -> None:
    with pytest.raises(LoggingError) as refused:
        validate_structured_log_event_line(line)
    assert refused.value.code == "MH_LOG_WIRE_EVENT"
    assert _CANARY not in repr(refused.value.args)
    assert refused.value.__context__ is None and refused.value.__cause__ is None


@pytest.mark.parametrize(
    "line",
    [b"not json\n", b"[1,2,3]\n", b"\xff\xfe\n", b"x" * (MAX_EVENT_LINE_BYTES + 1)],
    ids=["non-json", "json-array", "invalid-utf8", "oversized"],
)
def test_a_structurally_broken_line_is_refused(line: bytes) -> None:
    with pytest.raises(LoggingError) as refused:
        validate_structured_log_event_line(line)
    assert refused.value.code == "MH_LOG_WIRE_EVENT"


def test_a_non_bytes_line_is_refused() -> None:
    with pytest.raises(LoggingError) as refused:
        validate_structured_log_event_line("collector.completed")  # type: ignore[arg-type]
    assert refused.value.code == "MH_LOG_WIRE_EVENT"


# --- the same bad line is refused at every read surface ------------------------------------------


def _state_root(tmp_path: Path) -> Path:
    logs = tmp_path / "logs"
    logs.mkdir(mode=0o700)
    os.chmod(logs, 0o700)
    control = tmp_path / "control"
    control.mkdir(mode=0o700)
    os.chmod(control, 0o700)
    return logs


def _barrier(tmp_path: Path) -> GlobalCommitBarrier:
    control = tmp_path / "control"
    database = open_control_database(control / "milhouse.sqlite3")
    barrier = GlobalCommitBarrier(control / "commit.lock")
    initialize_control_state(database, barrier=barrier, applied_at=_NOW)
    database.close()
    return barrier


def _header_line() -> bytes:
    return structured_log_header_line(
        StructuredLogHeaderV1(sequence=1, opened_at=_NOW, retention_days=14)
    )


def _write_private(path: Path, content: bytes) -> None:
    path.write_bytes(content)
    os.chmod(path, 0o600)


def test_reopen_rejects_a_complete_invalid_event_line(tmp_path: Path) -> None:
    logs = _state_root(tmp_path)
    current = logs / "structured-log.current.jsonl"
    _write_private(current, _header_line() + _canonical_line(level="BOGUS"))
    with pytest.raises(LoggingError) as refused:
        StructuredLogStore(logs_dir=logs, retention_days=14, monotonic=_monotonic, opened_at=_NOW)
    assert refused.value.code == "MH_LOG_EVENT"
    assert "BOGUS" not in repr(refused.value.args)


def test_recovery_rejects_a_complete_invalid_event_line(tmp_path: Path) -> None:
    logs = _state_root(tmp_path)
    barrier = _barrier(tmp_path)
    current = logs / "structured-log.current.jsonl"
    _write_private(current, _header_line() + _canonical_line(level="BOGUS"))
    with pytest.raises(LoggingError) as refused:
        recover_structured_logs(logs_dir=logs, barrier=barrier, monotonic=_monotonic)
    assert refused.value.code == "MH_LOG_EVENT"


def test_retention_refuses_a_closed_segment_with_an_invalid_event_line(tmp_path: Path) -> None:
    logs = _state_root(tmp_path)
    barrier = _barrier(tmp_path)
    trailer = structured_log_trailer_line(
        StructuredLogTrailerV1(
            sequence=1,
            closed_at=_NOW,
            last_event_at=_NOW,
            event_count=1,
            content_sha256="0" * 64,
            expires_at=_NOW + timedelta(days=14),
        )
    )
    segment = logs / f"structured-log.{1:020d}.jsonl"
    _write_private(segment, _header_line() + _canonical_line(level="BOGUS") + trailer)
    report = retention_preview(
        logs_dir=logs,
        barrier=barrier,
        monotonic=_monotonic,
        retention_days=14,
        now=_NOW + timedelta(days=30),
    )
    assert report.segments == ()
    assert [(refused.sequence, refused.code) for refused in report.refused] == [(1, "MH_LOG_EVENT")]
