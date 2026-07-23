from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime

import pytest

from milhouse.config import ConfigError
from milhouse.core import FixedClock
from milhouse.core.log_wire import (
    MAX_EVENT_LINE_BYTES,
    STRUCTURED_LOG_LINE_EVENT,
    STRUCTURED_LOG_PRIVACY_CLASS,
    STRUCTURED_LOG_SCHEMA_VERSION,
    structured_log_event_line,
)
from milhouse.core.logging import (
    LogEventSpec,
    LogFingerprintSpec,
    LoggingError,
    LogLevel,
    LogMetric,
    LogMetricKind,
    LogMetricSpec,
    StructuredLogEventV1,
    StructuredLogger,
)
from milhouse.privacy import Pseudonymizer

_RECORDS = LogMetricSpec("records", LogMetricKind.COUNT)
_DEGRADED = LogMetricSpec("degraded", LogMetricKind.FLAG)
_CORRELATION = LogFingerprintSpec("logging")
_PLAIN = LogEventSpec(
    "collector.completed",
    LogLevel.INFO,
    metrics=(_RECORDS, _DEGRADED),
)
_RICH = LogEventSpec(
    "collector.completed",
    LogLevel.WARNING,
    metrics=(_RECORDS,),
    error_codes=("config.test.failure",),
    fingerprint=_CORRELATION,
)


@dataclass
class _CapturingSink:
    events: list[StructuredLogEventV1] = field(default_factory=list)

    def write(self, event: StructuredLogEventV1) -> None:
        self.events.append(event)


def _emit(spec: LogEventSpec, **emit_kwargs: object) -> StructuredLogEventV1:
    logger = StructuredLogger(
        catalog=(spec,),
        clock=FixedClock(datetime(2026, 7, 21, 12, 34, 56, 987654, tzinfo=UTC)),
        sink=_CapturingSink(),
        minimum_level=LogLevel.DEBUG,
        pseudonymizer=Pseudonymizer(b"f" * 32),
    )
    event = logger.emit(spec, **emit_kwargs)  # type: ignore[arg-type]
    assert event is not None
    return event


def test_event_line_golden_bytes() -> None:
    event = _emit(_PLAIN, metrics=(LogMetric(_RECORDS, 3),))

    assert structured_log_event_line(event) == (
        b'{"error":null,"fingerprint":null,"level":"INFO","line":"event",'
        b'"metrics":[{"kind":"count","name":"records","value":3}],'
        b'"name":"collector.completed","privacy":"internal","schema":1,'
        b'"ts":"2026-07-21T12:34:56.987Z"}\n'
    )


def test_event_line_golden_bytes_with_coded_error() -> None:
    event = _emit(
        _RICH,
        metrics=(LogMetric(_RECORDS, 1),),
        error=ConfigError("config.test.failure", "unused-detail"),
    )

    assert structured_log_event_line(event) == (
        b'{"error":"config.test.failure","fingerprint":null,"level":"WARNING",'
        b'"line":"event","metrics":[{"kind":"count","name":"records","value":1}],'
        b'"name":"collector.completed","privacy":"internal","schema":1,'
        b'"ts":"2026-07-21T12:34:56.987Z"}\n'
    )


def test_event_line_is_a_closed_key_set_with_one_trailing_lf() -> None:
    event = _emit(_PLAIN, metrics=(LogMetric(_RECORDS, 3), LogMetric(_DEGRADED, True)))
    line = structured_log_event_line(event)

    assert line.endswith(b"\n")
    assert line.count(b"\n") == 1
    decoded = json.loads(line)
    assert set(decoded) == {
        "schema",
        "line",
        "privacy",
        "ts",
        "name",
        "level",
        "metrics",
        "error",
        "fingerprint",
    }
    assert decoded["schema"] == STRUCTURED_LOG_SCHEMA_VERSION
    assert decoded["line"] == STRUCTURED_LOG_LINE_EVENT
    assert decoded["privacy"] == STRUCTURED_LOG_PRIVACY_CLASS
    assert decoded["level"] == "INFO"
    # metrics stay sorted by name and expose only kind/name/value
    assert decoded["metrics"] == [
        {"kind": "flag", "name": "degraded", "value": True},
        {"kind": "count", "name": "records", "value": 3},
    ]
    assert all(set(metric) == {"kind", "name", "value"} for metric in decoded["metrics"])


def test_event_line_never_carries_arbitrary_text_or_exception_detail() -> None:
    canary = "runtime-secret-message-7f31ac"
    event = _emit(
        _RICH,
        metrics=(LogMetric(_RECORDS, 1),),
        error=ConfigError("config.test.failure", canary),
        fingerprint_value=canary,
    )
    line = structured_log_event_line(event)

    assert canary.encode("utf-8") not in line
    decoded = json.loads(line)
    assert decoded["error"] == "config.test.failure"
    assert decoded["fingerprint"].startswith("mh_fp1_e1_logging_")
    assert decoded["level"] == "WARNING"


def test_event_line_rejects_a_non_event_value() -> None:
    with pytest.raises(LoggingError) as captured:
        structured_log_event_line({"name": "collector.completed"})  # type: ignore[arg-type]
    assert captured.value.code == "MH_LOG_WIRE_EVENT"


def test_event_line_stays_within_the_line_byte_bound() -> None:
    event = _emit(_PLAIN, metrics=(LogMetric(_RECORDS, 3),))
    assert len(structured_log_event_line(event)) <= MAX_EVENT_LINE_BYTES


def test_event_line_fails_closed_when_local_log_authorization_changes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from milhouse.core import log_wire
    from milhouse.privacy import EgressDisposition

    monkeypatch.setattr(
        log_wire,
        "require_egress",
        lambda **_kwargs: EgressDisposition.REDACTED_RECORD,
    )
    event = _emit(_PLAIN, metrics=(LogMetric(_RECORDS, 3),))
    with pytest.raises(LoggingError) as captured:
        log_wire.structured_log_event_line(event)
    assert captured.value.code == "MH_LOG_WIRE_EGRESS"
