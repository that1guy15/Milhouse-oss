from __future__ import annotations

import io
import traceback
from dataclasses import dataclass, field
from datetime import UTC, datetime

import pytest

from milhouse.core import FixedClock
from milhouse.core.log_wire import StreamLogSink, structured_log_event_line
from milhouse.core.logging import (
    LogEventSpec,
    LoggingError,
    LogLevel,
    LogMetric,
    LogMetricKind,
    LogMetricSpec,
    StructuredLogEventV1,
    StructuredLogger,
)

_RECORDS = LogMetricSpec("records", LogMetricKind.COUNT)
_COMMIT = LogEventSpec("spool.commit", LogLevel.INFO, metrics=(_RECORDS,))
_RETRY = LogEventSpec("spool.retry", LogLevel.WARNING, metrics=(_RECORDS,))


@dataclass
class _CapturingSink:
    events: list[StructuredLogEventV1] = field(default_factory=list)

    def write(self, event: StructuredLogEventV1) -> None:
        self.events.append(event)


def _logger(
    sink: object, *, catalog: tuple[LogEventSpec, ...] = (_COMMIT, _RETRY)
) -> StructuredLogger:
    return StructuredLogger(
        catalog=catalog,
        clock=FixedClock(datetime(2026, 7, 21, 12, 0, 0, tzinfo=UTC)),
        sink=sink,  # type: ignore[arg-type]
        minimum_level=LogLevel.DEBUG,
    )


def _event() -> StructuredLogEventV1:
    capture = _CapturingSink()
    event = _logger(capture).emit(_COMMIT, metrics=(LogMetric(_RECORDS, 3),))
    assert event is not None
    return event


def test_stream_sink_writes_exactly_one_canonical_line() -> None:
    stream = io.BytesIO()
    event = _event()

    StreamLogSink(stream).write(event)

    written = stream.getvalue()
    assert written == structured_log_event_line(event)
    assert written.endswith(b"\n")
    assert written.count(b"\n") == 1


def test_stream_sink_appends_sequential_event_lines() -> None:
    stream = io.BytesIO()
    sink = StreamLogSink(stream)
    capture = _CapturingSink()
    logger = _logger(capture)

    first = logger.emit(_COMMIT, metrics=(LogMetric(_RECORDS, 1),))
    second = logger.emit(_RETRY, metrics=(LogMetric(_RECORDS, 2),))
    assert first is not None
    assert second is not None
    sink.write(first)
    sink.write(second)

    assert stream.getvalue() == structured_log_event_line(first) + structured_log_event_line(second)
    assert stream.getvalue().count(b"\n") == 2


def test_stream_sink_rejects_a_non_writable_stream() -> None:
    with pytest.raises(LoggingError) as captured:
        StreamLogSink(object())  # type: ignore[arg-type]
    assert captured.value.code == "MH_LOG_SINK_STREAM"


def test_stream_sink_rejects_a_non_event_value() -> None:
    sink = StreamLogSink(io.BytesIO())
    with pytest.raises(LoggingError) as captured:
        sink.write({"name": "spool.commit"})  # type: ignore[arg-type]
    assert captured.value.code == "MH_LOG_SINK_EVENT"


def test_stream_sink_wraps_a_hostile_stream_failure_without_leaking_detail() -> None:
    canary = "runtime-private-stream-detail-9c1f"

    class _HostileStream:
        def write(self, _data: bytes) -> int:
            raise OSError(canary)

    with pytest.raises(LoggingError) as captured:
        StreamLogSink(_HostileStream()).write(_event())

    error = captured.value
    assert error.code == "MH_LOG_SINK_WRITE"
    assert error.__cause__ is None
    assert error.__context__ is None
    graph = (
        str(error),
        repr(error),
        repr(error.args),
        "".join(traceback.format_exception(error)),
    )
    assert all(canary not in part for part in graph)


def test_structured_logger_delivers_to_a_stream_sink_without_touching_stdio(
    capsys: pytest.CaptureFixture[str],
) -> None:
    stream = io.BytesIO()
    event = _logger(StreamLogSink(stream)).emit(_COMMIT, metrics=(LogMetric(_RECORDS, 7),))

    assert event is not None
    assert stream.getvalue() == structured_log_event_line(event)
    assert capsys.readouterr() == ("", "")


class _ScriptedStream:
    """A binary stream whose write() returns scripted values and records accepted bytes."""

    def __init__(self, script: list[object]) -> None:
        self._script = list(script)
        self.written = bytearray()

    def write(self, data: object) -> object:
        outcome = self._script.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        buffer = bytes(data)  # type: ignore[arg-type]
        if type(outcome) is int and 0 <= outcome <= len(buffer):
            self.written += buffer[:outcome]
        return outcome


def test_stream_sink_completes_a_short_then_complete_write() -> None:
    event = _event()
    line = structured_log_event_line(event)
    stream = _ScriptedStream([7, len(line) - 7])

    StreamLogSink(stream).write(event)

    assert bytes(stream.written) == line


def test_stream_sink_completes_a_repeatedly_short_write() -> None:
    event = _event()
    line = structured_log_event_line(event)
    stream = _ScriptedStream([1, 1, len(line) - 2])

    StreamLogSink(stream).write(event)

    assert bytes(stream.written) == line


@pytest.mark.parametrize(
    "script",
    [
        [0],  # zero progress
        [-1],  # negative
        [None],  # non-integer
        [True],  # bool is not int
        [10_000],  # oversized (greater than the remaining length)
        [7, OSError("short then fail")],  # partial then raise
    ],
)
def test_stream_sink_fails_closed_on_invalid_or_incomplete_writes(script: list[object]) -> None:
    stream = _ScriptedStream(script)
    with pytest.raises(LoggingError) as captured:
        StreamLogSink(stream).write(_event())

    assert captured.value.code == "MH_LOG_SINK_WRITE"
    # a partial or rejected acceptance is never reported as a complete event line
    assert bytes(stream.written) != structured_log_event_line(_event())
