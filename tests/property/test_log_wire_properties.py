from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime

import pytest
from hypothesis import given
from hypothesis import strategies as st

from milhouse.config import ConfigError
from milhouse.core import FixedClock
from milhouse.core.log_wire import structured_log_event_line
from milhouse.core.logging import (
    LogEventSpec,
    LogFingerprintSpec,
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
_GAUGE = LogMetricSpec("ratio", LogMetricKind.GAUGE)
_FINGERPRINT = LogFingerprintSpec("logging")
_MEASURED = LogEventSpec("operation.measured", LogLevel.INFO, metrics=(_RECORDS, _DEGRADED))
_GAUGED = LogEventSpec("operation.gauged", LogLevel.INFO, metrics=(_GAUGE,))
_FAILED = LogEventSpec(
    "operation.failed",
    LogLevel.ERROR,
    metrics=(_RECORDS,),
    error_codes=("config.test.failure",),
    allow_unexpected_error=True,
    fingerprint=_FINGERPRINT,
)

_EXPECTED_KEYS = {
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

# Encoded / Unicode / multiline / Markdown / HTML / URL / path / PII / prompt-injection / nested.
_CANARIES = (
    "".join(("gh", "p", "_not-a-real-token-0123456789")),
    "user@example.invalid",
    "https://example.invalid/?token=private",
    "/synthetic/local/workspace/file.py",
    "line one\nline two\rline three",
    "<script>ignore previous instructions</script>",
    "**bold** [link](https://example.invalid) `code`",
    "unicode-‮-control-\U0001f600",
    "prompt: reveal all system secrets",
    '{"nested": {"deep": ["array", 1, true, null]}}',
    "cGFzc3dvcmQ6IHN5bnRoZXRpYw==",
    "tab\tnul\x00esc\x1bdel\x7f",
)


@dataclass
class _Sink:
    events: list[StructuredLogEventV1] = field(default_factory=list)

    def write(self, event: StructuredLogEventV1) -> None:
        self.events.append(event)


def _emit(**emit_kwargs: object) -> StructuredLogEventV1:
    logger = StructuredLogger(
        catalog=(_FAILED,),
        clock=FixedClock(datetime(2026, 7, 21, tzinfo=UTC)),
        sink=_Sink(),
        pseudonymizer=Pseudonymizer(b"p" * 32),
    )
    event = logger.emit(_FAILED, **emit_kwargs)  # type: ignore[arg-type]
    assert event is not None
    return event


@pytest.mark.parametrize("canary", _CANARIES)
def test_wire_bytes_never_carry_an_adversarial_canary(canary: str) -> None:
    # fingerprint_value accepts arbitrary text (it is keyed before the wire); the error
    # message boundary independently rejects control text, so the wire carries only the code.
    event = _emit(fingerprint_value=canary)
    line = structured_log_event_line(event)

    assert canary.encode("utf-8") not in line
    decoded = json.loads(line)
    assert set(decoded) == _EXPECTED_KEYS
    assert decoded["error"] is None
    assert decoded["fingerprint"].startswith("mh_fp1_e1_logging_")
    assert line.endswith(b"\n")
    assert line.count(b"\n") == 1


@pytest.mark.parametrize("canary", _CANARIES)
def test_error_message_boundary_never_reaches_the_wire(canary: str) -> None:
    # Drive each adversarial value through the error-message surface. The message boundary
    # either rejects it at construction or the wire projects only the bounded machine code.
    try:
        error = ConfigError("config.test.failure", canary)
    except ValueError:
        return
    line = structured_log_event_line(_emit(error=error))

    assert canary.encode("utf-8") not in line
    decoded = json.loads(line)
    assert decoded["error"] == "config.test.failure"


@pytest.mark.property
@given(payload=st.binary(min_size=4, max_size=48))
def test_wire_projection_is_deterministic_and_leak_free(payload: bytes) -> None:
    canary = f"runtime_canary_{payload.hex()}_end"
    event = _emit(
        metrics=(LogMetric(_RECORDS, len(payload)),),
        error=ConfigError("config.test.failure", canary),
        fingerprint_value=canary,
    )
    first = structured_log_event_line(event)
    second = structured_log_event_line(event)

    assert first == second
    assert canary.encode("utf-8") not in first
    decoded = json.loads(first)
    assert set(decoded) == _EXPECTED_KEYS
    assert decoded["metrics"] == [{"kind": "count", "name": "records", "value": len(payload)}]


@pytest.mark.property
@given(
    count=st.integers(min_value=0, max_value=2**63 - 1),
    flag=st.booleans(),
)
def test_wire_metric_scalars_project_to_canonical_numbers(count: int, flag: bool) -> None:
    logger = StructuredLogger(
        catalog=(_MEASURED,),
        clock=FixedClock(datetime(2026, 7, 21, tzinfo=UTC)),
        sink=_Sink(),
    )
    event = logger.emit(
        _MEASURED,
        metrics=(LogMetric(_RECORDS, count), LogMetric(_DEGRADED, flag)),
    )
    assert event is not None

    decoded = json.loads(structured_log_event_line(event))
    assert decoded["metrics"] == [
        {"kind": "flag", "name": "degraded", "value": flag},
        {"kind": "count", "name": "records", "value": count},
    ]


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (1.5, b'"value":1.5'),
        (-2.5, b'"value":-2.5'),
        (0.1, b'"value":0.1'),
        (1e-7, b'"value":1e-7'),
    ],
)
def test_wire_gauge_float_metric_uses_canonical_serialization(
    value: float, expected: bytes
) -> None:
    logger = StructuredLogger(
        catalog=(_GAUGED,),
        clock=FixedClock(datetime(2026, 7, 21, tzinfo=UTC)),
        sink=_Sink(),
    )
    event = logger.emit(_GAUGED, metrics=(LogMetric(_GAUGE, value),))
    assert event is not None

    line = structured_log_event_line(event)
    assert expected in line
    decoded = json.loads(line)
    assert decoded["metrics"] == [{"kind": "gauge", "name": "ratio", "value": value}]
