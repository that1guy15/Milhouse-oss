from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta, timezone

import pytest

from milhouse.config import ConfigError
from milhouse.core import FixedClock
from milhouse.core.errors import UNEXPECTED_ERROR_CODE
from milhouse.core.logging import (
    MAX_LOG_CATALOG_EVENTS,
    MAX_LOG_ERROR_CODES,
    MAX_LOG_METRICS,
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
_LATENCY = LogMetricSpec("latency_ms", LogMetricKind.DURATION_MILLISECONDS)
_CORRELATION = LogFingerprintSpec("logging")
_COMPLETED = LogEventSpec(
    "collector.completed",
    LogLevel.INFO,
    metrics=(_RECORDS, _DEGRADED, _LATENCY),
    error_codes=("config.test.failure",),
    allow_unexpected_error=True,
    fingerprint=_CORRELATION,
)
_DEBUG = LogEventSpec("collector.debug", LogLevel.DEBUG)


@dataclass
class _CapturingSink:
    events: list[StructuredLogEventV1] = field(default_factory=list)

    def write(self, event: StructuredLogEventV1) -> None:
        self.events.append(event)


def _clock() -> FixedClock:
    return FixedClock(datetime(2026, 7, 21, 12, 34, 56, 987654, tzinfo=UTC))


def _logger(
    sink: object | None = None,
    *,
    catalog: tuple[LogEventSpec, ...] = (_COMPLETED, _DEBUG),
    minimum_level: LogLevel = LogLevel.INFO,
    clock: object | None = None,
) -> StructuredLogger:
    return StructuredLogger(
        catalog=catalog,
        clock=_clock() if clock is None else clock,  # type: ignore[arg-type]
        sink=_CapturingSink() if sink is None else sink,  # type: ignore[arg-type]
        minimum_level=minimum_level,
        pseudonymizer=Pseudonymizer(b"f" * 32),
    )


def test_logger_emits_catalog_bound_event_without_terminal_output(
    capsys: pytest.CaptureFixture[str],
) -> None:
    runtime_canary = "runtime-secret-message-1a02c9"
    sink = _CapturingSink()

    emitted = _logger(sink).emit(
        _COMPLETED,
        metrics=(LogMetric(_RECORDS, 3), LogMetric(_DEGRADED, False)),
        error=ConfigError("config.test.failure", runtime_canary),
        fingerprint_value=runtime_canary,
    )

    assert emitted is sink.events[0]
    assert emitted.timestamp == datetime(2026, 7, 21, 12, 34, 56, 987000, tzinfo=UTC)
    assert emitted.name == "collector.completed"
    assert [metric.spec.name for metric in emitted.metrics] == ["degraded", "records"]
    assert emitted.error is not None
    assert emitted.error.code == "config.test.failure"
    assert emitted.fingerprint is not None
    assert emitted.fingerprint.startswith("mh_fp1_e1_logging_")
    assert runtime_canary not in repr(emitted)
    assert capsys.readouterr() == ("", "")


def test_unknown_or_unregistered_error_codes_reduce_to_fixed_metadata() -> None:
    runtime_canary = "runtime_secret_code_314159"
    sink = _CapturingSink()
    event = _logger(sink).emit(
        _COMPLETED,
        error=ConfigError(f"config.{runtime_canary}", runtime_canary),
    )

    assert event is not None
    assert event.error is not None
    assert event.error.code == UNEXPECTED_ERROR_CODE
    assert runtime_canary not in repr(event)


def test_hostile_unknown_exception_graph_is_never_rendered() -> None:
    runtime_canary = "runtime-secret-exception-a1527c"

    def hostile_render(_error: BaseException) -> str:
        raise AssertionError("logging must not render unknown exceptions")

    hostile_type = type(
        f"RuntimeCanary_{runtime_canary}",
        (Exception,),
        {"__str__": hostile_render, "__repr__": hostile_render},
    )
    error = hostile_type(runtime_canary)
    error.__cause__ = RuntimeError(runtime_canary)
    error.__context__ = ValueError(runtime_canary)
    error.add_note(runtime_canary)

    event = _logger().emit(_COMPLETED, error=error)

    assert event is not None
    assert event.error is not None
    assert event.error.code == UNEXPECTED_ERROR_CODE
    assert runtime_canary not in repr(event)


def test_event_without_error_capability_rejects_any_error() -> None:
    with pytest.raises(LoggingError) as captured:
        _logger(minimum_level=LogLevel.DEBUG).emit(
            _DEBUG,
            error=RuntimeError("runtime detail"),
        )

    assert captured.value.code == "MH_LOG_ERROR"


def test_event_rejects_non_exception_error_input_without_rendering_it() -> None:
    runtime_canary = "runtime-private-error-input-a405f7"

    with pytest.raises(LoggingError) as captured:
        _logger().emit(_COMPLETED, error=runtime_canary)  # type: ignore[arg-type]

    assert captured.value.code == "MH_LOG_ERROR"
    assert runtime_canary not in str(captured.value)


def test_filtered_event_does_not_read_clock_or_touch_sink() -> None:
    class UnusableClock:
        def now(self) -> datetime:
            raise AssertionError("filtered event read the clock")

    class UnusableSink:
        def write(self, _event: StructuredLogEventV1) -> None:
            raise AssertionError("filtered event touched the sink")

    logger = _logger(
        UnusableSink(),
        minimum_level=LogLevel.WARNING,
        clock=UnusableClock(),
    )

    assert logger.emit(_DEBUG) is None


@pytest.mark.parametrize(
    ("kind", "accepted"),
    [
        (LogMetricKind.FLAG, True),
        (LogMetricKind.COUNT, 0),
        (LogMetricKind.BYTES, 2**63 - 1),
        (LogMetricKind.DURATION_MILLISECONDS, 25),
        (LogMetricKind.GAUGE, -(2**63)),
        (LogMetricKind.GAUGE, 1.5),
    ],
)
def test_metric_kinds_accept_only_their_safe_scalar_domain(
    kind: LogMetricKind,
    accepted: bool | int | float,
) -> None:
    spec = LogMetricSpec("value", kind)

    assert LogMetric(spec, accepted).value == accepted


@pytest.mark.parametrize(
    ("kind", "rejected"),
    [
        (LogMetricKind.FLAG, 1),
        (LogMetricKind.COUNT, True),
        (LogMetricKind.COUNT, -1),
        (LogMetricKind.BYTES, 1.5),
        (LogMetricKind.DURATION_MILLISECONDS, 2**63),
        (LogMetricKind.GAUGE, True),
        (LogMetricKind.GAUGE, float("nan")),
        (LogMetricKind.GAUGE, float("inf")),
        (LogMetricKind.GAUGE, float(2**63)),
        (LogMetricKind.GAUGE, "raw text"),
    ],
)
def test_metric_kinds_reject_wrong_or_unbounded_values(
    kind: LogMetricKind,
    rejected: object,
) -> None:
    with pytest.raises(LoggingError) as captured:
        LogMetric(LogMetricSpec("value", kind), rejected)  # type: ignore[arg-type]

    assert captured.value.code == "MH_LOG_METRIC"
    assert repr(rejected) not in str(captured.value)


@pytest.mark.parametrize(
    ("name", "kind", "code"),
    [
        ("", LogMetricKind.COUNT, "MH_LOG_NAME"),
        ("Uppercase", LogMetricKind.COUNT, "MH_LOG_NAME"),
        ("a" * 65, LogMetricKind.COUNT, "MH_LOG_NAME"),
        ("valid", "count", "MH_LOG_METRIC"),
    ],
)
def test_metric_spec_is_strict(name: str, kind: object, code: str) -> None:
    with pytest.raises(LoggingError) as captured:
        LogMetricSpec(name, kind)  # type: ignore[arg-type]

    assert captured.value.code == code


def test_metric_requires_a_validated_spec() -> None:
    with pytest.raises(LoggingError, match="MH_LOG_METRIC"):
        LogMetric(object(), 1)  # type: ignore[arg-type]


def test_event_spec_canonicalizes_its_allowlists() -> None:
    second = LogMetricSpec("a_metric", LogMetricKind.COUNT)
    spec = LogEventSpec(
        "event.valid",
        LogLevel.INFO,
        metrics=(_RECORDS, second),
        error_codes=("secrets.test.failure", "config.test.failure"),
    )

    assert [metric.name for metric in spec.metrics] == ["a_metric", "records"]
    assert spec.error_codes == ("config.test.failure", "secrets.test.failure")


@pytest.mark.parametrize(
    "kwargs",
    [
        {"name": "", "level": LogLevel.INFO},
        {"name": "event.valid", "level": 20},
        {"name": "event.valid", "level": LogLevel.INFO, "metrics": []},
        {
            "name": "event.valid",
            "level": LogLevel.INFO,
            "metrics": tuple(
                LogMetricSpec(f"metric_{index}", LogMetricKind.COUNT)
                for index in range(MAX_LOG_METRICS + 1)
            ),
        },
        {"name": "event.valid", "level": LogLevel.INFO, "metrics": (object(),)},
        {
            "name": "event.valid",
            "level": LogLevel.INFO,
            "metrics": (_RECORDS, LogMetricSpec("records", LogMetricKind.COUNT)),
        },
        {"name": "event.valid", "level": LogLevel.INFO, "error_codes": []},
        {
            "name": "event.valid",
            "level": LogLevel.INFO,
            "error_codes": tuple(
                f"config.test_{index}.failure" for index in range(MAX_LOG_ERROR_CODES + 1)
            ),
        },
        {"name": "event.valid", "level": LogLevel.INFO, "error_codes": ("bad-code",)},
        {
            "name": "event.valid",
            "level": LogLevel.INFO,
            "error_codes": ("config.test.failure", "config.test.failure"),
        },
        {
            "name": "event.valid",
            "level": LogLevel.INFO,
            "error_codes": (UNEXPECTED_ERROR_CODE,),
        },
        {"name": "event.valid", "level": LogLevel.INFO, "allow_unexpected_error": 1},
        {"name": "event.valid", "level": LogLevel.INFO, "fingerprint": object()},
    ],
)
def test_event_spec_rejects_invalid_contracts(kwargs: dict[str, object]) -> None:
    with pytest.raises(LoggingError) as captured:
        LogEventSpec(**kwargs)  # type: ignore[arg-type]

    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None


def test_event_spec_invalid_error_code_never_survives_in_exception_graph() -> None:
    runtime_canary = "runtime-private-error-code-7e316b"

    with pytest.raises(LoggingError) as captured:
        LogEventSpec(
            "event.valid",
            LogLevel.INFO,
            error_codes=(runtime_canary,),
        )

    assert runtime_canary not in str(captured.value)
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None


def test_logger_catalog_is_identity_bound() -> None:
    runtime_canary = "runtime_secret_account_314159"
    runtime_spec = LogEventSpec(runtime_canary, LogLevel.INFO)

    with pytest.raises(LoggingError) as captured:
        _logger().emit(runtime_spec)

    assert captured.value.code == "MH_LOG_SPEC"
    assert runtime_canary not in str(captured.value)


def test_event_metric_allowlist_is_identity_bound() -> None:
    runtime_canary = "runtime_secret_metric_314159"
    runtime_spec = LogMetricSpec(runtime_canary, LogMetricKind.COUNT)
    equal_but_unregistered = LogMetricSpec("records", LogMetricKind.COUNT)

    for metric in (LogMetric(runtime_spec, 314159), LogMetric(equal_but_unregistered, 1)):
        with pytest.raises(LoggingError) as captured:
            _logger().emit(_COMPLETED, metrics=(metric,))
        assert captured.value.code == "MH_LOG_METRICS"
        assert runtime_canary not in str(captured.value)


def test_event_rejects_duplicate_excess_or_unvalidated_metrics() -> None:
    with pytest.raises(LoggingError, match="MH_LOG_METRICS"):
        _logger().emit(
            _COMPLETED,
            metrics=(LogMetric(_RECORDS, 1), LogMetric(_RECORDS, 2)),
        )
    with pytest.raises(LoggingError, match="MH_LOG_METRICS"):
        _logger().emit(_COMPLETED, metrics=[LogMetric(_RECORDS, 1)])  # type: ignore[arg-type]
    with pytest.raises(LoggingError, match="MH_LOG_METRICS"):
        _logger().emit(_COMPLETED, metrics=(object(),))  # type: ignore[arg-type]
    with pytest.raises(LoggingError, match="MH_LOG_METRICS"):
        _logger().emit(
            _COMPLETED,
            metrics=tuple(LogMetric(_RECORDS, index) for index in range(MAX_LOG_METRICS + 1)),
        )


def test_event_enforces_total_metadata_size_bound() -> None:
    metric_specs = tuple(
        LogMetricSpec(f"m{index:02d}_" + ("a" * 60), LogMetricKind.GAUGE)
        for index in range(MAX_LOG_METRICS)
    )
    spec = LogEventSpec("event.valid", LogLevel.INFO, metrics=metric_specs)
    metrics = tuple(LogMetric(metric_spec, index) for index, metric_spec in enumerate(metric_specs))

    with pytest.raises(LoggingError) as captured:
        _logger(catalog=(spec,)).emit(spec, metrics=metrics)

    assert captured.value.code == "MH_LOG_SIZE"


def test_event_type_cannot_be_constructed_directly() -> None:
    with pytest.raises(TypeError):
        StructuredLogEventV1()


def test_event_normalizes_aware_timestamp_to_utc_milliseconds() -> None:
    timestamp = datetime(
        2026,
        7,
        21,
        14,
        34,
        56,
        987654,
        tzinfo=timezone(timedelta(hours=2)),
    )

    class OffsetClock:
        def now(self) -> datetime:
            return timestamp

    event = _logger(clock=OffsetClock()).emit(_COMPLETED)

    assert event is not None
    assert event.timestamp == datetime(2026, 7, 21, 12, 34, 56, 987000, tzinfo=UTC)


def test_invalid_event_timestamp_is_detached() -> None:
    class NaiveClock:
        def now(self) -> datetime:
            return datetime(2026, 7, 21)

    with pytest.raises(LoggingError) as captured:
        _logger(clock=NaiveClock()).emit(_COMPLETED)

    assert captured.value.code == "MH_LOG_TIMESTAMP"
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None


def test_fingerprint_is_derived_inside_logger_from_catalog_kind() -> None:
    runtime_canary = "runtime_secret_fingerprint_value_314159"

    event = _logger().emit(_COMPLETED, fingerprint_value=runtime_canary)

    assert event is not None
    assert event.fingerprint is not None
    assert event.fingerprint.startswith("mh_fp1_e1_logging_")
    assert runtime_canary not in event.fingerprint
    assert runtime_canary not in repr(event)


@pytest.mark.parametrize("kind", ["logging.kind", "Bad Kind", "x" * 33])
def test_fingerprint_spec_uses_exact_pseudonym_kind_contract(kind: str) -> None:
    with pytest.raises(LoggingError) as captured:
        LogFingerprintSpec(kind)

    assert captured.value.code == "MH_LOG_FINGERPRINT"
    assert kind not in str(captured.value)
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None


def test_logger_requires_real_pseudonymizer_for_fingerprint_catalog() -> None:
    for pseudonymizer in (None, object()):
        with pytest.raises(LoggingError, match="MH_LOG_FINGERPRINT"):
            StructuredLogger(
                catalog=(_COMPLETED,),
                clock=_clock(),
                sink=_CapturingSink(),
                pseudonymizer=pseudonymizer,  # type: ignore[arg-type]
            )


def test_logger_rejects_invalid_pseudonymizer_even_without_fingerprint_events() -> None:
    with pytest.raises(LoggingError, match="MH_LOG_FINGERPRINT"):
        StructuredLogger(
            catalog=(_DEBUG,),
            clock=_clock(),
            sink=_CapturingSink(),
            pseudonymizer=object(),  # type: ignore[arg-type]
        )


def test_fingerprint_input_cannot_supply_a_prebuilt_token_or_wrong_type() -> None:
    runtime_token = "mh_fp1_e1_logging_" + ("a" * 52)
    event = _logger().emit(_COMPLETED, fingerprint_value=runtime_token)

    assert event is not None
    assert event.fingerprint is not None
    assert event.fingerprint != runtime_token
    assert runtime_token not in repr(event)

    with pytest.raises(LoggingError, match="MH_LOG_FINGERPRINT"):
        _logger().emit(_COMPLETED, fingerprint_value=b"raw")  # type: ignore[arg-type]


def test_fingerprint_failure_is_value_free_detached_and_capability_bound() -> None:
    runtime_canary = "runtime-private-fingerprint-78fb41"
    for value in ("", "bad\ud800value"):
        with pytest.raises(LoggingError) as captured:
            _logger().emit(_COMPLETED, fingerprint_value=value)
        assert captured.value.code == "MH_LOG_FINGERPRINT"
        if value:
            assert value not in str(captured.value)
        assert captured.value.__cause__ is None
        assert captured.value.__context__ is None

    with pytest.raises(LoggingError) as captured:
        _logger(minimum_level=LogLevel.DEBUG).emit(
            _DEBUG,
            fingerprint_value=runtime_canary,
        )
    assert captured.value.code == "MH_LOG_FINGERPRINT"
    assert runtime_canary not in str(captured.value)


@pytest.mark.parametrize(
    "catalog",
    [
        (),
        [],
        tuple(
            LogEventSpec(f"event_{index}", LogLevel.INFO)
            for index in range(MAX_LOG_CATALOG_EVENTS + 1)
        ),
        (object(),),
        (
            LogEventSpec("event.same", LogLevel.INFO),
            LogEventSpec("event.same", LogLevel.ERROR),
        ),
    ],
)
def test_logger_rejects_invalid_catalogs(catalog: object) -> None:
    with pytest.raises(LoggingError, match="MH_LOG_CATALOG"):
        _logger(catalog=catalog)  # type: ignore[arg-type]


def test_sink_failure_is_value_free_and_detached() -> None:
    runtime_canary = "runtime-secret-sink-96bcc9"

    class FailingSink:
        def write(self, _event: StructuredLogEventV1) -> None:
            raise RuntimeError(runtime_canary)

    with pytest.raises(LoggingError) as captured:
        _logger(FailingSink()).emit(_COMPLETED)

    assert captured.value.code == "MH_LOG_SINK"
    assert runtime_canary not in str(captured.value)
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None


@pytest.mark.parametrize("mode", ["raises", "returns_invalid"])
def test_clock_failure_is_value_free_and_detached(mode: str) -> None:
    runtime_canary = "runtime-secret-clock-bf5061"

    class FailingClock:
        def now(self) -> datetime:
            if mode == "raises":
                raise RuntimeError(runtime_canary)
            return runtime_canary  # type: ignore[return-value]

    with pytest.raises(LoggingError) as captured:
        _logger(clock=FailingClock()).emit(_COMPLETED)

    assert captured.value.code == "MH_LOG_CLOCK"
    assert runtime_canary not in str(captured.value)
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None


def test_base_exceptions_from_sink_are_not_converted() -> None:
    class InterruptingSink:
        def write(self, _event: StructuredLogEventV1) -> None:
            raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        _logger(InterruptingSink()).emit(_COMPLETED)


def test_logger_has_value_safe_repr_and_strict_minimum_level() -> None:
    class HostileSink:
        def __repr__(self) -> str:
            raise AssertionError("logger repr inspected its sink")

        def write(self, _event: StructuredLogEventV1) -> None:
            return None

    with pytest.raises(LoggingError, match="MH_LOG_LEVEL"):
        _logger(HostileSink(), minimum_level=20)  # type: ignore[arg-type]

    logger = _logger(HostileSink())
    assert repr(logger) == "StructuredLogger(minimum_level=INFO, catalog_events=2)"
