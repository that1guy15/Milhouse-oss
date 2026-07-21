"""Catalog-bound structured operational events with injected sinks and time."""

from __future__ import annotations

import math
import re
import threading
from dataclasses import dataclass
from datetime import datetime
from enum import Enum, IntEnum
from typing import Protocol, cast

from milhouse.core.canonical import MAX_CANONICAL_INT, MIN_CANONICAL_INT
from milhouse.core.clock import WallClock, format_timestamp, truncate_to_milliseconds
from milhouse.core.errors import (
    UNEXPECTED_ERROR_CODE,
    MilhouseValueError,
    NormalizedError,
    _validate_error_code,
    normalize_error,
)
from milhouse.privacy.pseudonym import (
    PrivacyError,
    Pseudonymizer,
    validate_pseudonym_kind,
)

MAX_LOG_CATALOG_EVENTS = 256
MAX_LOG_EVENT_NAME_BYTES = 128
MAX_LOG_METRIC_NAME_BYTES = 64
MAX_LOG_METRICS = 32
MAX_LOG_ERROR_CODES = 32
MAX_LOG_EVENT_METADATA_BYTES = 2_048

_MACHINE_NAME_PATTERN = re.compile(
    r"[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*",
    flags=re.ASCII,
)
_FINGERPRINT_PATTERN = re.compile(
    r"mh_fp1_e(?:[1-9][0-9]{0,9})_(?P<kind>[a-z][a-z0-9_-]{0,31})_[a-z2-7]{52}",
    flags=re.ASCII,
)


class LoggingError(MilhouseValueError):
    """A stable failure at the safe structured-logging boundary."""


class LogLevel(IntEnum):
    """Ordered internal event severity."""

    DEBUG = 10
    INFO = 20
    WARNING = 30
    ERROR = 40
    CRITICAL = 50


class LogMetricKind(Enum):
    """Code-owned semantic class for one privacy-safe operational measurement."""

    FLAG = "flag"
    COUNT = "count"
    BYTES = "bytes"
    DURATION_MILLISECONDS = "duration_milliseconds"
    GAUGE = "gauge"


def _validate_machine_name(value: object, *, maximum_bytes: int) -> str:
    if (
        type(value) is not str
        or not value
        or len(value) > maximum_bytes
        or _MACHINE_NAME_PATTERN.fullmatch(value) is None
    ):
        raise LoggingError("MH_LOG_NAME", "a bounded ASCII machine name is required")
    return value


@dataclass(frozen=True, slots=True)
class LogMetricSpec:
    """Developer-owned metric identity and semantic kind."""

    name: str
    kind: LogMetricKind

    def __post_init__(self) -> None:
        _validate_machine_name(self.name, maximum_bytes=MAX_LOG_METRIC_NAME_BYTES)
        if type(self.kind) is not LogMetricKind:
            raise LoggingError("MH_LOG_METRIC", "a supported metric kind is required")


@dataclass(frozen=True, slots=True)
class LogFingerprintSpec:
    """Developer-owned keyed-correlation kind allowed for one event."""

    kind: str

    def __post_init__(self) -> None:
        invalid_kind = False
        try:
            validate_pseudonym_kind(self.kind)
        except PrivacyError:
            invalid_kind = True
        if invalid_kind:
            raise LoggingError(
                "MH_LOG_FINGERPRINT",
                "a valid fingerprint kind is required",
            )


@dataclass(frozen=True, slots=True)
class LogMetric:
    """One runtime value bound to a developer-owned metric specification."""

    spec: LogMetricSpec
    value: bool | int | float

    def __post_init__(self) -> None:
        if type(self.spec) is not LogMetricSpec:
            raise LoggingError("MH_LOG_METRIC", "a validated metric specification is required")
        if self.spec.kind is LogMetricKind.FLAG:
            if type(self.value) is bool:
                return
            raise LoggingError("MH_LOG_METRIC", "a flag metric requires a boolean")
        if self.spec.kind in {
            LogMetricKind.COUNT,
            LogMetricKind.BYTES,
            LogMetricKind.DURATION_MILLISECONDS,
        }:
            if type(self.value) is int and 0 <= self.value <= MAX_CANONICAL_INT:
                return
            raise LoggingError("MH_LOG_METRIC", "a count metric requires a bounded integer")
        if type(self.value) is int and MIN_CANONICAL_INT <= self.value <= MAX_CANONICAL_INT:
            return
        if (
            type(self.value) is float
            and math.isfinite(self.value)
            and MIN_CANONICAL_INT <= self.value <= MAX_CANONICAL_INT
        ):
            return
        raise LoggingError("MH_LOG_METRIC", "a gauge metric requires a bounded finite number")


@dataclass(frozen=True, slots=True)
class LogEventSpec:
    """Developer-owned event contract registered with one logger catalog."""

    name: str
    level: LogLevel
    metrics: tuple[LogMetricSpec, ...] = ()
    error_codes: tuple[str, ...] = ()
    allow_unexpected_error: bool = False
    fingerprint: LogFingerprintSpec | None = None

    def __post_init__(self) -> None:
        _validate_machine_name(self.name, maximum_bytes=MAX_LOG_EVENT_NAME_BYTES)
        if type(self.level) is not LogLevel:
            raise LoggingError("MH_LOG_LEVEL", "a supported log level is required")
        if type(self.metrics) is not tuple or len(self.metrics) > MAX_LOG_METRICS:
            raise LoggingError("MH_LOG_SPEC", "event metric specifications exceed the safe bound")
        if any(type(metric) is not LogMetricSpec for metric in self.metrics):
            raise LoggingError("MH_LOG_SPEC", "validated metric specifications are required")
        ordered_metrics = tuple(
            sorted(self.metrics, key=lambda metric: metric.name.encode("ascii"))
        )
        if len({metric.name for metric in ordered_metrics}) != len(ordered_metrics):
            raise LoggingError("MH_LOG_SPEC", "event metric specification names must be unique")
        if type(self.error_codes) is not tuple or len(self.error_codes) > MAX_LOG_ERROR_CODES:
            raise LoggingError("MH_LOG_SPEC", "event error codes exceed the safe bound")
        ordered_codes: tuple[str, ...] | None = None
        try:
            ordered_codes = tuple(sorted(_validate_error_code(code) for code in self.error_codes))
        except ValueError:
            pass
        if ordered_codes is None:
            raise LoggingError("MH_LOG_SPEC", "event error codes must be stable codes")
        if len(set(ordered_codes)) != len(ordered_codes) or UNEXPECTED_ERROR_CODE in ordered_codes:
            raise LoggingError("MH_LOG_SPEC", "event error codes must be unique expected codes")
        if type(self.allow_unexpected_error) is not bool:
            raise LoggingError("MH_LOG_SPEC", "event capability flags must be booleans")
        if self.fingerprint is not None and type(self.fingerprint) is not LogFingerprintSpec:
            raise LoggingError("MH_LOG_SPEC", "a validated fingerprint specification is required")
        object.__setattr__(self, "metrics", ordered_metrics)
        object.__setattr__(self, "error_codes", ordered_codes)


def _derive_fingerprint(
    spec: LogEventSpec,
    pseudonymizer: Pseudonymizer | None,
    value: object,
) -> str | None:
    if value is None:
        return None
    if spec.fingerprint is None:
        raise LoggingError(
            "MH_LOG_FINGERPRINT",
            "event fingerprint is not allowed by its specification",
        )
    if type(pseudonymizer) is not Pseudonymizer:
        raise LoggingError("MH_LOG_FINGERPRINT", "a Milhouse pseudonymizer is required")
    if type(value) is not str:
        raise LoggingError("MH_LOG_FINGERPRINT", "fingerprint input must be text")
    try:
        token = pseudonymizer.fingerprint(spec.fingerprint.kind, value)
    except Exception:
        pass
    else:
        match = _FINGERPRINT_PATTERN.fullmatch(token) if type(token) is str else None
        if match is not None and match.group("kind") == spec.fingerprint.kind:
            return token
    raise LoggingError("MH_LOG_FINGERPRINT", "keyed fingerprint derivation failed")


def _prepare_metrics(
    spec: LogEventSpec,
    metrics: object,
) -> tuple[LogMetric, ...]:
    if type(metrics) is not tuple or len(metrics) > MAX_LOG_METRICS:
        raise LoggingError("MH_LOG_METRICS", "event metrics exceed the safe bound")
    if any(type(metric) is not LogMetric for metric in metrics):
        raise LoggingError("MH_LOG_METRICS", "validated event metrics are required")
    typed_metrics = cast(tuple[LogMetric, ...], metrics)
    if any(not any(metric.spec is allowed for allowed in spec.metrics) for metric in typed_metrics):
        raise LoggingError("MH_LOG_METRICS", "event metric is not allowed by its specification")
    ordered = tuple(sorted(typed_metrics, key=lambda metric: metric.spec.name.encode("ascii")))
    if len({metric.spec.name for metric in ordered}) != len(ordered):
        raise LoggingError("MH_LOG_METRICS", "event metric names must be unique")
    return ordered


def _prepare_error(spec: LogEventSpec, error: object) -> NormalizedError | None:
    if error is None:
        return None
    if not isinstance(error, BaseException):
        raise LoggingError("MH_LOG_ERROR", "an exception or no error is required")
    normalized = normalize_error(error)
    if normalized.expected and normalized.code in spec.error_codes:
        return normalized
    if spec.allow_unexpected_error:
        return normalize_error(Exception())
    raise LoggingError("MH_LOG_ERROR", "event error is not allowed by its specification")


@dataclass(frozen=True, slots=True, init=False)
class StructuredLogEventV1:
    """Catalog-built internal event with no arbitrary-text field or public wire format."""

    timestamp: datetime
    name: str
    level: LogLevel
    metrics: tuple[LogMetric, ...]
    error: NormalizedError | None
    fingerprint: str | None

    def __init__(self) -> None:
        raise TypeError("StructuredLogEventV1 values are built by StructuredLogger")

    @classmethod
    def _create(
        cls,
        *,
        timestamp: datetime,
        spec: LogEventSpec,
        metrics: object,
        error: object,
        fingerprint: str | None,
    ) -> StructuredLogEventV1:
        try:
            normalized_timestamp = truncate_to_milliseconds(timestamp)
        except Exception:
            pass
        else:
            prepared_metrics = _prepare_metrics(spec, metrics)
            prepared_error = _prepare_error(spec, error)
            prepared_fingerprint: str | None = None
            if fingerprint is not None:
                if spec.fingerprint is None:
                    raise LoggingError(
                        "MH_LOG_FINGERPRINT",
                        "event fingerprint is not allowed by its specification",
                    )
                match = _FINGERPRINT_PATTERN.fullmatch(fingerprint)
                if match is None or match.group("kind") != spec.fingerprint.kind:
                    raise LoggingError(
                        "MH_LOG_FINGERPRINT",
                        "event fingerprint derivation is invalid",
                    )
                prepared_fingerprint = fingerprint
            instance = object.__new__(cls)
            object.__setattr__(instance, "timestamp", normalized_timestamp)
            object.__setattr__(instance, "name", spec.name)
            object.__setattr__(instance, "level", spec.level)
            object.__setattr__(instance, "metrics", prepared_metrics)
            object.__setattr__(instance, "error", prepared_error)
            object.__setattr__(instance, "fingerprint", prepared_fingerprint)
            if instance._metadata_size() > MAX_LOG_EVENT_METADATA_BYTES:
                raise LoggingError("MH_LOG_SIZE", "event metadata exceeds the safe byte bound")
            return instance
        raise LoggingError("MH_LOG_TIMESTAMP", "a valid UTC event timestamp is required")

    def _metadata_size(self) -> int:
        size = len(format_timestamp(self.timestamp)) + len(self.name) + len(self.level.name)
        size += sum(
            len(metric.spec.name) + len(metric.spec.kind.value) + len(repr(metric.value))
            for metric in self.metrics
        )
        if self.error is not None:
            size += len(self.error.code) + 1
        if self.fingerprint is not None:
            size += len(self.fingerprint)
        return size


class StructuredLogSink(Protocol):
    """Injected destination for one already-safe event object."""

    def write(self, event: StructuredLogEventV1) -> None:
        """Consume one event without weakening its privacy contract."""


def _read_event_time(clock: WallClock) -> datetime:
    try:
        value = clock.now()
    except Exception:
        pass
    else:
        if type(value) is datetime:
            return value
    raise LoggingError("MH_LOG_CLOCK", "event clock read failed")


def _write_event(
    sink: StructuredLogSink,
    event: StructuredLogEventV1,
    lock: threading.Lock,
) -> None:
    try:
        with lock:
            sink.write(event)
    except Exception:
        pass
    else:
        return
    raise LoggingError("MH_LOG_SINK", "structured log sink write failed")


class StructuredLogger:
    """Build catalog-owned safe events without touching terminal or files directly."""

    __slots__ = (
        "_catalog",
        "_clock",
        "_lock",
        "_minimum_level",
        "_pseudonymizer",
        "_sink",
    )

    def __init__(
        self,
        *,
        catalog: tuple[LogEventSpec, ...],
        clock: WallClock,
        sink: StructuredLogSink,
        minimum_level: LogLevel = LogLevel.INFO,
        pseudonymizer: Pseudonymizer | None = None,
    ) -> None:
        if type(catalog) is not tuple or not 1 <= len(catalog) <= MAX_LOG_CATALOG_EVENTS:
            raise LoggingError("MH_LOG_CATALOG", "a bounded event catalog is required")
        if any(type(spec) is not LogEventSpec for spec in catalog):
            raise LoggingError("MH_LOG_CATALOG", "validated event specifications are required")
        if len({spec.name for spec in catalog}) != len(catalog):
            raise LoggingError("MH_LOG_CATALOG", "event catalog names must be unique")
        if type(minimum_level) is not LogLevel:
            raise LoggingError("MH_LOG_LEVEL", "a supported minimum log level is required")
        requires_pseudonymizer = any(spec.fingerprint is not None for spec in catalog)
        if requires_pseudonymizer and type(pseudonymizer) is not Pseudonymizer:
            raise LoggingError(
                "MH_LOG_FINGERPRINT",
                "catalog fingerprint events require a Milhouse pseudonymizer",
            )
        if pseudonymizer is not None and type(pseudonymizer) is not Pseudonymizer:
            raise LoggingError("MH_LOG_FINGERPRINT", "a Milhouse pseudonymizer is required")
        self._catalog = catalog
        self._clock = clock
        self._sink = sink
        self._minimum_level = minimum_level
        self._pseudonymizer = pseudonymizer
        self._lock = threading.Lock()

    def __repr__(self) -> str:
        return (
            "StructuredLogger("
            f"minimum_level={self._minimum_level.name}, catalog_events={len(self._catalog)})"
        )

    def emit(
        self,
        spec: LogEventSpec,
        *,
        metrics: tuple[LogMetric, ...] = (),
        error: BaseException | None = None,
        fingerprint_value: str | None = None,
    ) -> StructuredLogEventV1 | None:
        """Deliver one catalog-owned event, or ``None`` when its level is filtered."""

        if type(spec) is not LogEventSpec or not any(spec is allowed for allowed in self._catalog):
            raise LoggingError("MH_LOG_SPEC", "event specification is not in the logger catalog")
        if spec.level < self._minimum_level:
            return None
        fingerprint = _derive_fingerprint(
            spec,
            self._pseudonymizer,
            fingerprint_value,
        )
        event = StructuredLogEventV1._create(
            timestamp=_read_event_time(self._clock),
            spec=spec,
            metrics=metrics,
            error=error,
            fingerprint=fingerprint,
        )
        _write_event(self._sink, event, self._lock)
        return event


__all__ = [
    "MAX_LOG_CATALOG_EVENTS",
    "MAX_LOG_ERROR_CODES",
    "MAX_LOG_EVENT_METADATA_BYTES",
    "MAX_LOG_EVENT_NAME_BYTES",
    "MAX_LOG_METRICS",
    "MAX_LOG_METRIC_NAME_BYTES",
    "LogEventSpec",
    "LogFingerprintSpec",
    "LogLevel",
    "LogMetric",
    "LogMetricKind",
    "LogMetricSpec",
    "LoggingError",
    "StructuredLogEventV1",
    "StructuredLogSink",
    "StructuredLogger",
]
