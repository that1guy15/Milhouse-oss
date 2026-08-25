"""CanonicalJSONV1 stored projections for the W02 structured-log wire.

This is the W02-owned wire: it maps constructor-controlled header, event, and trailer values to
bounded CanonicalJSONV1 UTF-8 JSONL bytes with one trailing line feed, derives the segment
``content_sha256`` over the header plus ordered event lines, and provides the injected-stream
``StreamLogSink`` that emits those exact bytes. It performs no file I/O, rotation, or persistence
(that is W03) and carries no arbitrary-text or exception-detail field.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import threading
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import NoReturn, Protocol

from milhouse.core.canonical import (
    MAX_CANONICAL_INT,
    MIN_CANONICAL_INT,
    CanonicalizationError,
    canonical_json_bytes,
)
from milhouse.core.clock import truncate_to_milliseconds
from milhouse.core.errors import _validate_error_code
from milhouse.core.logging import (
    _FINGERPRINT_PATTERN,
    MAX_LOG_EVENT_NAME_BYTES,
    MAX_LOG_METRIC_NAME_BYTES,
    MAX_LOG_METRICS,
    LoggingError,
    LogLevel,
    LogMetricKind,
    StructuredLogEventV1,
    _validate_machine_name,
)
from milhouse.domain.records import PrivacyClassV1
from milhouse.privacy.egress import EgressDisposition, EgressSurface, require_egress

STRUCTURED_LOG_SCHEMA_VERSION = 1
STRUCTURED_LOG_LINE_EVENT = "event"
STRUCTURED_LOG_LINE_HEADER = "header"
STRUCTURED_LOG_LINE_TRAILER = "trailer"
STRUCTURED_LOG_INSTALLATION_SCOPE = "installation"
STRUCTURED_LOG_PRIVACY_CLASS: PrivacyClassV1 = "internal"
MAX_EVENT_LINE_BYTES = 4_096
MAX_HEADER_LINE_BYTES = 1_024
MAX_TRAILER_LINE_BYTES = 1_024
# Must equal the config `[retention].logs_days` upper bound (see tests/unit/test_log_framing.py).
MAX_LOG_RETENTION_DAYS = 3_650

_LINE_FEED = b"\n"
_SHA256_HEX_PATTERN = re.compile(r"[0-9a-f]{64}", flags=re.ASCII)


def _authorize_local_log() -> None:
    """Fail closed unless the local_log surface still authorizes internal metadata.

    The stored log wire exists only because the binding egress matrix authorizes internal
    operational metadata on the ``local_log`` surface. If a future matrix change denied or
    widened that authorization, projection stops here rather than emitting bytes.
    """

    disposition = require_egress(
        surface=EgressSurface.LOCAL_LOG,
        privacy_class=STRUCTURED_LOG_PRIVACY_CLASS,
    )
    if disposition is not EgressDisposition.REDACTED_METADATA:
        raise LoggingError(
            "MH_LOG_WIRE_EGRESS",
            "local_log authorization is not internal metadata",
        )


def structured_log_event_line(event: StructuredLogEventV1) -> bytes:
    """Project one event into a bounded CanonicalJSONV1 JSONL line with a trailing LF."""

    if type(event) is not StructuredLogEventV1:
        raise LoggingError("MH_LOG_WIRE_EVENT", "a StructuredLogEventV1 is required")
    _authorize_local_log()

    payload: dict[str, object] = {
        "schema": STRUCTURED_LOG_SCHEMA_VERSION,
        "line": STRUCTURED_LOG_LINE_EVENT,
        "privacy": STRUCTURED_LOG_PRIVACY_CLASS,
        "ts": event.timestamp,
        "name": event.name,
        "level": event.level.name,
        "metrics": [
            {
                "kind": metric.spec.kind.value,
                "name": metric.spec.name,
                "value": metric.value,
            }
            for metric in event.metrics
        ],
        "error": event.error.code if event.error is not None else None,
        "fingerprint": event.fingerprint,
    }

    # Reserve one byte for the trailing line feed so the full line, including its LF,
    # never exceeds the section 4.15 bound.
    encoded = canonical_json_bytes(payload, max_bytes=MAX_EVENT_LINE_BYTES - len(_LINE_FEED))
    return encoded + _LINE_FEED


_EVENT_LINE_KEYS = frozenset(
    {"error", "fingerprint", "level", "line", "metrics", "name", "privacy", "schema", "ts"}
)
_METRIC_KEYS = frozenset({"kind", "name", "value"})


def _event_fail(message: str) -> NoReturn:
    """Raise a fixed, value-free stored-event failure; no offending byte reaches the message."""

    raise LoggingError("MH_LOG_WIRE_EVENT", message)


def _parse_wire_event_timestamp(value: object) -> datetime:
    parsed: datetime | None = None
    if type(value) is str:
        try:
            parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)
        except ValueError:
            parsed = None
    if type(parsed) is not datetime:
        _event_fail("an event timestamp is not a canonical UTC millisecond value")
    return _normalized_utc(parsed, "MH_LOG_WIRE_EVENT")


def _require_wire_metric_value(kind: LogMetricKind, value: object) -> None:
    if kind is LogMetricKind.FLAG:
        if type(value) is bool:
            return
        _event_fail("a flag metric requires a boolean")
    if kind in {LogMetricKind.COUNT, LogMetricKind.BYTES, LogMetricKind.DURATION_MILLISECONDS}:
        if type(value) is int and 0 <= value <= MAX_CANONICAL_INT:
            return
        _event_fail("a count metric requires a bounded non-negative integer")
    if type(value) is int and MIN_CANONICAL_INT <= value <= MAX_CANONICAL_INT:
        return
    if (
        type(value) is float
        and math.isfinite(value)
        and MIN_CANONICAL_INT <= value <= MAX_CANONICAL_INT
    ):
        return
    _event_fail("a gauge metric requires a bounded finite number")


def _validate_wire_event_metrics(value: object) -> list[dict[str, object]]:
    if type(value) is not list or len(value) > MAX_LOG_METRICS:
        _event_fail("event metrics are not a bounded array")
    rebuilt: list[dict[str, object]] = []
    previous_key: bytes | None = None
    for item in value:
        if type(item) is not dict or frozenset(item) != _METRIC_KEYS:
            _event_fail("an event metric has an unexpected field set")
        kind_value = item["kind"]
        kind: LogMetricKind | None = None
        if type(kind_value) is str:
            try:
                kind = LogMetricKind(kind_value)
            except ValueError:
                kind = None
        if kind is None:
            _event_fail("an event metric kind is not supported")
        name: str | None = None
        try:
            name = _validate_machine_name(item["name"], maximum_bytes=MAX_LOG_METRIC_NAME_BYTES)
        except LoggingError:
            name = None
        if name is None:
            _event_fail("an event metric name is not a valid machine name")
        _require_wire_metric_value(kind, item["value"])
        key = name.encode("ascii")
        if previous_key is not None and key <= previous_key:
            _event_fail("event metrics must be sorted by unique name")
        previous_key = key
        rebuilt.append({"kind": kind.value, "name": name, "value": item["value"]})
    return rebuilt


def validate_structured_log_event_line(line: bytes) -> datetime:
    """Validate one complete stored event line against the exact CanonicalJSONV1/A05 contract.

    Enforces the field set, envelope, and every A05 scalar, enum (``LogLevel`` name), machine name,
    metric shape/type/order, coded nullable error, and nullable keyed fingerprint rule, then
    requires the line to equal the exact canonical bytes the encoder would produce for the same
    values — a full round-trip that also proves key order, spacing, and minimal number/timestamp
    form. Returns the event timestamp. Fails closed with a fixed value-free :class:`LoggingError`;
    recovery repairs only a torn tail, so a complete malformed line is rejected here, not stored.

    The persistence boundary validates the wire GRAMMAR (a ``LogLevel`` member and a valid machine
    name), never live-catalog registration: a durable 14-day log is read back across upgrades whose
    in-memory catalog may differ, so its validity must not depend on mutable runtime state.
    """

    if type(line) is not bytes:
        _event_fail("an event line must be bytes")
    if len(line) > MAX_EVENT_LINE_BYTES:
        _event_fail("an event line exceeds its byte bound")
    payload: object = None
    decoded = False
    try:
        payload = json.loads(line.decode("utf-8"))
        decoded = True
    except (UnicodeDecodeError, ValueError, RecursionError):
        decoded = False
    if not decoded or type(payload) is not dict:
        _event_fail("an event line must be one JSON object")
    if frozenset(payload) != _EVENT_LINE_KEYS:
        _event_fail("an event line has an unexpected field set")
    if (
        payload["schema"] != STRUCTURED_LOG_SCHEMA_VERSION
        or payload["line"] != STRUCTURED_LOG_LINE_EVENT
        or payload["privacy"] != STRUCTURED_LOG_PRIVACY_CLASS
    ):
        _event_fail("an event line is not a v1 internal event")

    timestamp = _parse_wire_event_timestamp(payload["ts"])

    name: str | None = None
    try:
        name = _validate_machine_name(payload["name"], maximum_bytes=MAX_LOG_EVENT_NAME_BYTES)
    except LoggingError:
        name = None
    if name is None:
        _event_fail("an event name is not a valid machine name")

    level_value = payload["level"]
    level: LogLevel | None = None
    if type(level_value) is str:
        try:
            level = LogLevel[level_value]
        except KeyError:
            level = None
    if level is None:
        _event_fail("an event level is not a catalog level")

    metrics = _validate_wire_event_metrics(payload["metrics"])

    error_code = payload["error"]
    if error_code is not None:
        valid_code: str | None = None
        if type(error_code) is str:
            try:
                valid_code = _validate_error_code(error_code)
            except ValueError:
                valid_code = None
        if valid_code is None:
            _event_fail("an event error is not a stable code")

    fingerprint = payload["fingerprint"]
    if fingerprint is not None and (
        type(fingerprint) is not str or _FINGERPRINT_PATTERN.fullmatch(fingerprint) is None
    ):
        _event_fail("an event fingerprint is not a valid keyed token")

    rebuilt: dict[str, object] = {
        "schema": STRUCTURED_LOG_SCHEMA_VERSION,
        "line": STRUCTURED_LOG_LINE_EVENT,
        "privacy": STRUCTURED_LOG_PRIVACY_CLASS,
        "ts": timestamp,
        "name": name,
        "level": level.name,
        "metrics": metrics,
        "error": error_code,
        "fingerprint": fingerprint,
    }
    canonical: bytes | None = None
    try:
        canonical = canonical_json_bytes(rebuilt, max_bytes=MAX_EVENT_LINE_BYTES - len(_LINE_FEED))
    except CanonicalizationError:
        canonical = None
    if canonical is None or canonical + _LINE_FEED != line:
        _event_fail("an event line is not canonical")
    return timestamp


def _validate_sequence(value: object) -> None:
    if type(value) is not int or not 0 < value <= MAX_CANONICAL_INT:
        raise LoggingError("MH_LOG_SEQUENCE", "a positive signed-64 sequence is required")


def _normalized_utc(value: object, code: str) -> datetime:
    """Normalize an aware timestamp to a safe UTC value, failing closed on hostile ``tzinfo``.

    A hostile ``tzinfo`` whose ``utcoffset`` raises never reaches an exception or traceback: it is
    caught here and a fixed ``LoggingError`` is raised outside the handler with no cause or context.
    """

    normalized: datetime | None = None
    if type(value) is datetime:
        try:
            if value.tzinfo is not None and value.utcoffset() is not None:
                normalized = truncate_to_milliseconds(value)
        except Exception:
            normalized = None
    if type(normalized) is not datetime:
        raise LoggingError(code, "an aware UTC timestamp is required")
    return normalized


@dataclass(frozen=True, slots=True)
class StructuredLogHeaderV1:
    """Constructor-controlled header opening one stored structured-log segment."""

    sequence: int
    opened_at: datetime
    retention_days: int

    def __post_init__(self) -> None:
        _validate_sequence(self.sequence)
        object.__setattr__(self, "opened_at", _normalized_utc(self.opened_at, "MH_LOG_HEADER_TIME"))
        if (
            type(self.retention_days) is not int
            or not 1 <= self.retention_days <= MAX_LOG_RETENTION_DAYS
        ):
            raise LoggingError(
                "MH_LOG_HEADER_RETENTION", "a bounded positive retention is required"
            )


@dataclass(frozen=True, slots=True)
class StructuredLogTrailerV1:
    """Constructor-controlled trailer closing one stored structured-log segment."""

    sequence: int
    closed_at: datetime
    last_event_at: datetime | None
    event_count: int
    content_sha256: str
    expires_at: datetime

    def __post_init__(self) -> None:
        _validate_sequence(self.sequence)
        object.__setattr__(
            self, "closed_at", _normalized_utc(self.closed_at, "MH_LOG_TRAILER_TIME")
        )
        object.__setattr__(
            self, "expires_at", _normalized_utc(self.expires_at, "MH_LOG_TRAILER_TIME")
        )
        if type(self.event_count) is not int or not 0 <= self.event_count <= MAX_CANONICAL_INT:
            raise LoggingError("MH_LOG_TRAILER_COUNT", "a bounded event count is required")
        if (
            type(self.content_sha256) is not str
            or _SHA256_HEX_PATTERN.fullmatch(self.content_sha256) is None
        ):
            raise LoggingError(
                "MH_LOG_TRAILER_DIGEST", "a lowercase hex sha-256 digest is required"
            )
        if self.event_count == 0:
            if self.last_event_at is not None:
                raise LoggingError(
                    "MH_LOG_TRAILER_EVENT_TIME", "an empty segment has no last-event time"
                )
        else:
            object.__setattr__(
                self,
                "last_event_at",
                _normalized_utc(self.last_event_at, "MH_LOG_TRAILER_EVENT_TIME"),
            )


def structured_log_header_line(header: StructuredLogHeaderV1) -> bytes:
    """Project a header into a bounded CanonicalJSONV1 JSONL line with a trailing LF."""

    if type(header) is not StructuredLogHeaderV1:
        raise LoggingError("MH_LOG_HEADER", "a StructuredLogHeaderV1 is required")
    _authorize_local_log()

    payload: dict[str, object] = {
        "schema": STRUCTURED_LOG_SCHEMA_VERSION,
        "line": STRUCTURED_LOG_LINE_HEADER,
        "scope": STRUCTURED_LOG_INSTALLATION_SCOPE,
        "sequence": header.sequence,
        "opened_at": header.opened_at,
        "retention_days": header.retention_days,
    }
    encoded = canonical_json_bytes(payload, max_bytes=MAX_HEADER_LINE_BYTES - len(_LINE_FEED))
    return encoded + _LINE_FEED


def structured_log_trailer_line(trailer: StructuredLogTrailerV1) -> bytes:
    """Project a trailer into a bounded CanonicalJSONV1 JSONL line with a trailing LF."""

    if type(trailer) is not StructuredLogTrailerV1:
        raise LoggingError("MH_LOG_TRAILER", "a StructuredLogTrailerV1 is required")
    _authorize_local_log()

    payload: dict[str, object] = {
        "schema": STRUCTURED_LOG_SCHEMA_VERSION,
        "line": STRUCTURED_LOG_LINE_TRAILER,
        "sequence": trailer.sequence,
        "closed_at": trailer.closed_at,
        "last_event_at": trailer.last_event_at,
        "event_count": trailer.event_count,
        "content_sha256": trailer.content_sha256,
        "expires_at": trailer.expires_at,
    }
    encoded = canonical_json_bytes(payload, max_bytes=MAX_TRAILER_LINE_BYTES - len(_LINE_FEED))
    return encoded + _LINE_FEED


def structured_log_content_sha256(header_line: bytes, event_lines: Iterable[bytes]) -> str:
    """Return the hex SHA-256 over the header line plus the ordered event lines.

    Covers the exact header and event-line bytes including their line feeds and excludes the
    trailer, per section 4.15.
    """

    if type(header_line) is not bytes:
        raise LoggingError("MH_LOG_DIGEST", "the header line must be bytes")
    digest = hashlib.sha256()
    digest.update(header_line)
    # Consume the caller-supplied iterable under a normalization boundary so a hostile
    # __iter__/__next__ cannot leak raw exception text into an exception or traceback.
    failed = False
    try:
        for line in event_lines:
            if type(line) is not bytes:
                failed = True
                break
            digest.update(line)
    except Exception:
        failed = True
    if failed:
        raise LoggingError("MH_LOG_DIGEST", "the event lines are invalid")
    return digest.hexdigest()


class _BinaryStream(Protocol):
    def write(self, data: bytes, /) -> object:
        """Write raw bytes to the underlying stream."""


class StreamLogSink:
    """A ``StructuredLogSink`` that writes exact event-line bytes to an injected binary stream.

    W02 owns the sink interface and the exact bytes. Binding a concrete stream (for example
    ``sys.stderr.buffer``) and any flushing or buffering policy are W06 responsibilities. The
    ``local_log`` egress guard runs inside ``structured_log_event_line`` before any byte is
    written, so a denied or widened matrix emits nothing.
    """

    __slots__ = ("_lock", "_stream")

    def __init__(self, stream: _BinaryStream) -> None:
        writable = False
        try:
            writable = callable(getattr(stream, "write", None))
        except Exception:
            writable = False
        if not writable:
            raise LoggingError("MH_LOG_SINK_STREAM", "a writable binary stream is required")
        self._stream = stream
        self._lock = threading.Lock()

    def write(self, event: StructuredLogEventV1) -> None:
        if type(event) is not StructuredLogEventV1:
            raise LoggingError("MH_LOG_SINK_EVENT", "a StructuredLogEventV1 is required")
        # Projection and its local_log egress guard run outside the stream-write handler so their
        # fixed-code errors are never masked or normalized away.
        line = structured_log_event_line(event)
        if not self._write_all(line):
            # Raised outside any exception handler: both __cause__ and __context__ stay empty, so no
            # stream-originated detail is reachable through the exception object.
            raise LoggingError("MH_LOG_SINK_WRITE", "structured log sink stream write failed")

    def _write_all(self, line: bytes) -> bool:
        """Write the whole line under the sink lock; never surface stream-originated detail.

        Returns ``True`` only when every byte was written exactly once. Any raised failure, or a
        return that is not a positive integer within the remaining length, fails closed so a
        partial, zero, or invalid write is never acknowledged as a complete event line. The lock
        keeps concurrent writers from interleaving one event line across retries.
        """

        total = len(line)
        offset = 0
        with self._lock:
            while offset < total:
                try:
                    written = self._stream.write(line[offset:])
                except Exception:
                    return False
                if type(written) is not int:
                    return False
                if not 0 < written <= total - offset:
                    return False
                offset += written
        return True


__all__ = [
    "MAX_EVENT_LINE_BYTES",
    "MAX_HEADER_LINE_BYTES",
    "MAX_LOG_RETENTION_DAYS",
    "MAX_TRAILER_LINE_BYTES",
    "STRUCTURED_LOG_INSTALLATION_SCOPE",
    "STRUCTURED_LOG_LINE_EVENT",
    "STRUCTURED_LOG_LINE_HEADER",
    "STRUCTURED_LOG_LINE_TRAILER",
    "STRUCTURED_LOG_PRIVACY_CLASS",
    "STRUCTURED_LOG_SCHEMA_VERSION",
    "StreamLogSink",
    "StructuredLogHeaderV1",
    "StructuredLogTrailerV1",
    "structured_log_content_sha256",
    "structured_log_event_line",
    "structured_log_header_line",
    "structured_log_trailer_line",
    "validate_structured_log_event_line",
]
