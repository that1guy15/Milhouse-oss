"""CanonicalJSONV1 stored projection of catalog-owned structured log events.

This is the W02-owned event-line wire: it maps a constructor-controlled
``StructuredLogEventV1`` to bounded CanonicalJSONV1 UTF-8 JSONL bytes with one trailing
line feed, plus the injected-stream ``StreamLogSink`` that emits those exact bytes. It performs no
file I/O, rotation, or persistence (that is W03) and carries no arbitrary-text or exception-detail
field.
"""

from __future__ import annotations

import threading
from typing import Protocol

from milhouse.core.canonical import canonical_json_bytes
from milhouse.core.logging import LoggingError, StructuredLogEventV1
from milhouse.domain.records import PrivacyClassV1
from milhouse.privacy.egress import EgressDisposition, EgressSurface, require_egress

STRUCTURED_LOG_SCHEMA_VERSION = 1
STRUCTURED_LOG_LINE_EVENT = "event"
STRUCTURED_LOG_PRIVACY_CLASS: PrivacyClassV1 = "internal"
MAX_EVENT_LINE_BYTES = 4_096

_LINE_FEED = b"\n"


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
    "STRUCTURED_LOG_LINE_EVENT",
    "STRUCTURED_LOG_PRIVACY_CLASS",
    "STRUCTURED_LOG_SCHEMA_VERSION",
    "StreamLogSink",
    "structured_log_event_line",
]
