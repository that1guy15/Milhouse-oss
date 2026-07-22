"""CanonicalJSONV1 stored projection of catalog-owned structured log events.

This is the W02-owned event-line wire: it maps a constructor-controlled
``StructuredLogEventV1`` to bounded CanonicalJSONV1 UTF-8 JSONL bytes with one trailing
line feed. It performs no file or sink I/O (that is W03) and carries no arbitrary-text or
exception-detail field.
"""

from __future__ import annotations

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


__all__ = [
    "MAX_EVENT_LINE_BYTES",
    "STRUCTURED_LOG_LINE_EVENT",
    "STRUCTURED_LOG_PRIVACY_CLASS",
    "STRUCTURED_LOG_SCHEMA_VERSION",
    "structured_log_event_line",
]
