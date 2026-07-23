"""Machine-checked lock for the exact v1 stored-log schema (plan section 4.15, amendment A05).

Each declared key, literal, scalar type, optionality rule, bound, digest-coverage rule, and the
`expires_at = opened_at + retention_days` deadline is pinned here as an exact normative vector. A
drift in any projection fails this test loudly rather than silently amending the v1 stored format.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from milhouse.config import ConfigError
from milhouse.core import FixedClock
from milhouse.core.log_wire import (
    MAX_EVENT_LINE_BYTES,
    MAX_HEADER_LINE_BYTES,
    MAX_LOG_RETENTION_DAYS,
    MAX_TRAILER_LINE_BYTES,
    StructuredLogHeaderV1,
    StructuredLogTrailerV1,
    structured_log_content_sha256,
    structured_log_event_line,
    structured_log_header_line,
    structured_log_trailer_line,
)
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

_MAX_SEQUENCE = 2**63 - 1
_OPENED = datetime(2026, 7, 21, 12, 0, 0, tzinfo=UTC)
_CLOSED = datetime(2026, 7, 21, 12, 5, 0, tzinfo=UTC)

# --- exact normative vectors (bytes are authoritative; they lock keys, order, and encoding) ---

HEADER_MIN = (
    b'{"line":"header","opened_at":"2026-07-21T12:00:00.000Z","retention_days":1,'
    b'"schema":1,"scope":"installation","sequence":1}\n'
)
HEADER_MAX = (
    b'{"line":"header","opened_at":"2026-07-21T12:00:00.000Z","retention_days":3650,'
    b'"schema":1,"scope":"installation","sequence":9223372036854775807}\n'
)
EVENT_MIN = (
    b'{"error":null,"fingerprint":null,"level":"INFO","line":"event",'
    b'"metrics":[{"kind":"count","name":"records","value":3}],'
    b'"name":"spool.commit","privacy":"internal","schema":1,"ts":"2026-07-21T12:00:00.000Z"}\n'
)
EVENT_WITH_ERROR = (
    b'{"error":"config.test.failure","fingerprint":null,"level":"WARNING","line":"event",'
    b'"metrics":[{"kind":"count","name":"records","value":2}],'
    b'"name":"spool.retry","privacy":"internal","schema":1,"ts":"2026-07-21T12:00:00.000Z"}\n'
)
EVENT_WITH_FINGERPRINT = (
    b'{"error":null,'
    b'"fingerprint":"mh_fp1_e1_logging_rxkst4phggffrqzxycoiak4uhzniugpo2mqab3k3qcnnadxby5bq",'
    b'"level":"ERROR","line":"event","metrics":[{"kind":"count","name":"records","value":1}],'
    b'"name":"spool.audit","privacy":"internal","schema":1,"ts":"2026-07-21T12:00:00.000Z"}\n'
)
DIGEST_NONEMPTY = "d55a50b936d6839c7935fa7921115268cf9f2769451a16ec35a99d13da3ad13e"
DIGEST_EMPTY = "1041a02a0cbf4138f49d4cab89cac3fcf6e0df9f7d2f0b29224832cb7957093a"
TRAILER_NONEMPTY = (
    b'{"closed_at":"2026-07-21T12:05:00.000Z",'
    b'"content_sha256":"' + DIGEST_NONEMPTY.encode() + b'",'
    b'"event_count":2,"expires_at":"2026-08-04T12:00:00.000Z",'
    b'"last_event_at":"2026-07-21T12:00:00.000Z","line":"trailer","schema":1,"sequence":1}\n'
)
TRAILER_EMPTY = (
    b'{"closed_at":"2026-07-21T12:05:00.000Z",'
    b'"content_sha256":"' + DIGEST_EMPTY.encode() + b'",'
    b'"event_count":0,"expires_at":"2026-08-04T12:00:00.000Z",'
    b'"last_event_at":null,"line":"trailer","schema":1,"sequence":2}\n'
)


class _Sink:
    def write(self, event: StructuredLogEventV1) -> None:
        return None


def _events() -> tuple[StructuredLogEventV1, StructuredLogEventV1, StructuredLogEventV1]:
    records = LogMetricSpec("records", LogMetricKind.COUNT)
    fingerprint = LogFingerprintSpec("logging")
    plain = LogEventSpec("spool.commit", LogLevel.INFO, metrics=(records,))
    with_error = LogEventSpec(
        "spool.retry", LogLevel.WARNING, metrics=(records,), error_codes=("config.test.failure",)
    )
    with_fingerprint = LogEventSpec(
        "spool.audit", LogLevel.ERROR, metrics=(records,), fingerprint=fingerprint
    )
    logger = StructuredLogger(
        catalog=(plain, with_error, with_fingerprint),
        clock=FixedClock(_OPENED),
        sink=_Sink(),
        pseudonymizer=Pseudonymizer(b"s" * 32),
        minimum_level=LogLevel.DEBUG,
    )
    event_min = logger.emit(plain, metrics=(LogMetric(records, 3),))
    event_err = logger.emit(
        with_error,
        metrics=(LogMetric(records, 2),),
        error=ConfigError("config.test.failure", "x"),
    )
    event_fp = logger.emit(
        with_fingerprint, metrics=(LogMetric(records, 1),), fingerprint_value="donor-1234"
    )
    assert event_min is not None and event_err is not None and event_fp is not None
    return event_min, event_err, event_fp


def test_header_projection_matches_the_normative_min_and_max_vectors() -> None:
    assert (
        structured_log_header_line(
            StructuredLogHeaderV1(sequence=1, opened_at=_OPENED, retention_days=1)
        )
        == HEADER_MIN
    )
    assert (
        structured_log_header_line(
            StructuredLogHeaderV1(
                sequence=_MAX_SEQUENCE, opened_at=_OPENED, retention_days=MAX_LOG_RETENTION_DAYS
            )
        )
        == HEADER_MAX
    )


def test_event_projection_matches_the_normative_vectors() -> None:
    event_min, event_err, event_fp = _events()
    assert structured_log_event_line(event_min) == EVENT_MIN
    assert structured_log_event_line(event_err) == EVENT_WITH_ERROR
    assert structured_log_event_line(event_fp) == EVENT_WITH_FINGERPRINT


def test_optional_values_are_explicit_null_never_omitted() -> None:
    # error and fingerprint are always present; a fingerprint is the keyed value, not raw input.
    event_min, _event_err, event_fp = _events()
    minimal = json.loads(structured_log_event_line(event_min))
    assert minimal["error"] is None
    assert minimal["fingerprint"] is None
    fingerprinted = json.loads(structured_log_event_line(event_fp))
    assert isinstance(fingerprinted["fingerprint"], str)
    assert b"donor-1234" not in structured_log_event_line(event_fp)
    # an empty trailer keeps last_event_at present and null, with a zero event_count.
    empty = json.loads(TRAILER_EMPTY)
    assert empty["event_count"] == 0
    assert empty["last_event_at"] is None


def test_trailer_projection_matches_the_nonempty_and_empty_vectors() -> None:
    header_line = structured_log_header_line(
        StructuredLogHeaderV1(sequence=1, opened_at=_OPENED, retention_days=14)
    )
    event_min, event_err, _event_fp = _events()
    event_lines = [structured_log_event_line(event_min), structured_log_event_line(event_err)]
    nonempty_digest = structured_log_content_sha256(header_line, event_lines)
    empty_digest = structured_log_content_sha256(header_line, [])
    assert nonempty_digest == DIGEST_NONEMPTY
    assert empty_digest == DIGEST_EMPTY

    assert (
        structured_log_trailer_line(
            StructuredLogTrailerV1(
                sequence=1,
                closed_at=_CLOSED,
                last_event_at=_OPENED,
                event_count=2,
                content_sha256=nonempty_digest,
                expires_at=_OPENED + timedelta(days=14),
            )
        )
        == TRAILER_NONEMPTY
    )
    assert (
        structured_log_trailer_line(
            StructuredLogTrailerV1(
                sequence=2,
                closed_at=_CLOSED,
                last_event_at=None,
                event_count=0,
                content_sha256=empty_digest,
                expires_at=_OPENED + timedelta(days=14),
            )
        )
        == TRAILER_EMPTY
    )


def test_expiry_deadline_is_opened_at_plus_retention_days() -> None:
    # Normative contract vector: expires_at = opened_at + retention_days days (W03 computes this;
    # W02 locks that the trailer field carries and encodes exactly that instant).
    retention_days = 14
    expected_expires = _OPENED + timedelta(days=retention_days)
    assert expected_expires == datetime(2026, 8, 4, 12, 0, 0, tzinfo=UTC)
    trailer = json.loads(TRAILER_NONEMPTY)
    assert trailer["expires_at"] == "2026-08-04T12:00:00.000Z"


def test_each_line_stays_within_its_declared_byte_bound() -> None:
    for header in (HEADER_MIN, HEADER_MAX):
        assert len(header) <= MAX_HEADER_LINE_BYTES
    for event in (EVENT_MIN, EVENT_WITH_ERROR, EVENT_WITH_FINGERPRINT):
        assert len(event) <= MAX_EVENT_LINE_BYTES
    for trailer in (TRAILER_NONEMPTY, TRAILER_EMPTY):
        assert len(trailer) <= MAX_TRAILER_LINE_BYTES
