from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from datetime import UTC, datetime

from milhouse.config import ConfigError
from milhouse.core import FixedClock
from milhouse.core.log_wire import (
    StructuredLogHeaderV1,
    StructuredLogTrailerV1,
    structured_log_content_sha256,
    structured_log_event_line,
    structured_log_header_line,
    structured_log_trailer_line,
)
from milhouse.core.logging import (
    LogEventSpec,
    LogLevel,
    LogMetric,
    LogMetricKind,
    LogMetricSpec,
    StructuredLogEventV1,
    StructuredLogger,
)

MAX_CHILD_OUTPUT_BYTES = 8 * 1024
CHILD_TIMEOUT_SECONDS = 10

# (PYTHONHASHSEED, locale, timezone) — byte output must be identical across all of them.
RUN_ENVIRONMENTS = (
    ("0", "C", "UTC0"),
    ("1", "en_US.UTF-8", "EST5EDT"),
    ("314159", "POSIX", "GMT0"),
)

# Fingerprint-free golden so the exact bytes are hand-verifiable and byte-stable.
GOLDEN_WIRE = (
    b'{"error":null,"fingerprint":null,"level":"INFO","line":"event",'
    b'"metrics":[{"kind":"count","name":"records","value":3}],'
    b'"name":"spool.commit","privacy":"internal","schema":1,'
    b'"ts":"2026-07-21T12:00:00.000Z"}\n'
    b'{"error":"config.test.failure","fingerprint":null,"level":"WARNING",'
    b'"line":"event","metrics":[{"kind":"count","name":"attempts","value":2}],'
    b'"name":"spool.retry","privacy":"internal","schema":1,'
    b'"ts":"2026-07-21T12:00:00.000Z"}\n'
)

CHILD_SCRIPT = r"""
import os
import sys
from datetime import datetime, timezone


class WireFailure(Exception):
    pass


def main():
    if len(sys.argv) != 2 or not sys.flags.safe_path or not sys.flags.no_user_site:
        raise WireFailure
    if os.environ.get("PYTHONHASHSEED") != sys.argv[1]:
        raise WireFailure

    import locale
    import time

    locale.setlocale(locale.LC_ALL, "")
    if hasattr(time, "tzset"):
        time.tzset()

    from milhouse.config import ConfigError
    from milhouse.core import FixedClock
    from milhouse.core.log_wire import structured_log_event_line
    from milhouse.core.logging import (
        LogEventSpec,
        LogLevel,
        LogMetric,
        LogMetricKind,
        LogMetricSpec,
        StructuredLogger,
    )

    records = LogMetricSpec("records", LogMetricKind.COUNT)
    attempts = LogMetricSpec("attempts", LogMetricKind.COUNT)
    commit = LogEventSpec("spool.commit", LogLevel.INFO, metrics=(records,))
    retry = LogEventSpec(
        "spool.retry",
        LogLevel.WARNING,
        metrics=(attempts,),
        error_codes=("config.test.failure",),
    )

    class _Sink:
        def write(self, _event):
            return None

    logger = StructuredLogger(
        catalog=(commit, retry),
        clock=FixedClock(datetime(2026, 7, 21, 12, 0, 0, tzinfo=timezone.utc)),
        sink=_Sink(),
        minimum_level=LogLevel.DEBUG,
    )
    event_a = logger.emit(commit, metrics=(LogMetric(records, 3),))
    event_b = logger.emit(
        retry,
        metrics=(LogMetric(attempts, 2),),
        error=ConfigError("config.test.failure", "synthetic retry"),
    )
    if event_a is None or event_b is None:
        raise WireFailure

    output = structured_log_event_line(event_a) + structured_log_event_line(event_b)
    if len(output) > 8 * 1024:
        raise WireFailure
    sys.stdout.buffer.write(output)


try:
    main()
except BaseException:
    raise SystemExit(70) from None
"""


class _Sink:
    def write(self, event: StructuredLogEventV1) -> None:
        return None


def _build_in_process() -> bytes:
    records = LogMetricSpec("records", LogMetricKind.COUNT)
    attempts = LogMetricSpec("attempts", LogMetricKind.COUNT)
    commit = LogEventSpec("spool.commit", LogLevel.INFO, metrics=(records,))
    retry = LogEventSpec(
        "spool.retry",
        LogLevel.WARNING,
        metrics=(attempts,),
        error_codes=("config.test.failure",),
    )
    logger = StructuredLogger(
        catalog=(commit, retry),
        clock=FixedClock(datetime(2026, 7, 21, 12, 0, 0, tzinfo=UTC)),
        sink=_Sink(),
        minimum_level=LogLevel.DEBUG,
    )
    event_a = logger.emit(commit, metrics=(LogMetric(records, 3),))
    event_b = logger.emit(
        retry,
        metrics=(LogMetric(attempts, 2),),
        error=ConfigError("config.test.failure", "synthetic retry"),
    )
    assert event_a is not None
    assert event_b is not None
    return structured_log_event_line(event_a) + structured_log_event_line(event_b)


def test_golden_wire_matches_the_in_process_projection() -> None:
    assert _build_in_process() == GOLDEN_WIRE


def _run_child_outputs(script: str) -> list[bytes]:
    outputs: list[bytes] = []
    for run_number, (hash_seed, selected_locale, timezone_name) in enumerate(
        RUN_ENVIRONMENTS,
        start=1,
    ):
        child_environment = {
            "LC_ALL": selected_locale,
            "LANG": selected_locale,
            "TZ": timezone_name,
            "PYTHONHASHSEED": hash_seed,
            "PYTHONIOENCODING": "utf-8",
            "PYTHONNOUSERSITE": "1",
            "PYTHONUTF8": "1",
        }
        if "PATH" in os.environ:
            child_environment["PATH"] = os.environ["PATH"]
        with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
            try:
                completed = subprocess.run(
                    [sys.executable, "-s", "-P", "-c", script, hash_seed],
                    stdout=stdout_file,
                    stderr=stderr_file,
                    check=False,
                    env=child_environment,
                    timeout=CHILD_TIMEOUT_SECONDS,
                )
            except subprocess.TimeoutExpired:
                raise AssertionError(f"log-wire child run {run_number} timed out") from None
            except OSError:
                raise AssertionError(f"log-wire child run {run_number} could not start") from None

            stdout_size = os.fstat(stdout_file.fileno()).st_size
            stderr_size = os.fstat(stderr_file.fileno()).st_size
            stdout_file.seek(0)
            stderr_file.seek(0)
            child_stdout = stdout_file.read(MAX_CHILD_OUTPUT_BYTES + 1)
            child_stderr = stderr_file.read(MAX_CHILD_OUTPUT_BYTES + 1)

        assert stdout_size <= MAX_CHILD_OUTPUT_BYTES, f"run {run_number} exceeded the stdout bound"
        assert stderr_size <= MAX_CHILD_OUTPUT_BYTES, f"run {run_number} exceeded the stderr bound"
        assert completed.returncode == 0, f"log-wire child run {run_number} failed"
        assert child_stderr == b"", f"log-wire child run {run_number} wrote to stderr"
        outputs.append(child_stdout)
    return outputs


def test_wire_bytes_are_portable_across_isolated_process_environments() -> None:
    outputs = _run_child_outputs(CHILD_SCRIPT)
    for run_number, output in enumerate(outputs, start=1):
        assert output == GOLDEN_WIRE, f"log-wire child run {run_number} did not match golden"
    assert all(output == outputs[0] for output in outputs[1:])


def _build_segment() -> bytes:
    records = LogMetricSpec("records", LogMetricKind.COUNT)
    attempts = LogMetricSpec("attempts", LogMetricKind.COUNT)
    commit = LogEventSpec("spool.commit", LogLevel.INFO, metrics=(records,))
    retry = LogEventSpec(
        "spool.retry",
        LogLevel.WARNING,
        metrics=(attempts,),
        error_codes=("config.test.failure",),
    )
    logger = StructuredLogger(
        catalog=(commit, retry),
        clock=FixedClock(datetime(2026, 7, 21, 12, 0, 0, tzinfo=UTC)),
        sink=_Sink(),
        minimum_level=LogLevel.DEBUG,
    )
    event_a = logger.emit(commit, metrics=(LogMetric(records, 3),))
    event_b = logger.emit(
        retry,
        metrics=(LogMetric(attempts, 2),),
        error=ConfigError("config.test.failure", "synthetic retry"),
    )
    assert event_a is not None
    assert event_b is not None
    event_lines = [structured_log_event_line(event_a), structured_log_event_line(event_b)]
    header_line = structured_log_header_line(
        StructuredLogHeaderV1(
            sequence=1,
            opened_at=datetime(2026, 7, 21, 12, 0, 0, tzinfo=UTC),
            retention_days=14,
        )
    )
    trailer_line = structured_log_trailer_line(
        StructuredLogTrailerV1(
            sequence=1,
            closed_at=datetime(2026, 7, 21, 12, 5, 0, tzinfo=UTC),
            last_event_at=datetime(2026, 7, 21, 12, 0, 0, tzinfo=UTC),
            event_count=2,
            content_sha256=structured_log_content_sha256(header_line, event_lines),
            expires_at=datetime(2026, 8, 4, 12, 0, 0, tzinfo=UTC),
        )
    )
    return header_line + b"".join(event_lines) + trailer_line


SEGMENT_CHILD_SCRIPT = r"""
import os
import sys
from datetime import datetime, timezone


class WireFailure(Exception):
    pass


def main():
    if len(sys.argv) != 2 or not sys.flags.safe_path or not sys.flags.no_user_site:
        raise WireFailure
    if os.environ.get("PYTHONHASHSEED") != sys.argv[1]:
        raise WireFailure

    import locale
    import time

    locale.setlocale(locale.LC_ALL, "")
    if hasattr(time, "tzset"):
        time.tzset()

    from milhouse.config import ConfigError
    from milhouse.core import FixedClock
    from milhouse.core.log_wire import (
        StructuredLogHeaderV1,
        StructuredLogTrailerV1,
        structured_log_content_sha256,
        structured_log_event_line,
        structured_log_header_line,
        structured_log_trailer_line,
    )
    from milhouse.core.logging import (
        LogEventSpec,
        LogLevel,
        LogMetric,
        LogMetricKind,
        LogMetricSpec,
        StructuredLogger,
    )

    utc = timezone.utc
    records = LogMetricSpec("records", LogMetricKind.COUNT)
    attempts = LogMetricSpec("attempts", LogMetricKind.COUNT)
    commit = LogEventSpec("spool.commit", LogLevel.INFO, metrics=(records,))
    retry = LogEventSpec(
        "spool.retry",
        LogLevel.WARNING,
        metrics=(attempts,),
        error_codes=("config.test.failure",),
    )

    class _Sink:
        def write(self, _event):
            return None

    logger = StructuredLogger(
        catalog=(commit, retry),
        clock=FixedClock(datetime(2026, 7, 21, 12, 0, 0, tzinfo=utc)),
        sink=_Sink(),
        minimum_level=LogLevel.DEBUG,
    )
    event_a = logger.emit(commit, metrics=(LogMetric(records, 3),))
    event_b = logger.emit(
        retry,
        metrics=(LogMetric(attempts, 2),),
        error=ConfigError("config.test.failure", "synthetic retry"),
    )
    if event_a is None or event_b is None:
        raise WireFailure

    event_lines = [structured_log_event_line(event_a), structured_log_event_line(event_b)]
    header_line = structured_log_header_line(
        StructuredLogHeaderV1(
            sequence=1, opened_at=datetime(2026, 7, 21, 12, 0, 0, tzinfo=utc), retention_days=14
        )
    )
    trailer_line = structured_log_trailer_line(
        StructuredLogTrailerV1(
            sequence=1,
            closed_at=datetime(2026, 7, 21, 12, 5, 0, tzinfo=utc),
            last_event_at=datetime(2026, 7, 21, 12, 0, 0, tzinfo=utc),
            event_count=2,
            content_sha256=structured_log_content_sha256(header_line, event_lines),
            expires_at=datetime(2026, 8, 4, 12, 0, 0, tzinfo=utc),
        )
    )
    output = header_line + b"".join(event_lines) + trailer_line
    if len(output) > 8 * 1024:
        raise WireFailure
    sys.stdout.buffer.write(output)


try:
    main()
except BaseException:
    raise SystemExit(70) from None
"""


def test_full_segment_is_portable_across_isolated_process_environments() -> None:
    expected = _build_segment()
    assert expected.count(b"\n") == 4  # header + two events + trailer
    outputs = _run_child_outputs(SEGMENT_CHILD_SCRIPT)
    for run_number, output in enumerate(outputs, start=1):
        assert output == expected, (
            f"segment child run {run_number} did not match the in-process segment"
        )
    assert all(output == outputs[0] for output in outputs[1:])
