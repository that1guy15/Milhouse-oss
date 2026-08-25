from __future__ import annotations

import os
import subprocess
import sys
import tempfile

import pytest

_CANARY = "SYNTHETIC_SECRET_CANARY"
_CHILD_TIMEOUT_SECONDS = 10
_MAX_CHILD_STDERR_BYTES = 64 * 1024

# Each child triggers one hostile W02 wire path and lets the resulting LoggingError propagate
# UNCAUGHT, so the interpreter prints a full traceback to stderr. The fixed failure boundary must
# keep the planted canary out of that traceback, its message, and the whole exception graph.
_PREAMBLE = f"""
from datetime import datetime, timezone, tzinfo

CANARY = {_CANARY!r}


class HostileTz(tzinfo):
    def utcoffset(self, dt):
        raise ValueError(CANARY)

    def tzname(self, dt):
        raise ValueError(CANARY)

    def dst(self, dt):
        raise ValueError(CANARY)


class HostileIter:
    def __iter__(self):
        raise RuntimeError(CANARY)


class HostileNext:
    def __iter__(self):
        return self

    def __next__(self):
        raise RuntimeError(CANARY)


hostile = datetime(2026, 7, 21, 12, 0, 0, tzinfo=HostileTz())
utc = timezone.utc
"""

_HEADER_TIME_CHILD = (
    _PREAMBLE
    + """
from milhouse.core.log_wire import StructuredLogHeaderV1

StructuredLogHeaderV1(sequence=1, opened_at=hostile, retention_days=14)
"""
)

_TRAILER_TIME_CHILD = (
    _PREAMBLE
    + """
from milhouse.core.log_wire import StructuredLogTrailerV1

StructuredLogTrailerV1(
    sequence=1,
    closed_at=hostile,
    last_event_at=None,
    event_count=0,
    content_sha256="a" * 64,
    expires_at=datetime(2026, 7, 22, 12, 0, 0, tzinfo=utc),
)
"""
)

_TRAILER_EVENT_TIME_CHILD = (
    _PREAMBLE
    + """
from milhouse.core.log_wire import StructuredLogTrailerV1

StructuredLogTrailerV1(
    sequence=1,
    closed_at=datetime(2026, 7, 21, 12, 5, 0, tzinfo=utc),
    last_event_at=hostile,
    event_count=2,
    content_sha256="a" * 64,
    expires_at=datetime(2026, 7, 22, 12, 0, 0, tzinfo=utc),
)
"""
)

_DIGEST_ITER_CHILD = (
    _PREAMBLE
    + """
from milhouse.core.log_wire import structured_log_content_sha256

structured_log_content_sha256(b"header\\n", HostileIter())
"""
)

_DIGEST_NEXT_CHILD = (
    _PREAMBLE
    + """
from milhouse.core.log_wire import structured_log_content_sha256

structured_log_content_sha256(b"header\\n", HostileNext())
"""
)

_HOSTILE_CHILDREN = (
    _HEADER_TIME_CHILD,
    _TRAILER_TIME_CHILD,
    _TRAILER_EVENT_TIME_CHILD,
    _DIGEST_ITER_CHILD,
    _DIGEST_NEXT_CHILD,
)


def _run_hostile_child(script: str) -> tuple[int, bytes]:
    child_environment = {"PYTHONNOUSERSITE": "1", "PYTHONUTF8": "1"}
    if "PATH" in os.environ:
        child_environment["PATH"] = os.environ["PATH"]
    with tempfile.TemporaryFile() as stderr_file:
        try:
            completed = subprocess.run(
                [sys.executable, "-s", "-P", "-c", script],
                stdout=subprocess.DEVNULL,
                stderr=stderr_file,
                check=False,
                env=child_environment,
                timeout=_CHILD_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired:
            raise AssertionError("hostile wire child timed out") from None
        except OSError:
            raise AssertionError("hostile wire child could not start") from None
        stderr_file.seek(0)
        stderr = stderr_file.read(_MAX_CHILD_STDERR_BYTES + 1)
    return completed.returncode, stderr


@pytest.mark.security
@pytest.mark.parametrize("script", _HOSTILE_CHILDREN)
def test_hostile_wire_paths_never_leak_a_canary_to_child_stderr(script: str) -> None:
    returncode, stderr = _run_hostile_child(script)

    # The wire path must fail (the LoggingError propagated uncaught), and its uncaught traceback...
    assert returncode != 0, "the hostile wire path did not fail as expected"
    assert stderr != b"", "the child produced no traceback to inspect"
    # ...must not disclose the planted secret anywhere on stderr.
    assert _CANARY.encode("utf-8") not in stderr
