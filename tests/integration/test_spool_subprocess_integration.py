from __future__ import annotations

import os
import subprocess
import sys
import tempfile

_BUILD = r"""
from datetime import datetime, timedelta, timezone

from milhouse.domain.records import (
    CollectorDescriptorV1,
    EventDataV1,
    RecordDraftV1,
    SourceDescriptorV1,
    TargetDescriptorV1,
    finalize_record,
)
from milhouse.spooling import (
    SegmentHeaderV1,
    SpoolFrameV1,
    spool_content_sha256,
    spool_frame_line,
    spool_segment_header_line,
)

utc = timezone.utc
now = datetime(2026, 7, 24, 12, 0, 0, tzinfo=utc)


def envelope(source_event_id):
    values = {
        "record_type": "event",
        "name": "source.event",
        "occurred_at": now,
        "observed_at": now + timedelta(seconds=1),
        "ingested_at": now + timedelta(seconds=2),
        "expires_at": now + timedelta(days=30),
        "source_event_id": source_event_id,
        "operation_id": "operation-1",
        "collector_run_id": "collector-run-1",
        "scope": "target",
        "source": SourceDescriptorV1.model_validate({
            "id": "example-source",
            "type": "source.event",
            "producer": "collector",
            "observation_namespace_id": "mh_ns1_00000000000040008000000000000000",
            "source_generation_digest": "0" * 64,
            "observation": {"kind": "source.revision", "parts": {"revision": 1}},
        }),
        "collector": CollectorDescriptorV1(
            id="c", type="site.canary", implementation_version="1.0.0"
        ),
        "target": TargetDescriptorV1(
            id="example-target", name="Example", kind="web.service", environment="test"
        ),
        "severity": "info",
        "trust_level": "authenticated",
        "privacy_class": "internal",
        "redaction_version": "r1-e1",
        "data": EventDataV1(category="availability", status="healthy", message="ok"),
    }
    return finalize_record(
        RecordDraftV1.model_validate(values),
        installation_id="mh_in1_00000000000040008000000000000000",
    )


def segment_bytes():
    frames = [
        SpoolFrameV1(batch_id="batch-1", sequence=1, record=envelope("event-1")),
        SpoolFrameV1(batch_id="batch-1", sequence=2, record=envelope("event-2")),
    ]
    frame_lines = [spool_frame_line(frame) for frame in frames]
    header = SegmentHeaderV1(
        batch_id="batch-1",
        config_generation="a" * 64,
        scope="target",
        target_id="example-target",
        privacy_class="internal",
        retention_days=30,
        required_exporters=("clickhouse",),
        record_count=2,
        content_sha256=spool_content_sha256(frame_lines),
    )
    return spool_segment_header_line(header) + b"".join(frame_lines)
"""

CHILD_SCRIPT = (
    _BUILD
    + r"""
import os, sys

if not sys.flags.safe_path or not sys.flags.no_user_site:
    raise SystemExit(70)
if os.environ.get("PYTHONHASHSEED") != sys.argv[1]:
    raise SystemExit(70)

import locale, time
locale.setlocale(locale.LC_ALL, "")
if hasattr(time, "tzset"):
    time.tzset()

sys.stdout.buffer.write(segment_bytes())
"""
)

RUN_ENVIRONMENTS = (
    ("0", "C", "UTC0"),
    ("1", "en_US.UTF-8", "EST5EDT"),
    ("314159", "POSIX", "GMT0"),
)
MAX_CHILD_OUTPUT_BYTES = 1024 * 1024
CHILD_TIMEOUT_SECONDS = 20


def _build_in_process() -> bytes:
    namespace: dict[str, object] = {}
    exec(_BUILD, namespace)
    return namespace["segment_bytes"]()  # type: ignore[operator]


def test_segment_bytes_are_portable_across_isolated_process_environments() -> None:
    expected = _build_in_process()
    assert expected.count(b"\n") == 3  # header + two frames
    outputs: list[bytes] = []
    for run_number, (hash_seed, selected_locale, timezone_name) in enumerate(
        RUN_ENVIRONMENTS, start=1
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
            completed = subprocess.run(
                [sys.executable, "-s", "-P", "-c", CHILD_SCRIPT, hash_seed],
                stdout=stdout_file,
                stderr=stderr_file,
                check=False,
                env=child_environment,
                timeout=CHILD_TIMEOUT_SECONDS,
            )
            stdout_file.seek(0)
            child_stdout = stdout_file.read(MAX_CHILD_OUTPUT_BYTES + 1)
        assert completed.returncode == 0, f"segment child run {run_number} failed"
        outputs.append(child_stdout)

    for run_number, output in enumerate(outputs, start=1):
        assert output == expected, (
            f"segment child run {run_number} did not match the in-process bytes"
        )
    assert all(output == outputs[0] for output in outputs[1:])
