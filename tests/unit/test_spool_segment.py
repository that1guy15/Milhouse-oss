from __future__ import annotations

import hashlib
import json
import os
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

import milhouse.spooling.segment as segment_module
import milhouse.spooling.writer as writer_module
from milhouse.domain.records import (
    CollectorDescriptorV1,
    EventDataV1,
    RecordDraftV1,
    RecordEnvelopeV1,
    SourceDescriptorV1,
    TargetDescriptorV1,
    finalize_record,
)
from milhouse.spooling import (
    SegmentHeaderV1,
    SpoolError,
    SpoolFrameV1,
    build_segment_bytes,
    spool_content_sha256,
    spool_frame_line,
    spool_segment_header_line,
    write_spool_segment,
)

_INSTALLATION_ID = "mh_in1_00000000000040008000000000000000"
_NOW = datetime(2026, 7, 24, 12, 0, 0, tzinfo=UTC)
_GENERATION = "a" * 64


def _source() -> SourceDescriptorV1:
    return SourceDescriptorV1.model_validate(
        {
            "id": "example-source",
            "type": "source.event",
            "producer": "collector",
            "observation_namespace_id": "mh_ns1_00000000000040008000000000000000",
            "source_generation_digest": "0" * 64,
            "observation": {"kind": "source.revision", "parts": {"revision": 1}},
        }
    )


def _target() -> TargetDescriptorV1:
    return TargetDescriptorV1(
        id="example-target", name="Example", kind="web.service", environment="test"
    )


def _envelope(
    *, scope: str = "target", privacy_class: str = "internal", source_event_id: str = "event-1"
) -> RecordEnvelopeV1:
    values: dict[str, object] = {
        "record_type": "event",
        "name": "source.event",
        "occurred_at": _NOW,
        "observed_at": _NOW + timedelta(seconds=1),
        "ingested_at": _NOW + timedelta(seconds=2),
        "expires_at": _NOW + timedelta(days=30),
        "source_event_id": source_event_id,
        "operation_id": "operation-1",
        "collector_run_id": "collector-run-1",
        "scope": scope,
        "source": _source(),
        "collector": CollectorDescriptorV1(
            id="c", type="site.canary", implementation_version="1.0.0"
        ),
        "target": _target() if scope == "target" else None,
        "severity": "info",
        "trust_level": "authenticated",
        "privacy_class": privacy_class,
        "redaction_version": "r1-e1",
        "data": EventDataV1(category="availability", status="healthy", message="ok"),
    }
    return finalize_record(RecordDraftV1.model_validate(values), installation_id=_INSTALLATION_ID)


def _frame(sequence: int, *, batch_id: str = "batch-1", **envelope_kwargs: object) -> SpoolFrameV1:
    return SpoolFrameV1(batch_id=batch_id, sequence=sequence, record=_envelope(**envelope_kwargs))  # type: ignore[arg-type]


def _header(frames: list[SpoolFrameV1], **overrides: object) -> SegmentHeaderV1:
    lines = [spool_frame_line(frame) for frame in frames]
    fields: dict[str, object] = {
        "batch_id": "batch-1",
        "config_generation": _GENERATION,
        "scope": "target",
        "target_id": "example-target",
        "privacy_class": "internal",
        "retention_days": 30,
        "required_exporters": ("clickhouse",),
        "record_count": len(frames),
        "content_sha256": spool_content_sha256(lines),
    }
    fields.update(overrides)
    return SegmentHeaderV1(**fields)  # type: ignore[arg-type]


def _private_dir(tmp_path: Path) -> Path:
    directory = tmp_path / "pending"
    directory.mkdir(mode=0o700)
    os.chmod(directory, 0o700)
    return directory


# --- frame + header projection ------------------------------------------------------------------


def test_frame_line_is_a_closed_canonical_record_frame() -> None:
    frame = _frame(1)
    line = spool_frame_line(frame)
    assert line.endswith(b"\n")
    assert line.count(b"\n") == 1
    decoded = json.loads(line)
    assert set(decoded) == {"batch_id", "frame_version", "record", "record_id", "sequence"}
    assert decoded["batch_id"] == "batch-1"
    assert decoded["frame_version"] == 1
    assert decoded["sequence"] == 1
    assert decoded["record_id"] == frame.record.record_id
    assert decoded["record"]["record_id"] == frame.record.record_id


def test_header_line_is_a_closed_canonical_header() -> None:
    line = spool_segment_header_line(_header([_frame(1)]))
    assert line.endswith(b"\n")
    assert line.count(b"\n") == 1
    decoded = json.loads(line)
    assert set(decoded) == {
        "batch_id",
        "config_generation",
        "content_sha256",
        "frame_version",
        "privacy_class",
        "record_count",
        "required_exporters",
        "retention_days",
        "schema",
        "scope",
        "target_id",
    }
    assert decoded["schema"] == 1
    assert decoded["scope"] == "target"
    assert decoded["target_id"] == "example-target"
    assert decoded["required_exporters"] == ["clickhouse"]


def test_installation_scope_header_carries_a_null_target() -> None:
    frame = _frame(1, scope="installation")
    header = _header([frame], scope="installation", target_id=None)
    decoded = json.loads(spool_segment_header_line(header))
    assert decoded["scope"] == "installation"
    assert decoded["target_id"] is None


def test_content_sha256_covers_the_ordered_frame_bytes() -> None:
    lines = [spool_frame_line(_frame(1)), spool_frame_line(_frame(2, source_event_id="event-2"))]
    assert spool_content_sha256(lines) == hashlib.sha256(b"".join(lines)).hexdigest()
    assert spool_content_sha256([]) == hashlib.sha256(b"").hexdigest()


def test_content_sha256_hostile_iterable_fails_closed() -> None:
    class _Hostile:
        def __iter__(self) -> object:
            raise RuntimeError("SYNTHETIC_SECRET")

    with pytest.raises(SpoolError) as captured:
        spool_content_sha256(_Hostile())  # type: ignore[arg-type]
    assert captured.value.code == "MH_SPOOL_DIGEST"
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None


def test_content_sha256_rejects_a_non_bytes_line() -> None:
    with pytest.raises(SpoolError) as captured:
        spool_content_sha256([b"valid\n", bytearray(b"not-bytes\n")])  # type: ignore[list-item]
    assert captured.value.code == "MH_SPOOL_DIGEST"


# --- validation ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("field", "value", "code"),
    [
        ("batch_id", "bad id!", "MH_SPOOL_BATCH_ID"),
        ("sequence", 0, "MH_SPOOL_SEQUENCE"),
        ("sequence", True, "MH_SPOOL_SEQUENCE"),
    ],
)
def test_frame_rejects_invalid_fields(field: str, value: object, code: str) -> None:
    fields: dict[str, object] = {"batch_id": "batch-1", "sequence": 1, "record": _envelope()}
    fields[field] = value
    with pytest.raises(SpoolError) as captured:
        SpoolFrameV1(**fields)  # type: ignore[arg-type]
    assert captured.value.code == code


def test_frame_rejects_a_non_envelope_record() -> None:
    with pytest.raises(SpoolError) as captured:
        SpoolFrameV1(batch_id="batch-1", sequence=1, record={"record_id": "x"})  # type: ignore[arg-type]
    assert captured.value.code == "MH_SPOOL_RECORD"


@pytest.mark.parametrize(
    ("field", "value", "code"),
    [
        ("config_generation", "z" * 64, "MH_SPOOL_CONFIG_GENERATION"),
        ("scope", "global", "MH_SPOOL_SCOPE"),
        ("target_id", None, "MH_SPOOL_TARGET"),  # target scope requires a target id
        ("privacy_class", "secret", "MH_SPOOL_PRIVACY"),
        ("retention_days", 0, "MH_SPOOL_RETENTION"),
        ("retention_days", 3651, "MH_SPOOL_RETENTION"),
        ("required_exporters", ("b", "a"), "MH_SPOOL_EXPORTERS"),
        ("required_exporters", ("a", "a"), "MH_SPOOL_EXPORTERS"),
        ("record_count", -1, "MH_SPOOL_COUNT"),
        ("content_sha256", "A" * 64, "MH_SPOOL_DIGEST"),
    ],
)
def test_header_rejects_invalid_fields(field: str, value: object, code: str) -> None:
    with pytest.raises(SpoolError) as captured:
        _header([_frame(1)], **{field: value})
    assert captured.value.code == code


@pytest.mark.parametrize(
    "required_exporters",
    [
        ["clickhouse"],
        ("",),
    ],
)
def test_header_rejects_a_non_tuple_or_invalid_exporter_ids(
    required_exporters: object,
) -> None:
    with pytest.raises(SpoolError) as captured:
        _header([_frame(1)], required_exporters=required_exporters)
    assert captured.value.code == "MH_SPOOL_EXPORTERS"


def test_wire_projectors_reject_the_wrong_model_type() -> None:
    with pytest.raises(SpoolError) as frame:
        spool_frame_line(object())  # type: ignore[arg-type]
    assert frame.value.code == "MH_SPOOL_FRAME"

    with pytest.raises(SpoolError) as header:
        spool_segment_header_line(object())  # type: ignore[arg-type]
    assert header.value.code == "MH_SPOOL_HEADER"


def test_installation_scope_forbids_a_target_id() -> None:
    with pytest.raises(SpoolError) as captured:
        _header([_frame(1, scope="installation")], scope="installation")  # target_id still set
    assert captured.value.code == "MH_SPOOL_TARGET"


def test_models_are_immutable() -> None:
    import dataclasses

    with pytest.raises(dataclasses.FrozenInstanceError):
        _frame(1).sequence = 2  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        _header([_frame(1)]).record_count = 5  # type: ignore[misc]


# --- atomic writer ------------------------------------------------------------------------------


def test_write_publishes_the_exact_segment_bytes_owner_only(tmp_path: Path) -> None:
    directory = _private_dir(tmp_path)
    frames = [_frame(1), _frame(2, source_event_id="event-2")]
    header = _header(frames)
    path = directory / "batch-1.jsonl"
    write_spool_segment(path, header, frames)

    expected = spool_segment_header_line(header) + b"".join(spool_frame_line(f) for f in frames)
    assert path.read_bytes() == expected
    assert stat.S_IMODE(os.lstat(path).st_mode) == 0o600
    assert path.read_bytes().count(b"\n") == 3  # header + two frames


def test_write_refuses_to_overwrite_an_existing_segment(tmp_path: Path) -> None:
    directory = _private_dir(tmp_path)
    frames = [_frame(1)]
    header = _header(frames)
    path = directory / "batch-1.jsonl"
    write_spool_segment(path, header, frames)
    with pytest.raises(SpoolError) as captured:
        write_spool_segment(path, header, frames)
    assert captured.value.code == "MH_SPOOL_EXISTS"


@pytest.mark.parametrize(
    ("mutate", "code"),
    [
        ({"record_count": 5}, "MH_SPOOL_COUNT"),
        ({"batch_id": "other"}, "MH_SPOOL_BATCH_ID"),
        ({"scope": "installation", "target_id": None}, "MH_SPOOL_SCOPE"),
        ({"target_id": "other-target"}, "MH_SPOOL_TARGET"),
        ({"privacy_class": "public"}, "MH_SPOOL_PRIVACY"),
        ({"content_sha256": "b" * 64}, "MH_SPOOL_DIGEST"),
    ],
)
def test_write_rejects_a_header_inconsistent_with_the_frames(
    tmp_path: Path, mutate: dict[str, object], code: str
) -> None:
    directory = _private_dir(tmp_path)
    frames = [_frame(1)]
    header = _header(frames, **mutate)
    with pytest.raises(SpoolError) as captured:
        write_spool_segment(directory / "batch-1.jsonl", header, frames)
    assert captured.value.code == code


def test_write_rejects_a_noncontiguous_sequence(tmp_path: Path) -> None:
    directory = _private_dir(tmp_path)
    frames = [_frame(1), _frame(3, source_event_id="event-3")]
    header = _header(frames)
    with pytest.raises(SpoolError) as captured:
        write_spool_segment(directory / "batch-1.jsonl", header, frames)
    assert captured.value.code == "MH_SPOOL_SEQUENCE"


def test_writer_rejects_wrong_header_frames_and_frame_members() -> None:
    frame = _frame(1)
    header = _header([frame])

    with pytest.raises(SpoolError) as wrong_header:
        build_segment_bytes(object(), [frame])  # type: ignore[arg-type]
    assert wrong_header.value.code == "MH_SPOOL_HEADER"

    with pytest.raises(SpoolError) as wrong_frames:
        build_segment_bytes(header, iter([frame]))  # type: ignore[arg-type]
    assert wrong_frames.value.code == "MH_SPOOL_FRAMES"

    with pytest.raises(SpoolError) as wrong_member:
        build_segment_bytes(header, [object()])  # type: ignore[list-item]
    assert wrong_member.value.code == "MH_SPOOL_FRAME"


def test_writer_uses_the_central_segment_caps() -> None:
    assert writer_module.MAX_SEGMENT_FRAMES == segment_module.MAX_SEGMENT_FRAMES
    assert writer_module.MAX_SEGMENT_FILE_BYTES == segment_module.MAX_SEGMENT_FILE_BYTES


def test_writer_frame_cap_accepts_exactly_the_cap_and_refuses_cap_plus_one_before_publication(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = _frame(1)
    second = _frame(2, source_event_id="event-2")
    one_header = _header([first])
    two_header = _header([first, second])
    published: list[bytes] = []

    monkeypatch.setattr(writer_module, "MAX_SEGMENT_FRAMES", 1)
    monkeypatch.setattr(
        writer_module,
        "publish_segment_bytes",
        lambda _path, content: published.append(content),
    )

    writer_module.write_spool_segment("unused", one_header, [first])
    assert published == [build_segment_bytes(one_header, [first])]

    published.clear()
    with pytest.raises(SpoolError) as captured:
        writer_module.write_spool_segment("unused", two_header, [first, second])
    assert captured.value.code == "MH_SPOOL_COUNT"
    assert published == []


def test_writer_byte_cap_accepts_exactly_the_cap_and_refuses_cap_plus_one_before_publication(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    frame = _frame(1)
    header = _header([frame])
    expected = spool_segment_header_line(header) + spool_frame_line(frame)
    published: list[bytes] = []

    monkeypatch.setattr(writer_module, "MAX_SEGMENT_FILE_BYTES", len(expected))
    monkeypatch.setattr(
        writer_module,
        "publish_segment_bytes",
        lambda _path, content: published.append(content),
    )

    writer_module.write_spool_segment("unused", header, [frame])
    assert published == [expected]

    published.clear()
    monkeypatch.setattr(writer_module, "MAX_SEGMENT_FILE_BYTES", len(expected) - 1)
    with pytest.raises(SpoolError) as captured:
        writer_module.write_spool_segment("unused", header, [frame])
    assert captured.value.code == "MH_SPOOL_SIZE"
    assert published == []


def test_write_fails_closed_when_the_parent_is_not_private(tmp_path: Path) -> None:
    directory = tmp_path / "loose"
    directory.mkdir()
    os.chmod(directory, 0o777)
    frames = [_frame(1)]
    header = _header(frames)
    with pytest.raises(SpoolError) as captured:
        write_spool_segment(directory / "batch-1.jsonl", header, frames)
    assert captured.value.code == "MH_SPOOL_WRITE"
