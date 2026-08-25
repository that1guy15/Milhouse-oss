from __future__ import annotations

import hashlib
import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

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
    ParsedSegment,
    SegmentHeaderV1,
    SpoolError,
    SpoolFrameV1,
    build_segment_bytes,
    parse_segment_bytes,
    publish_segment_bytes,
    read_trusted_segment,
    read_untrusted_segment,
    spool_content_sha256,
    spool_frame_line,
    spool_segment_header_line,
)
from milhouse.spooling import reader as reader_module

_OTHER_INSTALLATION_ID = "mh_in1_00000000000040008000000000000001"


def _spool_root(tmp_path: Path) -> Path:
    root = tmp_path / "spool"
    root.mkdir(mode=0o700)
    os.chmod(root, 0o700)
    return root


def _trusted_path(tmp_path: Path, content: bytes | None = None) -> Path:
    """Publish a segment exactly as the writer would: a 0600 single-link file in a 0700 parent."""

    root = _spool_root(tmp_path)
    path = root / "batch-1.jsonl"
    publish_segment_bytes(path, content if content is not None else _valid_bytes(2))
    return path


_INSTALLATION_ID = "mh_in1_00000000000040008000000000000000"
_NOW = datetime(2026, 7, 24, 12, 0, 0, tzinfo=UTC)


def _envelope(source_event_id: str) -> RecordEnvelopeV1:
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
        "scope": "target",
        "source": SourceDescriptorV1.model_validate(
            {
                "id": "example-source",
                "type": "source.event",
                "producer": "collector",
                "observation_namespace_id": "mh_ns1_00000000000040008000000000000000",
                "source_generation_digest": "0" * 64,
                "observation": {"kind": "source.revision", "parts": {"revision": 1}},
            }
        ),
        "collector": CollectorDescriptorV1(
            id="c", type="site.canary", implementation_version="1.0.0"
        ),
        "target": TargetDescriptorV1(
            id="example-target", name="E", kind="web.service", environment="test"
        ),
        "severity": "info",
        "trust_level": "authenticated",
        "privacy_class": "internal",
        "redaction_version": "r1-e1",
        "data": EventDataV1(category="availability", status="healthy", message="ok"),
    }
    return finalize_record(RecordDraftV1.model_validate(values), installation_id=_INSTALLATION_ID)


def _frames(count: int) -> tuple[SpoolFrameV1, ...]:
    return tuple(
        SpoolFrameV1(batch_id="batch-1", sequence=index, record=_envelope(f"event-{index}"))
        for index in range(1, count + 1)
    )


def _header(frames: tuple[SpoolFrameV1, ...], **overrides: object) -> SegmentHeaderV1:
    lines = [spool_frame_line(frame) for frame in frames]
    fields: dict[str, object] = {
        "batch_id": "batch-1",
        "config_generation": "a" * 64,
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


def _assemble(header: SegmentHeaderV1, frames: tuple[SpoolFrameV1, ...]) -> bytes:
    """Assemble raw segment bytes WITHOUT the writer's consistency guard (for corruption cases)."""

    return spool_segment_header_line(header) + b"".join(spool_frame_line(frame) for frame in frames)


# --- round trip -----------------------------------------------------------------------------------


def test_a_committed_segment_round_trips_exactly() -> None:
    frames = _frames(3)
    header = _header(frames)
    content = build_segment_bytes(header, frames)

    parsed = parse_segment_bytes(content)

    assert isinstance(parsed, ParsedSegment)
    assert parsed.header == header
    assert parsed.byte_size == len(content)
    assert parsed.file_sha256 == hashlib.sha256(content).hexdigest()
    assert tuple(f.sequence for f in parsed.frames) == (1, 2, 3)
    assert tuple(f.record.record_id for f in parsed.frames) == tuple(
        f.record.record_id for f in frames
    )
    # the parsed frames re-encode to the exact original bytes
    assert b"".join(spool_frame_line(f) for f in parsed.frames) == b"".join(
        spool_frame_line(f) for f in frames
    )


def test_an_empty_segment_round_trips() -> None:
    frames = _frames(0)
    header = _header(frames)
    content = build_segment_bytes(header, frames)

    parsed = parse_segment_bytes(content)

    assert parsed.frames == ()
    assert parsed.header.record_count == 0
    assert parsed.header.content_sha256 == hashlib.sha256(b"").hexdigest()


# --- truncation and framing ----------------------------------------------------------------------


def _valid_bytes(count: int = 2) -> bytes:
    frames = _frames(count)
    return build_segment_bytes(_header(frames), frames)


@pytest.mark.parametrize(
    ("mutate", "code"),
    [
        (lambda b: b"", "MH_SPOOL_TRUNCATED"),
        (lambda b: b.rstrip(b"\n"), "MH_SPOOL_TRUNCATED"),  # no trailing line feed
        (lambda b: b + b"\n", "MH_SPOOL_TRUNCATED"),  # a blank trailing line
        (lambda b: b"\n" + b, "MH_SPOOL_TRUNCATED"),  # a blank leading line
    ],
)
def test_truncated_or_blank_framing_fails_closed(mutate, code: str) -> None:
    with pytest.raises(SpoolError) as captured:
        parse_segment_bytes(mutate(_valid_bytes()))
    assert captured.value.code == code


def test_non_bytes_content_fails_closed() -> None:
    with pytest.raises(SpoolError) as captured:
        parse_segment_bytes("not bytes")  # type: ignore[arg-type]
    assert captured.value.code == "MH_SPOOL_READ"


# --- header validation ---------------------------------------------------------------------------


def test_a_non_json_header_fails_closed() -> None:
    frames = _frames(1)
    content = b"not json at all\n" + spool_frame_line(frames[0])
    with pytest.raises(SpoolError) as captured:
        parse_segment_bytes(content)
    assert captured.value.code == "MH_SPOOL_HEADER"


def test_a_header_with_unexpected_fields_fails_closed() -> None:
    frames = _frames(1)
    obj = json.loads(spool_segment_header_line(_header(frames)).decode())
    obj["surprise"] = 1
    content = (json.dumps(obj) + "\n").encode() + spool_frame_line(frames[0])
    with pytest.raises(SpoolError) as captured:
        parse_segment_bytes(content)
    assert captured.value.code == "MH_SPOOL_HEADER"


@pytest.mark.parametrize("field", ["schema", "frame_version"])
def test_an_unsupported_header_version_fails_closed(field: str) -> None:
    frames = _frames(1)
    obj = json.loads(spool_segment_header_line(_header(frames)).decode())
    obj[field] = 2
    content = (json.dumps(obj) + "\n").encode() + spool_frame_line(frames[0])
    with pytest.raises(SpoolError) as captured:
        parse_segment_bytes(content)
    assert captured.value.code == "MH_SPOOL_HEADER"


def test_a_non_canonical_header_line_fails_closed() -> None:
    frames = _frames(1)
    header = _header(frames)
    obj = json.loads(spool_segment_header_line(header).decode())
    # valid fields, but re-serialized non-canonically (spaces, key order)
    non_canonical = json.dumps(obj, indent=1).replace("\n", " ")
    content = (non_canonical + "\n").encode() + spool_frame_line(frames[0])
    with pytest.raises(SpoolError) as captured:
        parse_segment_bytes(content)
    assert captured.value.code == "MH_SPOOL_HEADER"


def test_a_bad_header_field_value_fails_closed() -> None:
    frames = _frames(1)
    obj = json.loads(spool_segment_header_line(_header(frames)).decode())
    obj["privacy_class"] = "restricted"  # forbidden class
    content = (json.dumps(obj) + "\n").encode() + spool_frame_line(frames[0])
    with pytest.raises(SpoolError) as captured:
        parse_segment_bytes(content)
    assert captured.value.code == "MH_SPOOL_PRIVACY"


# --- count, digest, sequence, header/frame agreement ---------------------------------------------


def test_a_header_count_that_disagrees_with_the_frames_fails_closed() -> None:
    frames = _frames(2)
    header = _header(frames, record_count=3)  # digest still matches the real frames
    with pytest.raises(SpoolError) as captured:
        parse_segment_bytes(_assemble(header, frames))
    assert captured.value.code == "MH_SPOOL_COUNT"


def test_a_header_digest_that_disagrees_with_the_frames_fails_closed() -> None:
    frames = _frames(2)
    header = _header(frames, content_sha256="b" * 64)  # correct count, wrong digest
    with pytest.raises(SpoolError) as captured:
        parse_segment_bytes(_assemble(header, frames))
    assert captured.value.code == "MH_SPOOL_DIGEST"


def test_a_non_contiguous_frame_sequence_fails_closed() -> None:
    first = SpoolFrameV1(batch_id="batch-1", sequence=1, record=_envelope("event-1"))
    skipped = SpoolFrameV1(batch_id="batch-1", sequence=3, record=_envelope("event-2"))
    frames = (first, skipped)
    header = _header(frames)  # digest over these exact two lines, count 2
    with pytest.raises(SpoolError) as captured:
        parse_segment_bytes(_assemble(header, frames))
    assert captured.value.code == "MH_SPOOL_SEQUENCE"


def test_a_frame_batch_id_that_disagrees_with_the_header_fails_closed() -> None:
    # a frame for a different batch than the header (its digest still matches, but the ids diverge)
    frames = (SpoolFrameV1(batch_id="batch-2", sequence=1, record=_envelope("event-1")),)
    header = _header(frames)  # header batch id defaults to "batch-1"
    with pytest.raises(SpoolError) as captured:
        parse_segment_bytes(_assemble(header, frames))
    assert captured.value.code == "MH_SPOOL_BATCH_ID"


def test_a_header_with_non_list_exporters_fails_closed() -> None:
    frames = _frames(1)
    obj = json.loads(spool_segment_header_line(_header(frames)).decode())
    obj["required_exporters"] = "clickhouse"  # a string, not a list
    content = (json.dumps(obj) + "\n").encode() + spool_frame_line(frames[0])
    with pytest.raises(SpoolError) as captured:
        parse_segment_bytes(content)
    assert captured.value.code == "MH_SPOOL_HEADER"


def test_a_frame_with_an_unsupported_version_fails_closed() -> None:
    frames = _frames(1)
    header = _header(frames)
    obj = json.loads(spool_frame_line(frames[0]).decode())
    obj["frame_version"] = 2
    content = spool_segment_header_line(header) + (json.dumps(obj) + "\n").encode()
    with pytest.raises(SpoolError) as captured:
        parse_segment_bytes(content)
    assert captured.value.code == "MH_SPOOL_FRAME"


def test_a_frame_record_that_is_not_an_object_fails_closed() -> None:
    frames = _frames(1)
    header = _header(frames)
    obj = json.loads(spool_frame_line(frames[0]).decode())
    obj["record"] = "not an object"
    content = spool_segment_header_line(header) + (json.dumps(obj) + "\n").encode()
    with pytest.raises(SpoolError) as captured:
        parse_segment_bytes(content)
    assert captured.value.code == "MH_SPOOL_FRAME"


@pytest.mark.parametrize(
    ("overrides", "code"),
    [
        ({"scope": "installation", "target_id": None}, "MH_SPOOL_SCOPE"),
        ({"target_id": "other-target"}, "MH_SPOOL_TARGET"),
        ({"privacy_class": "public"}, "MH_SPOOL_PRIVACY"),
    ],
)
def test_a_frame_that_disagrees_with_the_header_policy_fails_closed(
    overrides: dict[str, object], code: str
) -> None:
    # the header's declared policy diverges from the frame's record; the digest still matches
    frames = _frames(1)
    header = _header(frames, **overrides)
    with pytest.raises(SpoolError) as captured:
        parse_segment_bytes(_assemble(header, frames))
    assert captured.value.code == code


def test_a_non_canonical_frame_line_fails_closed() -> None:
    frames = _frames(1)
    header = _header(frames)
    line_obj = json.loads(spool_frame_line(frames[0]).decode())
    non_canonical = (json.dumps(line_obj, indent=1).replace("\n", " ") + "\n").encode()
    content = spool_segment_header_line(header) + non_canonical
    with pytest.raises(SpoolError) as captured:
        parse_segment_bytes(content)
    # a non-canonical frame changes the frame bytes, so the ordered-frame digest no longer matches
    assert captured.value.code in {"MH_SPOOL_FRAME", "MH_SPOOL_DIGEST"}


def test_a_frame_with_unexpected_fields_fails_closed() -> None:
    frames = _frames(1)
    header = _header(frames)
    obj = json.loads(spool_frame_line(frames[0]).decode())
    obj["surprise"] = 1
    content = spool_segment_header_line(header) + (json.dumps(obj) + "\n").encode()
    with pytest.raises(SpoolError) as captured:
        parse_segment_bytes(content)
    assert captured.value.code == "MH_SPOOL_FRAME"


def test_a_frame_record_that_cannot_be_reconstructed_fails_closed() -> None:
    frames = _frames(1)
    header = _header(frames)
    obj = json.loads(spool_frame_line(frames[0]).decode())
    obj["record"] = {"broken": True}
    content = spool_segment_header_line(header) + (json.dumps(obj) + "\n").encode()
    with pytest.raises(SpoolError) as captured:
        parse_segment_bytes(content)
    assert captured.value.code == "MH_SPOOL_RECORD"


def test_a_frame_record_id_that_disagrees_with_its_record_fails_closed() -> None:
    frames = _frames(1)
    header = _header(frames)
    obj = json.loads(spool_frame_line(frames[0]).decode())
    obj["record_id"] = "mh_rec1_ffffffffffffffffffffffffffffffff"
    content = spool_segment_header_line(header) + (json.dumps(obj) + "\n").encode()
    with pytest.raises(SpoolError) as captured:
        parse_segment_bytes(content)
    assert captured.value.code == "MH_SPOOL_RECORD"


# --- trusted reader: record identity / provenance ------------------------------------------------


def test_trusted_read_accepts_a_genuine_installation(tmp_path: Path) -> None:
    path = _trusted_path(tmp_path)
    parsed = read_trusted_segment(path, installation_id=_INSTALLATION_ID)
    assert isinstance(parsed, ParsedSegment)
    assert tuple(f.sequence for f in parsed.frames) == (1, 2)


def test_trusted_read_rejects_a_foreign_installation(tmp_path: Path) -> None:
    # the records are canonical and self-consistent, but were not minted by this installation
    path = _trusted_path(tmp_path)
    with pytest.raises(SpoolError) as captured:
        read_trusted_segment(path, installation_id=_OTHER_INSTALLATION_ID)
    assert captured.value.code == "MH_SPOOL_RECORD"


def test_trusted_read_rejects_a_canonical_but_forged_record(tmp_path: Path) -> None:
    record_a = _envelope("event-1")
    record_b = _envelope("event-2")
    obj = json.loads(
        spool_frame_line(SpoolFrameV1(batch_id="batch-1", sequence=1, record=record_a)).decode()
    )
    forged_id = record_b.record_id  # a real, valid id — but not record A's identity
    obj["record"]["record_id"] = forged_id
    obj["record_id"] = forged_id
    forged_record = RecordEnvelopeV1.model_validate_json(json.dumps(obj["record"]))
    forged_frame = SpoolFrameV1(batch_id="batch-1", sequence=1, record=forged_record)
    content = _assemble(_header((forged_frame,)), (forged_frame,))

    # the forgery is canonical and internally self-consistent, so the untrusted parse accepts it...
    assert parse_segment_bytes(content).frames[0].record.record_id == forged_id
    # ...but the trusted reader re-derives the id from the body and rejects it
    path = _trusted_path(tmp_path, content)
    with pytest.raises(SpoolError) as captured:
        read_trusted_segment(path, installation_id=_INSTALLATION_ID)
    assert captured.value.code == "MH_SPOOL_RECORD"


def test_trusted_read_cannot_bypass_provenance(tmp_path: Path) -> None:
    # installation_id is mandatory: there is no argument-free call that skips provenance
    path = _trusted_path(tmp_path)
    with pytest.raises(TypeError):
        read_trusted_segment(path)  # type: ignore[call-arg]


@pytest.mark.parametrize(
    "candidate",
    [
        _INSTALLATION_ID,
        _OTHER_INSTALLATION_ID,
        "mh_in1_00000000000040008000000000000000\n",  # trailing newline
        "mh_in1_00000000000040008000000000000000 ",  # trailing space
        "MH_IN1_00000000000040008000000000000000",  # wrong case
        "mh_in1_00000000000050008000000000000000",  # wrong version nibble
        "mh_in1_0000000000004000c000000000000000",  # wrong variant nibble
        "mh_ns1_00000000000040008000000000000000",  # wrong prefix
        "not-an-id",
        "",
    ],
)
def test_reader_installation_pattern_matches_the_domain(candidate: str) -> None:
    # Lock the reader's boundary regex to the domain's InstallationIdV1 so the id-leak fix cannot
    # silently regress if the domain pattern later changes.
    from pydantic import TypeAdapter, ValidationError

    from milhouse.domain.identity import InstallationIdV1

    reader_accepts = reader_module.INSTALLATION_ID_PATTERN.fullmatch(candidate) is not None
    try:
        TypeAdapter(InstallationIdV1).validate_python(candidate)
        domain_accepts = True
    except ValidationError:
        domain_accepts = False
    assert reader_accepts == domain_accepts


def test_trusted_read_rejects_a_malformed_installation_id_without_leaking_it(
    tmp_path: Path,
) -> None:
    path = _trusted_path(tmp_path)
    canary = "SECRET-CANARY-not-an-id"
    with pytest.raises(SpoolError) as captured:
        read_trusted_segment(path, installation_id=canary)
    error = captured.value
    assert error.code == "MH_SPOOL_IDENTITY"
    surface = " ".join([error.code, *(str(a) for a in error.args), str(error), repr(error)])
    assert canary not in surface
    assert error.__cause__ is None
    assert error.__context__ is None


# --- trusted reader: secure file metadata --------------------------------------------------------


def test_trusted_read_rejects_a_loose_mode_file(tmp_path: Path) -> None:
    path = _trusted_path(tmp_path)
    os.chmod(path, 0o644)
    with pytest.raises(SpoolError) as captured:
        read_trusted_segment(path, installation_id=_INSTALLATION_ID)
    assert captured.value.code == "MH_SPOOL_UNSAFE"


def test_trusted_read_rejects_a_world_writable_parent(tmp_path: Path) -> None:
    path = _trusted_path(tmp_path)
    os.chmod(path.parent, 0o777)
    try:
        with pytest.raises(SpoolError) as captured:
            read_trusted_segment(path, installation_id=_INSTALLATION_ID)
        assert captured.value.code == "MH_SPOOL_UNSAFE"
    finally:
        os.chmod(path.parent, 0o700)


def test_trusted_read_rejects_a_hard_linked_file(tmp_path: Path) -> None:
    path = _trusted_path(tmp_path)
    os.link(path, path.parent / "alias.jsonl")  # a second link: st_nlink == 2
    with pytest.raises(SpoolError) as captured:
        read_trusted_segment(path, installation_id=_INSTALLATION_ID)
    assert captured.value.code == "MH_SPOOL_UNSAFE"


def test_trusted_read_rejects_a_file_mutated_during_the_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _trusted_path(tmp_path)
    real_read = os.read
    state = {"mutated": False}

    def _mutate_then_read(fd: int, length: int) -> bytes:
        if not state["mutated"]:
            state["mutated"] = True
            with open(path, "ab") as handle:  # append out of band while our descriptor is open
                handle.write(b"x")
        return real_read(fd, length)

    monkeypatch.setattr(reader_module.os, "read", _mutate_then_read)
    with pytest.raises(SpoolError) as captured:
        read_trusted_segment(path, installation_id=_INSTALLATION_ID)
    assert captured.value.code == "MH_SPOOL_CHANGED"


# --- reader safety bounds ------------------------------------------------------------------------


def test_oversized_content_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(reader_module, "MAX_SEGMENT_FILE_BYTES", 8)
    with pytest.raises(SpoolError) as captured:
        parse_segment_bytes(_valid_bytes())
    assert captured.value.code == "MH_SPOOL_SIZE"


def test_too_many_real_frames_fails_closed_before_reconstruction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # the bound is on the real frame list, not the header's declared count, so it holds before the
    # expensive per-frame reconstruction runs
    monkeypatch.setattr(reader_module, "MAX_SEGMENT_FRAMES", 1)
    with pytest.raises(SpoolError) as captured:
        parse_segment_bytes(_valid_bytes(2))
    assert captured.value.code == "MH_SPOOL_COUNT"


def test_an_oversized_line_fails_closed() -> None:
    frames = _frames(1)
    header = _header(frames)
    padded = json.loads(spool_frame_line(frames[0]).decode())
    # a syntactically fine but enormous line, over the frame line bound
    content = (
        spool_segment_header_line(header)
        + (json.dumps(padded) + " " * (reader_module.MAX_FRAME_LINE_BYTES + 10) + "\n").encode()
    )
    with pytest.raises(SpoolError) as captured:
        parse_segment_bytes(content)
    assert captured.value.code == "MH_SPOOL_LINE"


# --- untrusted file read (diagnostics) -----------------------------------------------------------


def test_untrusted_read_round_trips(tmp_path: Path) -> None:
    content = _valid_bytes(2)
    path = (
        tmp_path / "batch-1.jsonl"
    )  # a plain, loose file — the untrusted path does not require 0600
    path.write_bytes(content)
    assert read_untrusted_segment(path) == parse_segment_bytes(content)


def test_reading_a_missing_file_reports_not_found(tmp_path: Path) -> None:
    with pytest.raises(SpoolError) as captured:
        read_untrusted_segment(tmp_path / "absent.jsonl")
    assert captured.value.code == "MH_SPOOL_NOT_FOUND"


def test_reading_a_symlink_reports_not_regular(tmp_path: Path) -> None:
    target = tmp_path / "batch-1.jsonl"
    target.write_bytes(_valid_bytes())
    link = tmp_path / "link.jsonl"
    link.symlink_to(target)
    with pytest.raises(SpoolError) as captured:
        read_untrusted_segment(link)
    assert captured.value.code == "MH_SPOOL_NOT_REGULAR"


def test_reading_a_directory_reports_not_regular(tmp_path: Path) -> None:
    directory = tmp_path / "adir"
    directory.mkdir()
    with pytest.raises(SpoolError) as captured:
        read_untrusted_segment(directory)
    assert captured.value.code == "MH_SPOOL_NOT_REGULAR"


def test_reading_an_oversized_file_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "big.jsonl"
    path.write_bytes(_valid_bytes())
    monkeypatch.setattr(reader_module, "MAX_SEGMENT_FILE_BYTES", 8)
    with pytest.raises(SpoolError) as captured:
        read_untrusted_segment(path)
    assert captured.value.code == "MH_SPOOL_SIZE"


# --- privacy-safe failures -----------------------------------------------------------------------


def test_an_io_error_during_read_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "batch-1.jsonl"
    path.write_bytes(_valid_bytes())

    def _raise(*_args: object, **_kwargs: object) -> bytes:
        raise OSError("planted read failure")

    # os.read is used only for the segment body; the secure open uses os.open/os.fstat/os.close.
    monkeypatch.setattr(reader_module.os, "read", _raise)
    with pytest.raises(SpoolError) as captured:
        read_untrusted_segment(path)
    assert captured.value.code == "MH_SPOOL_READ"
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None


def test_a_parse_failure_leaks_no_cause_or_context() -> None:
    with pytest.raises(SpoolError) as captured:
        parse_segment_bytes(b"{not valid json}\n")
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None
