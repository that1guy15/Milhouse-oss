"""W07 increment 1: the ``.milhouse`` outbox reader spine fault matrix (plan section 4.9).

These offline tests drive :func:`read_outbox`, the frame parser, the cursor codec, and the atomic
ack read/writer against temp files, exercising every recovery/detection branch the gate requires:
unchanged input, single/multi append, torn tails, malformed and oversized lines, compliant and
multi-step rotation, and each data-loss discontinuity (truncation, consumed-prefix rewrite, a
removed rotated file, a torn rotated file, and inode reuse). Privacy is asserted directly: a canary
planted in a rejected line never appears in any frame, diagnostic, loss signal, or raised error.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import traceback
from datetime import UTC, datetime
from pathlib import Path

import pytest

from milhouse.outbox import (
    MAX_OUTBOX_FRAME_BYTES,
    OUTBOX_POSITION_VERSION,
    OutboxAckV1,
    OutboxFrameV1,
    OutboxPosition,
    OutboxReaderConfig,
    decode_outbox_position,
    encode_outbox_position,
    outbox_ack_bytes,
    parse_outbox_frame_line,
    read_outbox,
    read_outbox_ack,
    write_outbox_ack,
)
from milhouse.outbox.errors import OutboxError
from milhouse.state.cursors import SourceCursor

_OUTBOX_NAME = "feedback-outbox.jsonl"
_ROTATION_GLOB = "feedback-outbox.*.jsonl"
_TS = "2026-08-17T12:00:00.000Z"


# --- helpers ------------------------------------------------------------------------------------


def _frame_document(**overrides: object) -> dict[str, object]:
    document: dict[str, object] = {
        "schema_version": "1.0",
        "producer_id": "web-ci",
        "occurred_at": _TS,
        "target": "web-service",
        "kind": "deploy.completed",
        "actionability": "observe",
        "evidence_references": ["ev-1"],
        "data": {"count": 3},
    }
    document.update(overrides)
    return document


def _frame_line(**overrides: object) -> bytes:
    return json.dumps(_frame_document(**overrides)).encode("utf-8") + b"\n"


def _cursor(position: str) -> SourceCursor:
    return SourceCursor(
        source="outbox", position=position, batch_id=None, revision=0, updated_at=_TS
    )


def _write(path: Path, data: bytes) -> None:
    path.write_bytes(data)


def _append(path: Path, data: bytes) -> None:
    with path.open("ab") as handle:
        handle.write(data)


def _outbox(tmp_path: Path, data: bytes = b"") -> Path:
    path = tmp_path / _OUTBOX_NAME
    _write(path, data)
    return path


def _cursor_for(path: Path, consumed: bytes) -> SourceCursor:
    """Build a cursor that has consumed exactly ``consumed`` bytes from ``path``'s current inode."""

    info = os.stat(path)
    position = OutboxPosition(
        device=info.st_dev,
        inode=info.st_ino,
        offset=len(consumed),
        content_sha256=hashlib.sha256(consumed).hexdigest(),
    )
    return _cursor(encode_outbox_position(position))


def _surfaces(*values: object) -> str:
    return "\n".join(repr(value) for value in values)


# --- OutboxFrameV1 ------------------------------------------------------------------------------


def test_valid_frame_parses_with_bounded_fields() -> None:
    frame = parse_outbox_frame_line(_frame_line(evidence_references=["ev-1", "ev-2"]))
    assert type(frame) is OutboxFrameV1
    assert frame.producer_id == "web-ci"
    assert frame.kind == "deploy.completed"
    assert frame.actionability == "observe"
    assert list(frame.evidence_references) == ["ev-1", "ev-2"]
    assert dict(frame.data) == {"count": 3}


def test_frame_at_bounds_accepted_and_one_over_rejected() -> None:
    max_producer = "p" + "0" * 63  # 64 chars: the MachineId ceiling
    parse_outbox_frame_line(_frame_line(producer_id=max_producer))
    with pytest.raises(OutboxError) as over:
        parse_outbox_frame_line(_frame_line(producer_id="p" + "0" * 64))
    assert over.value.code == "MH_OUTBOX_FRAME"

    max_evidence = [f"ev-{index}" for index in range(100)]
    parse_outbox_frame_line(_frame_line(evidence_references=max_evidence))
    with pytest.raises(OutboxError):
        parse_outbox_frame_line(_frame_line(evidence_references=[*max_evidence, "ev-100"]))


def test_frame_ceiling_rejects_oversized_structured_data() -> None:
    huge = "z" * (MAX_OUTBOX_FRAME_BYTES // 2)
    with pytest.raises(OutboxError):
        parse_outbox_frame_line(_frame_line(data={"blob": huge, "blob_two": huge}))


@pytest.mark.parametrize(
    "line",
    [
        b'{"schema_version":"2.0","producer_id":"web-ci","occurred_at":"'
        + _TS.encode()
        + b'","target":"t","kind":"k","actionability":"observe"}',
        b'{"producer_id":"web-ci","occurred_at":"'
        + _TS.encode()
        + b'","target":"t","kind":"k","actionability":"nope"}',
        b'{"producer_id":"web-ci","occurred_at":"'
        + _TS.encode()
        + b'","target":"t","kind":"k","actionability":"observe","surprise":1}',
        b"not json at all",
        b"",
        b"\xff\xfe not utf-8",
    ],
)
def test_frame_rejects_malformed_input_with_fixed_code(line: bytes) -> None:
    with pytest.raises(OutboxError) as raised:
        parse_outbox_frame_line(line)
    assert raised.value.code == "MH_OUTBOX_FRAME"


def test_frame_parse_error_never_carries_raw_value() -> None:
    canary = f"PRIVATE-{secrets.token_hex(12)}"
    line = json.dumps({**_frame_document(), "secret_field": canary}).encode("utf-8")
    with pytest.raises(OutboxError) as raised:
        parse_outbox_frame_line(line)
    error = raised.value
    surfaces = (
        str(error),
        repr(error),
        repr(error.args),
        "".join(traceback.format_exception(error)),
    )
    assert all(canary not in surface for surface in surfaces)
    assert error.__cause__ is None
    assert error.__context__ is None


# --- cursor codec -------------------------------------------------------------------------------


def test_cursor_codec_round_trips_and_is_self_describing() -> None:
    position = OutboxPosition(device=7, inode=99, offset=4096, content_sha256="a" * 64)
    encoded = encode_outbox_position(position)
    assert json.loads(encoded)["v"] == OUTBOX_POSITION_VERSION
    assert decode_outbox_position(encoded) == position


@pytest.mark.parametrize(
    "payload",
    [
        '{"v":2,"dev":1,"inode":1,"offset":0,"sha256":"' + "a" * 64 + '"}',  # wrong version
        '{"v":1,"dev":1,"inode":1,"offset":0}',  # missing key
        '{"v":1,"dev":1,"inode":1,"offset":0,"sha256":"a","extra":1}',  # extra key
        '{"v":1,"dev":1,"inode":1,"offset":-1,"sha256":"' + "a" * 64 + '"}',  # negative offset
        '{"v":1,"dev":1,"inode":1,"offset":0,"sha256":"nothex"}',  # bad digest
        '{ "v":1, "dev":1, "inode":1, "offset":0, "sha256":"' + "a" * 64 + '" }',  # non-canonical
        "not json",
    ],
)
def test_cursor_codec_rejects_malformed_position(payload: str) -> None:
    with pytest.raises(OutboxError) as raised:
        decode_outbox_position(payload)
    assert raised.value.code == "MH_OUTBOX_POSITION"


# --- reader: steady state -----------------------------------------------------------------------


def test_empty_file_yields_no_frames_and_establishes_cursor(tmp_path: Path) -> None:
    path = _outbox(tmp_path)
    result = read_outbox(file_path=path, prior_cursor=None, config=OutboxReaderConfig())
    assert result.new_frames == ()
    assert result.loss_signal is None
    assert result.next_position is not None
    assert result.next_position.offset == 0
    assert result.next_position.content_sha256 == hashlib.sha256(b"").hexdigest()


def test_single_append_reads_only_new_frame(tmp_path: Path) -> None:
    path = _outbox(tmp_path, _frame_line(kind="deploy.started"))
    first = read_outbox(file_path=path, prior_cursor=None, config=OutboxReaderConfig())
    assert len(first.new_frames) == 1

    _append(path, _frame_line(kind="deploy.completed"))
    second = read_outbox(
        file_path=path,
        prior_cursor=_cursor(first.next_position_string),
        config=OutboxReaderConfig(),
    )
    assert [frame.kind for frame in second.new_frames] == ["deploy.completed"]
    assert second.diagnostics.frames_emitted == 1


def test_unchanged_input_yields_no_new_frames(tmp_path: Path) -> None:
    path = _outbox(tmp_path, _frame_line() + _frame_line(kind="deploy.started"))
    first = read_outbox(file_path=path, prior_cursor=None, config=OutboxReaderConfig())
    assert len(first.new_frames) == 2

    second = read_outbox(
        file_path=path,
        prior_cursor=_cursor(first.next_position_string),
        config=OutboxReaderConfig(),
    )
    assert second.new_frames == ()
    assert second.diagnostics.frames_emitted == 0
    assert second.next_position_string == first.next_position_string


def test_multi_append_reads_only_the_appended_frames(tmp_path: Path) -> None:
    path = _outbox(tmp_path, _frame_line(kind="a"))
    first = read_outbox(file_path=path, prior_cursor=None, config=OutboxReaderConfig())

    _append(path, _frame_line(kind="b") + _frame_line(kind="c") + _frame_line(kind="d"))
    second = read_outbox(
        file_path=path,
        prior_cursor=_cursor(first.next_position_string),
        config=OutboxReaderConfig(),
    )
    assert [frame.kind for frame in second.new_frames] == ["b", "c", "d"]


def test_partial_torn_tail_is_not_consumed_then_completes(tmp_path: Path) -> None:
    path = _outbox(tmp_path, _frame_line(kind="a"))
    first = read_outbox(file_path=path, prior_cursor=None, config=OutboxReaderConfig())

    # Append one complete line plus a torn (no trailing LF) partial line.
    complete = _frame_line(kind="b")
    partial = _frame_line(kind="c")[:-10]
    _append(path, complete + partial)
    second = read_outbox(
        file_path=path,
        prior_cursor=_cursor(first.next_position_string),
        config=OutboxReaderConfig(),
    )
    assert [frame.kind for frame in second.new_frames] == ["b"]
    assert second.diagnostics.torn_tail_bytes == len(partial)

    # Completing the torn line makes it available on the next read, with no duplication of "b".
    _append(path, _frame_line(kind="c")[-10:])
    third = read_outbox(
        file_path=path,
        prior_cursor=_cursor(second.next_position_string),
        config=OutboxReaderConfig(),
    )
    assert [frame.kind for frame in third.new_frames] == ["c"]
    assert third.diagnostics.torn_tail_bytes == 0


# --- reader: rejection posture ------------------------------------------------------------------


def test_malformed_line_rejected_and_neighbors_are_read(tmp_path: Path) -> None:
    canary = f"PRIVATE-{secrets.token_hex(12)}"
    malformed = b'{"kind": "broken", "leak": "' + canary.encode() + b'"\n'  # no closing brace
    data = _frame_line(kind="before") + malformed + _frame_line(kind="after")
    path = _outbox(tmp_path, data)
    result = read_outbox(file_path=path, prior_cursor=None, config=OutboxReaderConfig())

    assert [frame.kind for frame in result.new_frames] == ["before", "after"]
    assert result.diagnostics.rejected_lines == 1
    assert result.diagnostics.rejected_codes["MH_OUTBOX_FRAME"] == 1
    # The whole malformed line was consumed exactly once: re-reading yields nothing new.
    assert result.next_position.offset == len(data)
    assert canary not in _surfaces(result, result.diagnostics, *result.new_frames)


def test_oversized_line_rejected_without_raw_persistence(tmp_path: Path) -> None:
    canary = f"PRIVATE-{secrets.token_hex(12)}"
    config = OutboxReaderConfig(max_line_bytes=256)
    oversized = (
        json.dumps(_frame_document(data={"blob": canary + "x" * 512})).encode("utf-8") + b"\n"
    )
    data = _frame_line(kind="ok") + oversized
    path = _outbox(tmp_path, data)
    result = read_outbox(file_path=path, prior_cursor=None, config=config)

    assert [frame.kind for frame in result.new_frames] == ["ok"]
    assert result.diagnostics.rejected_codes["MH_OUTBOX_LINE_OVERSIZE"] == 1
    assert canary not in _surfaces(result, result.diagnostics, *result.new_frames)


def test_producer_allowlist_denies_unlisted_producers(tmp_path: Path) -> None:
    config = OutboxReaderConfig(producer_allowlist=("web-ci",))
    data = _frame_line(producer_id="web-ci", kind="ok") + _frame_line(
        producer_id="rogue", kind="no"
    )
    path = _outbox(tmp_path, data)
    result = read_outbox(file_path=path, prior_cursor=None, config=config)

    assert [frame.kind for frame in result.new_frames] == ["ok"]
    assert result.diagnostics.rejected_codes["MH_OUTBOX_PRODUCER_DENIED"] == 1


# --- reader: rotation ---------------------------------------------------------------------------


def _rotate(path: Path, sequence: int) -> Path:
    rotated = path.parent / f"feedback-outbox.{sequence:08d}.jsonl"
    os.rename(path, rotated)
    return rotated


def test_compliant_rotation_recovers_without_loss_or_duplication(tmp_path: Path) -> None:
    path = _outbox(tmp_path, _frame_line(kind="a") + _frame_line(kind="b"))
    cursor = _cursor_for(path, _frame_line(kind="a"))  # consumed only "a"

    _rotate(path, 1)
    _write(path, _frame_line(kind="c") + _frame_line(kind="d"))
    config = OutboxReaderConfig(rotation_glob=_ROTATION_GLOB)
    result = read_outbox(file_path=path, prior_cursor=cursor, config=config)

    assert result.loss_signal is None
    assert [frame.kind for frame in result.new_frames] == ["b", "c", "d"]
    assert result.diagnostics.rotations_crossed == 1
    # The next cursor points into the new active file.
    assert result.next_position.inode == os.stat(path).st_ino


def test_multiple_rotations_recovered_in_monotonic_order(tmp_path: Path) -> None:
    path = _outbox(tmp_path, _frame_line(kind="a") + _frame_line(kind="b"))
    cursor = _cursor_for(path, _frame_line(kind="a"))

    _rotate(path, 1)
    _write(path, _frame_line(kind="c"))
    _rotate(path, 2)
    _write(path, _frame_line(kind="d") + _frame_line(kind="e"))
    config = OutboxReaderConfig(rotation_glob=_ROTATION_GLOB)
    result = read_outbox(file_path=path, prior_cursor=cursor, config=config)

    assert result.loss_signal is None
    assert [frame.kind for frame in result.new_frames] == ["b", "c", "d", "e"]
    assert result.diagnostics.rotations_crossed == 2


def test_first_read_no_cursor_ingests_retained_rotations(tmp_path: Path) -> None:
    # FIX 1 (P1): a FIRST read (cursor still None: run 1 committed nothing) after the outbox ALREADY
    # rotated must ingest the retained rotated file too -- reading only the active file would drop
    # those frames forever with no loss signal.
    path = _outbox(tmp_path, _frame_line(kind="a") + _frame_line(kind="b"))
    _rotate(path, 1)  # feedback-outbox.00000001.jsonl now holds a, b
    _write(path, _frame_line(kind="c"))  # the fresh active file holds c
    config = OutboxReaderConfig(rotation_glob=_ROTATION_GLOB)

    result = read_outbox(file_path=path, prior_cursor=None, config=config)
    assert result.loss_signal is None
    assert [frame.kind for frame in result.new_frames] == ["a", "b", "c"]  # whole chain, in order
    assert result.diagnostics.rotations_crossed == 1
    assert result.max_observed_sequence == 1
    # The cursor is established at the active file's EOF.
    assert result.next_position is not None
    assert result.next_position.inode == os.stat(path).st_ino
    assert result.next_position.offset == len(_frame_line(kind="c"))


def test_first_read_no_cursor_without_glob_reads_only_active(tmp_path: Path) -> None:
    # Without a rotation_glob the reader cannot enumerate rotations, so a first read reads only the
    # active file -- the pre-existing, safe single-file behaviour (there is nothing to discover).
    path = _outbox(tmp_path, _frame_line(kind="a"))
    _rotate(path, 1)
    _write(path, _frame_line(kind="c"))
    result = read_outbox(file_path=path, prior_cursor=None, config=OutboxReaderConfig())
    assert result.loss_signal is None
    assert [frame.kind for frame in result.new_frames] == ["c"]


def test_first_read_no_cursor_gap_in_rotations_is_p1_loss(tmp_path: Path) -> None:
    # A gap in the retained rotated run on a first read is unrecoverable loss (nothing is acked, so
    # a compliant producer would not have deleted an intermediate segment). Reported at zero.
    path = _outbox(tmp_path, _frame_line(kind="a"))
    _rotate(path, 1)
    _write(path, _frame_line(kind="b"))
    _rotate(path, 3)  # sequences {1, 3} retained -- 2 is missing
    _write(path, _frame_line(kind="c"))
    result = read_outbox(
        file_path=path, prior_cursor=None, config=OutboxReaderConfig(rotation_glob=_ROTATION_GLOB)
    )
    assert result.new_frames == ()
    assert result.loss_signal is not None
    assert result.loss_signal.code == "MH_OUTBOX_LOSS_ROTATION_GONE"


def test_frame_offsets_are_per_file_byte_positions(tmp_path: Path) -> None:
    # FIX 2: each frame exposes its start byte WITHIN its own file, so a consumer can fold the
    # offset into identity to keep byte-identical-but-distinct frames apart.
    line_a = _frame_line(kind="a")
    path = _outbox(tmp_path, line_a + _frame_line(kind="b"))
    result = read_outbox(file_path=path, prior_cursor=None, config=OutboxReaderConfig())
    assert [frame.kind for frame in result.new_frames] == ["a", "b"]
    assert result.frame_offsets == (0, len(line_a))


def test_frame_offset_skips_a_preceding_rejected_line(tmp_path: Path) -> None:
    # A rejected line BEFORE a valid frame must not shift the valid frame's offset: the running
    # total advances over the rejected line so the frame records its TRUE byte start.
    rejected = b"this is not a valid json frame\n"
    good = _frame_line(kind="ok")
    path = _outbox(tmp_path, rejected + good)
    result = read_outbox(file_path=path, prior_cursor=None, config=OutboxReaderConfig())
    assert [frame.kind for frame in result.new_frames] == ["ok"]
    assert result.diagnostics.rejected_lines == 1
    assert result.frame_offsets == (len(rejected),)  # the true offset, past the skipped bad line


def test_frame_offset_skips_a_preceding_oversized_line(tmp_path: Path) -> None:
    # The oversize branch also advances the running total, so a valid frame after an oversized line
    # still records its true offset. The bound is set above the valid frame but below the bad line.
    good = _frame_line(kind="ok")
    config = OutboxReaderConfig(max_line_bytes=len(good) + 100)
    oversized = b"o" * (len(good) + 200) + b"\n"  # over max_line_bytes -> rejected as oversize
    path = _outbox(tmp_path, oversized + good)
    result = read_outbox(file_path=path, prior_cursor=None, config=config)
    assert [frame.kind for frame in result.new_frames] == ["ok"]
    assert result.diagnostics.rejected_lines == 1
    assert result.frame_offsets == (len(oversized),)


def test_frame_offset_is_stable_across_rotation(tmp_path: Path) -> None:
    # The per-file offset is what makes the replay/identity property survive rotation: a rename
    # never moves bytes, so frame "b" keeps the same offset once it lives in the rotated file.
    line_a = _frame_line(kind="a")
    path = _outbox(tmp_path, line_a + _frame_line(kind="b"))
    config = OutboxReaderConfig(rotation_glob=_ROTATION_GLOB)
    first = read_outbox(file_path=path, prior_cursor=None, config=config)
    b_first = [frame.kind for frame in first.new_frames].index("b")
    assert first.frame_offsets[b_first] == len(line_a)

    _rotate(path, 1)  # "b" now lives in the rotated file, at the SAME byte offset
    _write(path, _frame_line(kind="c"))
    second = read_outbox(file_path=path, prior_cursor=None, config=config)
    b_second = [frame.kind for frame in second.new_frames].index("b")
    assert second.frame_offsets[b_second] == len(line_a)


def test_needed_rotated_file_removed_is_p1_loss(tmp_path: Path) -> None:
    path = _outbox(tmp_path, _frame_line(kind="a") + _frame_line(kind="b"))
    cursor = _cursor_for(path, _frame_line(kind="a"))
    _rotate(path, 1)
    _write(path, _frame_line(kind="c"))
    os.unlink(path.parent / "feedback-outbox.00000001.jsonl")  # the file the cursor still needs

    config = OutboxReaderConfig(rotation_glob=_ROTATION_GLOB)
    result = read_outbox(file_path=path, prior_cursor=cursor, config=config)
    assert result.new_frames == ()
    assert result.loss_signal is not None
    assert result.loss_signal.code == "MH_OUTBOX_LOSS_ROTATION_GONE"
    assert result.loss_signal.priority == "P1"


def test_rotated_file_with_torn_tail_is_p1_loss(tmp_path: Path) -> None:
    path = _outbox(tmp_path, _frame_line(kind="a"))
    cursor = _cursor_for(path, b"")  # nothing consumed yet
    rotated = _rotate(path, 1)
    _append(rotated, b'{"torn": "no-final-lf"')  # rotated (immutable) file left non-LF-terminated
    _write(path, _frame_line(kind="b"))

    config = OutboxReaderConfig(rotation_glob=_ROTATION_GLOB)
    result = read_outbox(file_path=path, prior_cursor=cursor, config=config)
    assert result.new_frames == ()
    assert result.loss_signal.code == "MH_OUTBOX_LOSS_ROTATED_TORN"


def _rotate_to(path: Path, name: str) -> Path:
    """Rename the active file to an explicit rotated name (mirrors a producer rotation)."""

    rotated = path.parent / name
    os.rename(path, rotated)
    return rotated


def test_gap_in_rotated_sequence_above_cursor_is_p1_loss(tmp_path: Path) -> None:
    # Cursor in segment 1; the producer rotates twice more (segments 2 and 3 retained above it),
    # then the intermediate segment 2 is removed. The surviving segment 3 above the gap makes the
    # missing sequence detectable: a dropped unconsumed segment is un-recoverable P1 loss.
    path = _outbox(tmp_path, _frame_line(kind="a") + _frame_line(kind="b"))
    cursor = _cursor_for(path, _frame_line(kind="a"))
    _rotate(path, 1)
    _write(path, _frame_line(kind="c"))
    _rotate(path, 2)
    _write(path, _frame_line(kind="d"))
    _rotate(path, 3)
    _write(path, _frame_line(kind="e"))
    os.unlink(path.parent / "feedback-outbox.00000002.jsonl")  # drop the intermediate segment

    config = OutboxReaderConfig(rotation_glob=_ROTATION_GLOB)
    result = read_outbox(file_path=path, prior_cursor=cursor, config=config)
    assert result.new_frames == ()
    assert result.loss_signal is not None
    assert result.loss_signal.code == "MH_OUTBOX_LOSS_ROTATION_GONE"
    assert result.loss_signal.priority == "P1"
    assert result.next_position_string == cursor.position  # cursor NOT advanced


def test_gap_not_at_the_boundary_is_p1_loss(tmp_path: Path) -> None:
    # Cursor in segment 1; segments 2, 3, 4 rotate above it, then the MIDDLE segment 3 is removed
    # (2 present, 3 missing, 4 present). The hole between two survivors is detected.
    path = _outbox(tmp_path, _frame_line(kind="a") + _frame_line(kind="b"))
    cursor = _cursor_for(path, _frame_line(kind="a"))
    for sequence, kind in ((1, "c"), (2, "d"), (3, "e")):
        _rotate(path, sequence)
        _write(path, _frame_line(kind=kind))
    _rotate(path, 4)
    _write(path, _frame_line(kind="f"))
    os.unlink(path.parent / "feedback-outbox.00000003.jsonl")  # 2 present, 3 missing, 4 present

    config = OutboxReaderConfig(rotation_glob=_ROTATION_GLOB)
    result = read_outbox(file_path=path, prior_cursor=cursor, config=config)
    assert result.new_frames == ()
    assert result.loss_signal.code == "MH_OUTBOX_LOSS_ROTATION_GONE"


def test_unpadded_monotonic_names_order_numerically_without_false_loss(tmp_path: Path) -> None:
    # Unpadded names: "...10"/"...11" sort lexically BEFORE "...9" but must order numerically.
    path = _outbox(tmp_path, _frame_line(kind="a") + _frame_line(kind="b"))
    cursor = _cursor_for(path, _frame_line(kind="a"))
    _rotate_to(path, "feedback-outbox.9.jsonl")
    _write(path, _frame_line(kind="c"))
    _rotate_to(path, "feedback-outbox.10.jsonl")
    _write(path, _frame_line(kind="d"))
    _rotate_to(path, "feedback-outbox.11.jsonl")
    _write(path, _frame_line(kind="e"))

    config = OutboxReaderConfig(rotation_glob=_ROTATION_GLOB)
    result = read_outbox(file_path=path, prior_cursor=cursor, config=config)
    assert result.loss_signal is None
    # b (rest of seq 9), then seq 10, seq 11, then the active file -- each read exactly once.
    assert [frame.kind for frame in result.new_frames] == ["b", "c", "d", "e"]
    assert result.diagnostics.rotations_crossed == 3


def test_top_run_deletion_is_undetectable_without_a_high_water(tmp_path: Path) -> None:
    # DOCUMENTED RESIDUAL when NO high-water is supplied (reader._recover_rotation docstring): the
    # active file carries no sequence, so deletion of a RUN of the TOPMOST rotated segments (next to
    # the active file) leaves the survivors a contiguous run that passes the gap check. A stateless
    # single-file cursor keeps no record of the highest sequence that ever existed, so on its own it
    # cannot know those top segments were dropped. Increment 2a CLOSES this by threading a durable
    # rotation high-water (the ack's ``last_sequence``) back as ``last_acknowledged_sequence`` (see
    # test_top_run_deletion_detected_with_high_water). We keep this test with NO high-water passed
    # to PIN that, without one, the window is still (necessarily) silent, so a regression that
    # either widens it or spuriously fires here is caught.
    path = _outbox(tmp_path, _frame_line(kind="a") + _frame_line(kind="b"))
    cursor = _cursor_for(path, _frame_line(kind="a"))
    for sequence, kind in ((1, "c"), (2, "d"), (3, "e")):
        _rotate(path, sequence)
        _write(path, _frame_line(kind=kind))
    _rotate(path, 4)
    _write(path, _frame_line(kind="f"))  # active
    # seg1=[a,b] seg2=[c] seg3=[d] seg4=[e] active=[f]; drop the TOP RUN (segs 3+4) below active.
    os.unlink(path.parent / "feedback-outbox.00000003.jsonl")
    os.unlink(path.parent / "feedback-outbox.00000004.jsonl")

    config = OutboxReaderConfig(rotation_glob=_ROTATION_GLOB)
    result = read_outbox(file_path=path, prior_cursor=cursor, config=config)

    # NO high-water -> NO loss is signalled and d (seg3) + e (seg4) are silently absent. But the
    # reader still REPORTS the surviving top M (=2) so a caller that persisted it as the high-water
    # would trip the detector on the next read (that is exactly the closure path).
    assert result.loss_signal is None
    assert [frame.kind for frame in result.new_frames] == ["b", "c", "f"]
    assert result.max_observed_sequence == 2


def test_top_run_deletion_detected_with_high_water(tmp_path: Path) -> None:
    # TRUE POSITIVE (increment 2a): identical top-run deletion, but this time the reader is told the
    # durable high-water H=4 (segment 4 was OBSERVED in a prior read). The current top retained
    # rotated sequence M is only 2, so the run (segs 3, 4) -- above the cursor in seg1, hence
    # UNCONSUMED -- is a genuine data loss the reader now flags.
    path = _outbox(tmp_path, _frame_line(kind="a") + _frame_line(kind="b"))
    cursor = _cursor_for(path, _frame_line(kind="a"))  # cursor in seg1, consumed only "a"
    for sequence, kind in ((1, "c"), (2, "d"), (3, "e")):
        _rotate(path, sequence)
        _write(path, _frame_line(kind=kind))
    _rotate(path, 4)
    _write(path, _frame_line(kind="f"))  # active
    # seg1=[a,b] seg2=[c] seg3=[d] seg4=[e] active=[f]; drop the TOP RUN (segs 3+4).
    os.unlink(path.parent / "feedback-outbox.00000003.jsonl")
    os.unlink(path.parent / "feedback-outbox.00000004.jsonl")

    config = OutboxReaderConfig(rotation_glob=_ROTATION_GLOB)
    result = read_outbox(
        file_path=path, prior_cursor=cursor, config=config, last_acknowledged_sequence=4
    )
    assert result.new_frames == ()  # zero frames on a loss
    assert result.loss_signal is not None
    assert result.loss_signal.code == "MH_OUTBOX_LOSS_TOP_RUN_GONE"
    assert result.loss_signal.priority == "P1"
    assert result.next_position_string == cursor.position  # cursor NOT advanced
    assert result.max_observed_sequence == 2  # the surviving top, reported for the caller


@pytest.mark.parametrize("high_water", [None, 1, 2, 3])
def test_contiguous_rotation_with_high_water_reports_no_top_run_loss(
    tmp_path: Path, high_water: int | None
) -> None:
    # NO FALSE POSITIVE: a compliant contiguous rotation whose top retained M == 3. A high-water of
    # None, or any value at/below M (nothing observed is missing from the top), must NOT trip the
    # detector; the whole chain reads cleanly.
    path = _outbox(tmp_path, _frame_line(kind="a") + _frame_line(kind="b"))
    cursor = _cursor_for(path, _frame_line(kind="a"))
    _rotate(path, 1)
    _write(path, _frame_line(kind="c"))
    _rotate(path, 2)
    _write(path, _frame_line(kind="d"))
    _rotate(path, 3)
    _write(path, _frame_line(kind="e"))

    config = OutboxReaderConfig(rotation_glob=_ROTATION_GLOB)
    result = read_outbox(
        file_path=path,
        prior_cursor=cursor,
        config=config,
        last_acknowledged_sequence=high_water,
    )
    assert result.loss_signal is None
    assert [frame.kind for frame in result.new_frames] == ["b", "c", "d", "e"]
    assert result.diagnostics.rotations_crossed == 3
    assert result.max_observed_sequence == 3


def test_deleting_consumed_segment_below_cursor_does_not_flag_top_run(tmp_path: Path) -> None:
    # NO FALSE POSITIVE on an acked-below deletion: a rotated segment the cursor already CONSUMED
    # (strictly below it) may be deleted safely, and the top-run detector must not fire on it. The
    # cursor is in seg2; seg1 (fully consumed) is removed while the top M (=3) still matches the
    # high-water, so neither ROTATION_GONE nor TOP_RUN_GONE is raised.
    path = _outbox(tmp_path, _frame_line(kind="a") + _frame_line(kind="b"))
    _rotate(path, 1)  # seg1 = [a, b]
    _write(path, _frame_line(kind="c") + _frame_line(kind="d"))
    cursor = _cursor_for(path, _frame_line(kind="c"))  # cursor in the future seg2, consumed "c"
    _rotate(path, 2)  # seg2 = [c, d]
    _write(path, _frame_line(kind="e"))
    _rotate(path, 3)  # seg3 = [e]
    _write(path, _frame_line(kind="f"))  # active = [f]
    os.unlink(path.parent / "feedback-outbox.00000001.jsonl")  # drop the consumed below-cursor seg

    config = OutboxReaderConfig(rotation_glob=_ROTATION_GLOB)
    result = read_outbox(
        file_path=path, prior_cursor=cursor, config=config, last_acknowledged_sequence=3
    )
    # seg1 was below the cursor and already consumed, so its deletion is invisible; M (=3) equals
    # the high-water, so TOP_RUN_GONE does not fire either. (Deleting the cursor's OWN file would
    # instead surface as ROTATION_GONE -- still not a top-run false positive.)
    assert result.loss_signal is None
    assert [frame.kind for frame in result.new_frames] == ["d", "e", "f"]
    assert result.max_observed_sequence == 3


def test_max_observed_sequence_reports_top_retained_padded_rotation(tmp_path: Path) -> None:
    # The highest retained rotated sequence (M) is reported for the caller's monotonic high-water.
    path = _outbox(tmp_path, _frame_line(kind="a") + _frame_line(kind="b"))
    cursor = _cursor_for(path, _frame_line(kind="a"))
    _rotate(path, 1)
    _write(path, _frame_line(kind="c"))
    _rotate(path, 2)
    _write(path, _frame_line(kind="d"))

    config = OutboxReaderConfig(rotation_glob=_ROTATION_GLOB)
    result = read_outbox(file_path=path, prior_cursor=cursor, config=config)
    assert result.loss_signal is None
    assert result.max_observed_sequence == 2


def test_max_observed_sequence_orders_unpadded_names_numerically(tmp_path: Path) -> None:
    # Unpadded "...9"/"...10"/"...11": M must be the NUMERIC max (11), not the lexical max ("9").
    path = _outbox(tmp_path, _frame_line(kind="a") + _frame_line(kind="b"))
    cursor = _cursor_for(path, _frame_line(kind="a"))
    _rotate_to(path, "feedback-outbox.9.jsonl")
    _write(path, _frame_line(kind="c"))
    _rotate_to(path, "feedback-outbox.10.jsonl")
    _write(path, _frame_line(kind="d"))
    _rotate_to(path, "feedback-outbox.11.jsonl")
    _write(path, _frame_line(kind="e"))

    config = OutboxReaderConfig(rotation_glob=_ROTATION_GLOB)
    result = read_outbox(file_path=path, prior_cursor=cursor, config=config)
    assert result.loss_signal is None
    assert result.max_observed_sequence == 11


def test_max_observed_sequence_is_none_when_reading_only_active_file(tmp_path: Path) -> None:
    # No rotation this read (the cursor stays in the active file): nothing rotated was observed, so
    # the high-water output is None even when a rotation glob is configured.
    path = _outbox(tmp_path, _frame_line(kind="a"))
    first = read_outbox(file_path=path, prior_cursor=None, config=OutboxReaderConfig())
    assert first.max_observed_sequence is None  # bootstrap read of the active file only

    _append(path, _frame_line(kind="b"))
    second = read_outbox(
        file_path=path,
        prior_cursor=_cursor(first.next_position_string),
        config=OutboxReaderConfig(rotation_glob=_ROTATION_GLOB),
    )
    assert second.loss_signal is None
    assert [frame.kind for frame in second.new_frames] == ["b"]
    assert second.max_observed_sequence is None  # same active inode, no rotation crossed


@pytest.mark.parametrize("bad_high_water", [-1, 2**63, "3"])
def test_reader_rejects_malformed_high_water(tmp_path: Path, bad_high_water: object) -> None:
    # The high-water is defensively bounded: a negative, over-ceiling, or non-int value fails closed
    # with a fixed code rather than letting the reader reason from a bogus mark.
    path = _outbox(tmp_path, _frame_line(kind="a"))
    with pytest.raises(OutboxError) as raised:
        read_outbox(
            file_path=path,
            prior_cursor=None,
            config=OutboxReaderConfig(),
            last_acknowledged_sequence=bad_high_water,  # type: ignore[arg-type]
        )
    assert raised.value.code == "MH_OUTBOX_HIGH_WATER"


def test_unparseable_rotated_name_fails_closed(tmp_path: Path) -> None:
    path = _outbox(tmp_path, _frame_line(kind="a"))
    cursor = _cursor_for(path, b"")
    _rotate(path, 1)
    _write(path, _frame_line(kind="b"))
    # A glob match whose wildcard is not a pure integer run breaks ordering/contiguity reasoning.
    _write(tmp_path / "feedback-outbox.backup.jsonl", _frame_line(kind="x"))

    config = OutboxReaderConfig(rotation_glob=_ROTATION_GLOB)
    result = read_outbox(file_path=path, prior_cursor=cursor, config=config)
    assert result.new_frames == ()
    assert result.loss_signal.code == "MH_OUTBOX_LOSS_ROTATION_UNPARSEABLE"


def test_duplicate_rotated_sequence_fails_closed(tmp_path: Path) -> None:
    path = _outbox(tmp_path, _frame_line(kind="a"))
    cursor = _cursor_for(path, b"")
    _rotate(path, 2)  # feedback-outbox.00000002.jsonl -> parses to 2
    _write(path, _frame_line(kind="b"))
    _write(tmp_path / "feedback-outbox.2.jsonl", _frame_line(kind="x"))  # also parses to 2

    config = OutboxReaderConfig(rotation_glob=_ROTATION_GLOB)
    result = read_outbox(file_path=path, prior_cursor=cursor, config=config)
    assert result.new_frames == ()
    assert result.loss_signal.code == "MH_OUTBOX_LOSS_ROTATION_AMBIGUOUS"


# --- reader: data-loss discontinuities ----------------------------------------------------------


def test_truncation_below_offset_is_p1_loss(tmp_path: Path) -> None:
    data = _frame_line(kind="a") + _frame_line(kind="b")
    path = _outbox(tmp_path, data)
    first = read_outbox(file_path=path, prior_cursor=None, config=OutboxReaderConfig())

    _write(path, _frame_line(kind="a")[:5])  # shrink below the committed offset
    result = read_outbox(
        file_path=path,
        prior_cursor=_cursor(first.next_position_string),
        config=OutboxReaderConfig(),
    )
    assert result.new_frames == ()
    assert result.loss_signal.code == "MH_OUTBOX_LOSS_TRUNCATED"
    assert result.loss_signal.observed_size == 5
    assert result.next_position_string == first.next_position_string  # cursor NOT advanced


def test_consumed_prefix_rewrite_is_p1_loss(tmp_path: Path) -> None:
    path = _outbox(tmp_path, _frame_line(kind="a") + _frame_line(kind="b"))
    first = read_outbox(file_path=path, prior_cursor=None, config=OutboxReaderConfig())

    # Same length or longer, but the already-consumed bytes differ -> prefix hash mismatch.
    _write(path, _frame_line(kind="X") + _frame_line(kind="b") + _frame_line(kind="c"))
    result = read_outbox(
        file_path=path,
        prior_cursor=_cursor(first.next_position_string),
        config=OutboxReaderConfig(),
    )
    assert result.new_frames == ()
    assert result.loss_signal.code == "MH_OUTBOX_LOSS_REWRITE"
    assert result.loss_signal.observed_sha256 is not None


def test_a_replaced_file_at_the_same_path_fails_closed(tmp_path: Path) -> None:
    # The outbox file is unlinked and a DIFFERENT file written at the same path. Whether the OS
    # recycles the freed inode (Linux -> same inode number, so the consumed-prefix hash catches the
    # discontinuity as REWRITE) or assigns a fresh one (macOS -> INODE_REUSE), the reader must FAIL
    # CLOSED: zero frames, a P1 loss, cursor kept -- never resuming at the old offset in a replaced
    # file. (Defense-in-depth: inode identity AND the consumed-prefix hash.)
    path = _outbox(tmp_path, _frame_line(kind="a"))
    first = read_outbox(file_path=path, prior_cursor=None, config=OutboxReaderConfig())

    os.unlink(path)
    _write(path, _frame_line(kind="b"))  # a different file at the same path, no rotation glob
    result = read_outbox(
        file_path=path,
        prior_cursor=_cursor(first.next_position_string),
        config=OutboxReaderConfig(),
    )
    assert result.new_frames == ()
    assert result.loss_signal is not None
    assert result.loss_signal.priority == "P1"
    assert result.loss_signal.code in ("MH_OUTBOX_LOSS_INODE_REUSE", "MH_OUTBOX_LOSS_REWRITE")
    assert result.next_position_string == first.next_position_string  # cursor NOT advanced


def test_a_genuinely_different_inode_at_the_path_is_inode_reuse(tmp_path: Path) -> None:
    # Deterministic INODE_REUSE on every platform: create a second file (a fresh inode, distinct
    # from the still-live outbox), then atomically rename it onto the outbox path so the path now
    # resolves to an inode that is NOT the cursor's. With no rotation glob the reader cannot find
    # where the old bytes went -> MH_OUTBOX_LOSS_INODE_REUSE (zero frames, cursor unadvanced).
    path = _outbox(tmp_path, _frame_line(kind="a"))
    first = read_outbox(file_path=path, prior_cursor=None, config=OutboxReaderConfig())

    replacement = tmp_path / "replacement.jsonl"
    _write(replacement, _frame_line(kind="b"))
    os.rename(replacement, path)  # path now resolves to the replacement's (different) inode
    result = read_outbox(
        file_path=path,
        prior_cursor=_cursor(first.next_position_string),
        config=OutboxReaderConfig(),
    )
    assert result.new_frames == ()
    assert result.loss_signal.code == "MH_OUTBOX_LOSS_INODE_REUSE"
    assert result.next_position_string == first.next_position_string


def test_loss_signal_and_diagnostics_are_privacy_safe(tmp_path: Path) -> None:
    canary = f"PRIVATE-{secrets.token_hex(12)}"
    path = _outbox(tmp_path, _frame_line(kind="a", data={"note": canary}))
    first = read_outbox(file_path=path, prior_cursor=None, config=OutboxReaderConfig())
    # Rewrite the consumed prefix (whose bytes carried the canary) -> loss.
    _write(path, _frame_line(kind="Z", data={"note": canary}) + _frame_line(kind="b"))
    result = read_outbox(
        file_path=path,
        prior_cursor=_cursor(first.next_position_string),
        config=OutboxReaderConfig(),
    )
    assert result.loss_signal is not None
    assert canary not in _surfaces(result.loss_signal, result.diagnostics)


# --- reader: hard failures ----------------------------------------------------------------------


def test_missing_file_fails_closed(tmp_path: Path) -> None:
    with pytest.raises(OutboxError) as raised:
        read_outbox(
            file_path=tmp_path / "absent.jsonl", prior_cursor=None, config=OutboxReaderConfig()
        )
    assert raised.value.code == "MH_OUTBOX_NOT_FOUND"


def test_symlinked_outbox_is_rejected(tmp_path: Path) -> None:
    real = _outbox(tmp_path, _frame_line())
    link = tmp_path / "link.jsonl"
    link.symlink_to(real)
    with pytest.raises(OutboxError) as raised:
        read_outbox(file_path=link, prior_cursor=None, config=OutboxReaderConfig())
    assert raised.value.code == "MH_OUTBOX_NOT_REGULAR"


def test_file_over_max_bytes_fails_closed(tmp_path: Path) -> None:
    path = _outbox(tmp_path, _frame_line() * 4)
    config = OutboxReaderConfig(max_line_bytes=16, max_file_bytes=32)
    with pytest.raises(OutboxError) as raised:
        read_outbox(file_path=path, prior_cursor=None, config=config)
    assert raised.value.code == "MH_OUTBOX_FILE_OVERSIZE"


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_line_bytes": 0},
        {"max_line_bytes": 100, "max_file_bytes": 50},
        {"rotation_glob": "sub/dir/*.jsonl"},
        {"rotation_glob": ".."},
        {"rotation_glob": "no-wildcard.jsonl"},  # missing the '*' sequence wildcard
        {"rotation_glob": "a*b*c"},  # two wildcards -> ambiguous sequence position
    ],
)
def test_reader_config_rejects_invalid_knobs(kwargs: dict[str, object]) -> None:
    with pytest.raises(OutboxError) as raised:
        OutboxReaderConfig(**kwargs)  # type: ignore[arg-type]
    assert raised.value.code == "MH_OUTBOX_CONFIG"


# --- ack format + atomic writer -----------------------------------------------------------------


def _ack(**overrides: object) -> OutboxAckV1:
    values: dict[str, object] = {
        "producer_id": "web-ci",
        "file_device": 1,
        "file_inode": 42,
        "committed_offset": 128,
        "content_sha256": hashlib.sha256(b"prefix").hexdigest(),
        "last_line_sha256": hashlib.sha256(b"line").hexdigest(),
        "acknowledged_at": datetime(2026, 8, 17, 12, 0, 0, tzinfo=UTC),
    }
    values.update(overrides)
    return OutboxAckV1(**values)  # type: ignore[arg-type]


def _ack_dir(tmp_path: Path) -> Path:
    """A guaranteed owner-only 0700 `.milhouse` dir (the ack now requires a private parent)."""

    directory = tmp_path / ".milhouse"
    directory.mkdir()
    os.chmod(directory, 0o700)
    return directory


def test_ack_round_trips_atomically_at_0600(tmp_path: Path) -> None:
    directory = _ack_dir(tmp_path)
    ack = _ack()
    write_outbox_ack(directory, "outbox-ack.json", ack)
    published = directory / "outbox-ack.json"
    assert (published.stat().st_mode & 0o777) == 0o600
    assert read_outbox_ack(directory, "outbox-ack.json") == ack


def test_ack_atomic_replace_overwrites_prior_value(tmp_path: Path) -> None:
    directory = _ack_dir(tmp_path)
    write_outbox_ack(directory, "outbox-ack.json", _ack(committed_offset=1))
    write_outbox_ack(directory, "outbox-ack.json", _ack(committed_offset=2))
    assert read_outbox_ack(directory, "outbox-ack.json").committed_offset == 2
    # No staging artifact is left behind.
    leftovers = [entry.name for entry in directory.iterdir() if entry.name != "outbox-ack.json"]
    assert leftovers == []


def test_ack_absent_returns_none(tmp_path: Path) -> None:
    assert read_outbox_ack(_ack_dir(tmp_path), "outbox-ack.json") is None


def test_ack_rejects_symlinked_path(tmp_path: Path) -> None:
    directory = _ack_dir(tmp_path)
    real = directory / "real.json"
    real.write_bytes(outbox_ack_bytes(_ack()))
    os.chmod(real, 0o600)
    link = directory / "outbox-ack.json"
    link.symlink_to(real)
    with pytest.raises(OutboxError) as raised:
        read_outbox_ack(directory, "outbox-ack.json")
    assert raised.value.code == "MH_OUTBOX_ACK_UNSAFE"


def test_ack_rejects_non_0600_file(tmp_path: Path) -> None:
    directory = _ack_dir(tmp_path)
    published = directory / "outbox-ack.json"
    published.write_bytes(outbox_ack_bytes(_ack()))
    os.chmod(published, 0o644)
    with pytest.raises(OutboxError) as raised:
        read_outbox_ack(directory, "outbox-ack.json")
    assert raised.value.code == "MH_OUTBOX_ACK_UNSAFE"


def test_ack_requires_owner_only_0700_parent(tmp_path: Path) -> None:
    # The ack lives in the Milhouse-owned .milhouse dir, so a group/world-accessible parent is bad.
    insecure = tmp_path / "insecure"
    insecure.mkdir()
    os.chmod(insecure, 0o755)
    with pytest.raises(OutboxError) as write_raised:
        write_outbox_ack(insecure, "outbox-ack.json", _ack())
    assert write_raised.value.code == "MH_OUTBOX_ACK_UNSAFE"

    published = insecure / "outbox-ack.json"
    published.write_bytes(outbox_ack_bytes(_ack()))
    os.chmod(published, 0o600)
    with pytest.raises(OutboxError) as read_raised:
        read_outbox_ack(insecure, "outbox-ack.json")
    assert read_raised.value.code == "MH_OUTBOX_ACK_UNSAFE"


@pytest.mark.parametrize("filename", ["../escape.json", "sub/ack.json", "..", "."])
def test_ack_rejects_traversal_filenames(tmp_path: Path, filename: str) -> None:
    with pytest.raises(OutboxError) as raised:
        read_outbox_ack(_ack_dir(tmp_path), filename)
    assert raised.value.code == "MH_OUTBOX_ACK_PATH"


def test_ack_read_rejects_corrupt_and_foreign_content(tmp_path: Path) -> None:
    directory = _ack_dir(tmp_path)
    published = directory / "outbox-ack.json"
    published.write_bytes(b'{"not":"an ack"}')
    os.chmod(published, 0o600)
    with pytest.raises(OutboxError) as raised:
        read_outbox_ack(directory, "outbox-ack.json")
    assert raised.value.code == "MH_OUTBOX_ACK"


def test_ack_round_trips_last_sequence_high_water(tmp_path: Path) -> None:
    # The rotation high-water persists in the ack and reads back atomically; a default ack (None)
    # still omits it, so the field is backward-compatible.
    directory = _ack_dir(tmp_path)
    assert _ack().last_sequence is None  # default: omitted from the canonical bytes
    ack = _ack(last_sequence=7)
    write_outbox_ack(directory, "outbox-ack.json", ack)
    loaded = read_outbox_ack(directory, "outbox-ack.json")
    assert loaded == ack
    assert loaded is not None
    assert loaded.last_sequence == 7


@pytest.mark.parametrize("bad_value", [-1, 2**63, 1.5, "5"])
def test_ack_rejects_malformed_last_sequence(tmp_path: Path, bad_value: object) -> None:
    # A negative, over-ceiling, non-integer, or string last_sequence in a planted ack is rejected
    # value-free with the fixed MH_OUTBOX_ACK code (never resuming from a bogus high-water).
    directory = _ack_dir(tmp_path)
    published = directory / "outbox-ack.json"
    planted = json.loads(outbox_ack_bytes(_ack()))
    planted["last_sequence"] = bad_value
    published.write_bytes(json.dumps(planted).encode("utf-8"))
    os.chmod(published, 0o600)
    with pytest.raises(OutboxError) as raised:
        read_outbox_ack(directory, "outbox-ack.json")
    assert raised.value.code == "MH_OUTBOX_ACK"


# --- reader: guards, config validation, and none-cursor rotation edges (coverage) ---------------


def test_read_outbox_rejects_a_non_config() -> None:
    with pytest.raises(OutboxError) as err:
        read_outbox(file_path="/x", prior_cursor=None, config=object())  # type: ignore[arg-type]
    assert err.value.code == "MH_OUTBOX_CONFIG"


def test_read_outbox_rejects_a_non_cursor() -> None:
    with pytest.raises(OutboxError) as err:
        read_outbox(
            file_path="/x",
            prior_cursor=object(),  # type: ignore[arg-type]
            config=OutboxReaderConfig(),
        )
    assert err.value.code == "MH_OUTBOX_CURSOR"


def test_config_rejects_an_empty_rotation_glob() -> None:
    with pytest.raises(OutboxError) as err:
        OutboxReaderConfig(rotation_glob="")
    assert err.value.code == "MH_OUTBOX_CONFIG"


def test_config_rejects_a_non_string_producer_allowlist_entry() -> None:
    with pytest.raises(OutboxError) as err:
        OutboxReaderConfig(producer_allowlist=("ok", 1))  # type: ignore[arg-type]
    assert err.value.code == "MH_OUTBOX_CONFIG"


def test_read_outbox_on_a_directory_is_not_regular(tmp_path: Path) -> None:
    directory = tmp_path / "a-directory"
    directory.mkdir()
    with pytest.raises(OutboxError) as err:
        read_outbox(file_path=directory, prior_cursor=None, config=OutboxReaderConfig())
    assert err.value.code == "MH_OUTBOX_NOT_REGULAR"


def test_first_read_no_cursor_unparseable_rotation_is_loss(tmp_path: Path) -> None:
    path = _outbox(tmp_path, _frame_line(kind="a"))
    # matches the glob but the wildcard is not a pure integer run
    _write(path.parent / "feedback-outbox.abc.jsonl", _frame_line(kind="x"))
    result = read_outbox(
        file_path=path, prior_cursor=None, config=OutboxReaderConfig(rotation_glob=_ROTATION_GLOB)
    )
    assert result.new_frames == ()
    assert result.loss_signal is not None
    assert result.loss_signal.code == "MH_OUTBOX_LOSS_ROTATION_UNPARSEABLE"


def test_first_read_no_cursor_torn_rotation_is_loss(tmp_path: Path) -> None:
    path = _outbox(tmp_path, _frame_line(kind="a"))
    _write(path.parent / "feedback-outbox.00000001.jsonl", b"torn line without a newline")
    result = read_outbox(
        file_path=path, prior_cursor=None, config=OutboxReaderConfig(rotation_glob=_ROTATION_GLOB)
    )
    assert result.new_frames == ()
    assert result.loss_signal is not None
    assert result.loss_signal.code == "MH_OUTBOX_LOSS_ROTATED_TORN"


def test_first_read_no_cursor_glob_matching_active_link_is_excluded(tmp_path: Path) -> None:
    # A hard link with a rotated-looking name that resolves to the ACTIVE inode is excluded (never
    # double-counted), so the read falls back to the active file alone.
    path = _outbox(tmp_path, _frame_line(kind="a"))
    os.link(path, path.parent / "feedback-outbox.00000001.jsonl")
    result = read_outbox(
        file_path=path, prior_cursor=None, config=OutboxReaderConfig(rotation_glob=_ROTATION_GLOB)
    )
    assert result.loss_signal is None
    assert [frame.kind for frame in result.new_frames] == ["a"]


def test_rotated_cursor_file_truncated_below_offset_is_loss(tmp_path: Path) -> None:
    body = _frame_line(kind="a") + _frame_line(kind="b")
    path = _outbox(tmp_path, body)
    cursor = _cursor_for(path, body)  # consumed A+B
    rotated = _rotate(path, 1)
    _write(path, _frame_line(kind="c"))
    with rotated.open("r+b") as handle:
        handle.truncate(5)  # shrink the rotated cursor file below the cursor offset
    result = read_outbox(
        file_path=path, prior_cursor=cursor, config=OutboxReaderConfig(rotation_glob=_ROTATION_GLOB)
    )
    assert result.new_frames == ()
    assert result.loss_signal is not None
    assert result.loss_signal.code == "MH_OUTBOX_LOSS_TRUNCATED"


def test_rotated_cursor_file_rewritten_prefix_is_loss(tmp_path: Path) -> None:
    path = _outbox(tmp_path, _frame_line(kind="a"))
    cursor = _cursor_for(path, _frame_line(kind="a"))  # consumed A
    rotated = _rotate(path, 1)
    _write(path, _frame_line(kind="c"))
    # rewrite the consumed prefix with a same-length but different frame -> prefix hash mismatch
    rotated.write_bytes(_frame_line(kind="z"))
    result = read_outbox(
        file_path=path, prior_cursor=cursor, config=OutboxReaderConfig(rotation_glob=_ROTATION_GLOB)
    )
    assert result.new_frames == ()
    assert result.loss_signal is not None
    assert result.loss_signal.code == "MH_OUTBOX_LOSS_REWRITE"


def test_torn_rotated_file_above_cursor_is_loss(tmp_path: Path) -> None:
    # The cursor sits (consuming nothing) in the file that becomes seq 1; seq 2 -- ABOVE the cursor
    # -- is torn, so the whole recovery fails closed.
    path = _outbox(tmp_path, _frame_line(kind="a"))
    cursor = _cursor_for(path, b"")
    _rotate(path, 1)  # seq 1 = A (complete), the cursor's file
    _write(path, b"torn-no-newline")
    _rotate(path, 2)  # seq 2 = torn, above the cursor
    _write(path, _frame_line(kind="c"))
    result = read_outbox(
        file_path=path, prior_cursor=cursor, config=OutboxReaderConfig(rotation_glob=_ROTATION_GLOB)
    )
    assert result.new_frames == ()
    assert result.loss_signal is not None
    assert result.loss_signal.code == "MH_OUTBOX_LOSS_ROTATED_TORN"
