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


def test_top_run_deletion_is_the_documented_undetectable_residual(tmp_path: Path) -> None:
    # DOCUMENTED RESIDUAL (increment 1, reader._recover_rotation docstring): the active file carries
    # no sequence, so deletion of a RUN of the TOPMOST rotated segments (next to the active file)
    # leaves the survivors a contiguous run that passes the gap check -- a stateless single-file
    # cursor keeps no record of the highest sequence that ever existed, so it cannot know those top
    # segments were dropped. This is closed in increment 2 by the durable ack persisting the last
    # committed sequence. We PIN the known window here so a future change that widens OR (once
    # increment 2 lands) narrows it is caught.
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

    # NO loss is signalled (the known increment-1 limitation) and d (seg3) + e (seg4) are silently
    # absent -- exactly the top-run window increment 2's ack must close.
    assert result.loss_signal is None
    assert [frame.kind for frame in result.new_frames] == ["b", "c", "f"]


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
