"""Atomic durable publication of one self-describing spool segment (W03 slice 2).

``write_spool_segment`` validates that the header and frames are mutually consistent (matching
batch id, scope, target, privacy class, contiguous sequences, exact count, and the ordered-frame
digest), then
publishes the segment bytes with the W02 secure atomic-publish primitive: a unique temporary file is
written, flushed, and fsynced, atomically renamed without replacing an existing name, and the parent
directory is fsynced. The parent directory must already exist and be private. Any failure raises a
fixed ``MH_SPOOL_*`` error outside the handler, so no filesystem detail leaks; the SQLite ledger row
and crash reconciliation are a later slice.
"""

from __future__ import annotations

from pathlib import Path
from typing import NoReturn

from milhouse.config.filesystem import (
    SecureFileError,
    SecureFileErrorKind,
    create_regular_file_no_follow,
)
from milhouse.spooling.errors import SpoolError
from milhouse.spooling.segment import (
    MAX_SEGMENT_FILE_BYTES,
    MAX_SEGMENT_FRAMES,
    SegmentHeaderV1,
    SpoolFrameV1,
    spool_content_sha256,
    spool_frame_line,
    spool_segment_header_line,
)

_SEGMENT_FILE_MODE = 0o600


def _fail(code: str, message: str) -> NoReturn:
    raise SpoolError(code, message)


def _validate_consistency(header: SegmentHeaderV1, frames: tuple[SpoolFrameV1, ...]) -> None:
    if header.record_count != len(frames):
        _fail("MH_SPOOL_COUNT", "the header record count must equal the frame count")
    for index, frame in enumerate(frames, start=1):
        if not isinstance(frame, SpoolFrameV1):
            _fail("MH_SPOOL_FRAME", "a spool frame is required")
        if frame.sequence != index:
            _fail("MH_SPOOL_SEQUENCE", "frame sequences must be contiguous from 1")
        if frame.batch_id != header.batch_id:
            _fail("MH_SPOOL_BATCH_ID", "each frame batch id must match the header")
        record = frame.record
        if record.scope != header.scope:
            _fail("MH_SPOOL_SCOPE", "each frame scope must match the header")
        record_target = record.target.id if record.target is not None else None
        if record_target != header.target_id:
            _fail("MH_SPOOL_TARGET", "each frame target must match the header")
        if record.privacy_class != header.privacy_class:
            _fail("MH_SPOOL_PRIVACY", "each frame privacy class must match the header")


def _create_segment_file(path: str | Path, content: bytes) -> None:
    exists = False
    failed = False
    try:
        create_regular_file_no_follow(
            path, content, mode=_SEGMENT_FILE_MODE, require_private_parent=True
        )
    except SecureFileError as error:
        if error.kind is SecureFileErrorKind.ALREADY_EXISTS:
            exists = True
        else:
            failed = True
    if exists:
        _fail("MH_SPOOL_EXISTS", "a segment already exists at that name")
    if failed:
        _fail("MH_SPOOL_WRITE", "the segment could not be durably published")


def publish_segment_bytes(path: str | Path, content: bytes) -> None:
    _create_segment_file(path, content)


def build_segment_bytes(
    header: SegmentHeaderV1, frames: tuple[SpoolFrameV1, ...] | list[SpoolFrameV1]
) -> bytes:
    """Validate header/frame consistency and return the exact segment bytes (header line + frames).

    The header must already carry the digest of the ordered frame bytes; this re-validates it so the
    returned bytes are internally verifiable. Raises a fixed ``MH_SPOOL_*`` error on any mismatch.
    """

    if not isinstance(header, SegmentHeaderV1):
        _fail("MH_SPOOL_HEADER", "a segment header is required")
    if not isinstance(frames, (tuple, list)):
        _fail("MH_SPOOL_FRAMES", "frames must be provided as a concrete sequence")
    if len(frames) > MAX_SEGMENT_FRAMES:
        _fail("MH_SPOOL_COUNT", "the segment contains more frames than the writer admits")
    frame_tuple = tuple(frames)
    _validate_consistency(header, frame_tuple)
    header_line = spool_segment_header_line(header)
    frame_lines: list[bytes] = []
    total_bytes = len(header_line)
    for frame in frame_tuple:
        line = spool_frame_line(frame)
        total_bytes += len(line)
        if total_bytes > MAX_SEGMENT_FILE_BYTES:
            _fail("MH_SPOOL_SIZE", "the segment exceeds the maximum size")
        frame_lines.append(line)
    if spool_content_sha256(frame_lines) != header.content_sha256:
        _fail("MH_SPOOL_DIGEST", "the header digest does not match the frame bytes")
    return header_line + b"".join(frame_lines)


def write_spool_segment(
    path: str | Path, header: SegmentHeaderV1, frames: tuple[SpoolFrameV1, ...] | list[SpoolFrameV1]
) -> None:
    """Atomically publish a self-describing segment whose header and frames are mutually consistent.

    Publication never overwrites an existing name.
    """

    publish_segment_bytes(path, build_segment_bytes(header, frames))
