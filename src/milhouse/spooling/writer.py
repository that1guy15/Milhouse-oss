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


def _atomic_publish(path: str | Path, content: bytes) -> None:
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


def write_spool_segment(
    path: str | Path, header: SegmentHeaderV1, frames: tuple[SpoolFrameV1, ...] | list[SpoolFrameV1]
) -> None:
    """Atomically publish a self-describing segment whose header and frames are mutually consistent.

    The header must already carry the digest of the ordered frame bytes; this re-validates it so the
    published segment is internally verifiable. Publication never overwrites an existing name.
    """

    if not isinstance(header, SegmentHeaderV1):
        _fail("MH_SPOOL_HEADER", "a segment header is required")
    if not isinstance(frames, (tuple, list)):
        _fail("MH_SPOOL_FRAMES", "frames must be provided as a concrete sequence")
    frame_tuple = tuple(frames)
    _validate_consistency(header, frame_tuple)
    frame_lines = [spool_frame_line(frame) for frame in frame_tuple]
    if spool_content_sha256(frame_lines) != header.content_sha256:
        _fail("MH_SPOOL_DIGEST", "the header digest does not match the frame bytes")
    content = spool_segment_header_line(header) + b"".join(frame_lines)
    _atomic_publish(path, content)
