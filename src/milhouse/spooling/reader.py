"""Segment reader: the fail-closed inverse of the segment writer (W03 slice 3b).

Reconciliation, replay, and ``spool verify`` need to read a durable segment file back and validate
it, even when the file is a crash artifact, a foreign write, or deliberately tampered. This module
draws a hard line between two trust levels so a caller cannot accidentally accept untrusted bytes as
durable state:

* ``parse_segment_bytes`` is the **untrusted structural parser**. It splits the self-describing
  segment into a header line and ordered frame lines, rebuilds the typed ``SegmentHeaderV1`` and
  ``SpoolFrameV1`` records, and re-encodes each line with the canonical writer to prove it is
  byte-for-byte canonical, then verifies frame count, contiguous sequence, header/frame agreement,
  and the ordered-frame ``content_sha256``. It proves canonical form and internal self-consistency —
  not provenance — so its result must be used only for diagnostics, quarantine classification, or
  salvage, never accepted, registered, replayed, or exported as trusted durable state.
* ``read_untrusted_segment`` reads such a file (no-follow, size-bounded) and structurally parses it,
  for the same diagnostics-only purposes.
* ``read_trusted_segment`` is the **only** acceptance path. It opens the file no-follow under an
  owned ``0700`` parent, requires the descriptor to be a regular, owner-only ``0600``, single-link,
  ACL-safe file, reads it under the size bound, re-checks the descriptor snapshot after the read to
  reject any mutation during selection, and then **mandatorily** re-derives every record's
  deterministic identity against a required ``installation_id`` so a canonical-but-forged or foreign
  record fails closed. There is no optional argument that can bypass provenance.

Every failure is a fixed ``MH_SPOOL_*`` error raised outside any handler, so no filesystem, JSON,
record, or caller-supplied identity detail reaches its cause, context, args, or traceback. The
reader never mutates; quarantine, orphan registration, and torn-frame recovery are later slices that
build on the fixed error codes this reader raises to classify a corrupt file.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import NoReturn

from milhouse.config.filesystem import (
    FileIdentity,
    FileSnapshot,
    SecureFileError,
    SecureFileErrorKind,
    open_regular_file_no_follow,
)
from milhouse.domain.records import (
    RecordEnvelopeV1,
    RecordError,
    verify_record_identity,
)
from milhouse.spooling.errors import SpoolError
from milhouse.spooling.segment import (
    FRAME_VERSION,
    MAX_FRAME_LINE_BYTES,
    MAX_HEADER_LINE_BYTES,
    MAX_SEGMENT_FILE_BYTES,
    MAX_SEGMENT_FRAMES,
    SCHEMA_VERSION,
    SegmentHeaderV1,
    SpoolFrameV1,
    spool_content_sha256,
    spool_frame_line,
    spool_segment_header_line,
)

_LF = b"\n"
_TRUSTED_FILE_MODE = 0o600
# The same installation-id shape the domain enforces (identity.py InstallationIdV1), validated at
# the trusted-reader boundary so a malformed value fails closed as a fixed code rather than leaking
# out of a downstream pydantic error.
INSTALLATION_ID_PATTERN = re.compile(
    r"mh_in1_[0-9a-f]{12}4[0-9a-f]{3}[89ab][0-9a-f]{15}", flags=re.ASCII
)

_HEADER_KEYS = frozenset(
    {
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
)
_FRAME_KEYS = frozenset({"batch_id", "frame_version", "record", "record_id", "sequence"})

_READ_CODE_BY_KIND = {
    SecureFileErrorKind.NOT_FOUND: "MH_SPOOL_NOT_FOUND",
    SecureFileErrorKind.NOT_REGULAR: "MH_SPOOL_NOT_REGULAR",
    SecureFileErrorKind.PARENT_UNSAFE: "MH_SPOOL_UNSAFE",
    SecureFileErrorKind.ACCESS_CONTROL_UNSAFE: "MH_SPOOL_UNSAFE",
}


@dataclass(frozen=True, slots=True)
class ParsedSegment:
    """A structurally validated, canonical, internally self-consistent durable segment.

    A ``ParsedSegment`` from the untrusted structural parser proves canonical form only; it is
    proven trusted durable state solely when returned by ``read_trusted_segment``, which
    additionally enforces secure file metadata and mandatory record-identity provenance.
    """

    header: SegmentHeaderV1
    frames: tuple[SpoolFrameV1, ...]
    byte_size: int
    file_sha256: str


def _current_uid() -> int:
    # Match the W02 secure-file writer and the durable-commit store, which validate against euid.
    geteuid = getattr(os, "geteuid", None)
    if geteuid is None:  # pragma: no cover - Milhouse supports only POSIX hosts
        _fail("MH_SPOOL_UNSUPPORTED", "the spool requires a POSIX ownership model")
    return int(geteuid())


def _fail(code: str, message: str) -> NoReturn:
    raise SpoolError(code, message)


def _json_object(line: bytes, code: str) -> dict[str, object]:
    """Decode one bounded JSONL line to a JSON object, failing closed on any malformed input."""

    failed = False
    value: object = None
    try:
        value = json.loads(line.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        failed = True
    if failed or type(value) is not dict:
        _fail(code, "a canonical JSON object line is required")
    return value


def _reconstruct_record(payload: dict[str, object]) -> RecordEnvelopeV1:
    """Rebuild the finalized record envelope, failing closed so no record detail leaks.

    The envelope is a strict model whose Python-mode validation refuses to coerce the RFC3339 string
    timestamps the wire carries, so the record is re-parsed through pydantic's JSON mode, which
    accepts the canonical string forms exactly as they were written.
    """

    failed = False
    record: RecordEnvelopeV1 | None = None
    try:
        record = RecordEnvelopeV1.model_validate_json(json.dumps(payload))
    except Exception:
        failed = True
    if failed or record is None:
        _fail("MH_SPOOL_RECORD", "a finalized record envelope is required")
    return record


def _parse_header(line: bytes) -> SegmentHeaderV1:
    obj = _json_object(line, "MH_SPOOL_HEADER")
    if frozenset(obj) != _HEADER_KEYS:
        _fail("MH_SPOOL_HEADER", "the header line has unexpected fields")
    if obj["schema"] != SCHEMA_VERSION or obj["frame_version"] != FRAME_VERSION:
        _fail("MH_SPOOL_HEADER", "an unsupported segment schema or frame version")
    exporters = obj["required_exporters"]
    if type(exporters) is not list:
        _fail("MH_SPOOL_HEADER", "required exporters must be a list")
    # SegmentHeaderV1 validates every field value and raises a fixed MH_SPOOL_* with clean context.
    header = SegmentHeaderV1(
        batch_id=obj["batch_id"],  # type: ignore[arg-type]
        config_generation=obj["config_generation"],  # type: ignore[arg-type]
        scope=obj["scope"],  # type: ignore[arg-type]
        target_id=obj["target_id"],  # type: ignore[arg-type]
        privacy_class=obj["privacy_class"],  # type: ignore[arg-type]
        retention_days=obj["retention_days"],  # type: ignore[arg-type]
        required_exporters=tuple(exporters),
        record_count=obj["record_count"],  # type: ignore[arg-type]
        content_sha256=obj["content_sha256"],  # type: ignore[arg-type]
    )
    if spool_segment_header_line(header) != line:
        _fail("MH_SPOOL_HEADER", "the header line is not canonical")
    return header


def _parse_frame(line: bytes, header: SegmentHeaderV1, expected_sequence: int) -> SpoolFrameV1:
    obj = _json_object(line, "MH_SPOOL_FRAME")
    if frozenset(obj) != _FRAME_KEYS:
        _fail("MH_SPOOL_FRAME", "the frame line has unexpected fields")
    if obj["frame_version"] != FRAME_VERSION:
        _fail("MH_SPOOL_FRAME", "an unsupported frame version")
    if type(obj["record"]) is not dict:
        _fail("MH_SPOOL_FRAME", "the frame record must be a JSON object")
    record = _reconstruct_record(obj["record"])
    # SpoolFrameV1 validates the batch id and sequence and raises a fixed MH_SPOOL_* cleanly.
    frame = SpoolFrameV1(batch_id=obj["batch_id"], sequence=obj["sequence"], record=record)  # type: ignore[arg-type]
    if frame.sequence != expected_sequence:
        _fail("MH_SPOOL_SEQUENCE", "frame sequences must be contiguous from 1")
    if frame.batch_id != header.batch_id:
        _fail("MH_SPOOL_BATCH_ID", "each frame batch id must match the header")
    if obj["record_id"] != record.record_id:
        _fail("MH_SPOOL_RECORD", "the frame record id must match its record")
    if record.scope != header.scope:
        _fail("MH_SPOOL_SCOPE", "each frame scope must match the header")
    record_target = record.target.id if record.target is not None else None
    if record_target != header.target_id:
        _fail("MH_SPOOL_TARGET", "each frame target must match the header")
    if record.privacy_class != header.privacy_class:
        _fail("MH_SPOOL_PRIVACY", "each frame privacy class must match the header")
    if spool_frame_line(frame) != line:
        _fail("MH_SPOOL_FRAME", "the frame line is not canonical")
    return frame


def _verify_identity(frames: tuple[SpoolFrameV1, ...], installation_id: str) -> None:
    """Verify each frame's deterministic record identity against the given installation.

    Canonical form and internal self-consistency do not prove a record was minted by this
    installation; only re-deriving ``record_id``/``dedupe_key`` from the body and the installation
    id does. A mismatch means a forged or foreign record and fails closed with ``MH_SPOOL_RECORD``.
    """

    failed = False
    try:
        for frame in frames:
            verify_record_identity(frame.record, installation_id=installation_id)
    except RecordError:
        failed = True
    if failed:
        _fail("MH_SPOOL_RECORD", "a frame record identity does not match its body")


def _split_lines(content: bytes) -> tuple[bytes, tuple[bytes, ...]]:
    """Split trailing-LF-terminated content into the header line and ordered frame lines.

    Canonical JSON escapes every control character, so a line feed only ever appears as a line
    terminator; splitting on it cannot break a line apart.
    """

    if len(content) > MAX_SEGMENT_FILE_BYTES:
        _fail("MH_SPOOL_SIZE", "the segment exceeds the maximum size")
    if not content:
        _fail("MH_SPOOL_TRUNCATED", "a segment must contain at least a header line")
    if not content.endswith(_LF):
        _fail("MH_SPOOL_TRUNCATED", "the segment does not end with a complete line")
    parts = content.split(_LF)[:-1]  # drop the empty tail after the final terminator
    lines = []
    for index, part in enumerate(parts):
        if not part:
            _fail("MH_SPOOL_TRUNCATED", "the segment contains a blank line")
        line = part + _LF
        limit = MAX_HEADER_LINE_BYTES if index == 0 else MAX_FRAME_LINE_BYTES
        if len(line) > limit:
            _fail("MH_SPOOL_LINE", "a segment line exceeds its byte bound")
        lines.append(line)
    return lines[0], tuple(lines[1:])


def parse_segment_bytes(content: bytes) -> ParsedSegment:
    """Structurally parse and canonically validate segment bytes (UNTRUSTED).

    The returned frames are byte-for-byte canonical and internally self-consistent: a line that
    parses but is not canonical is rejected, and the reader never trusts the header's declared count
    or digest without re-deriving them from the actual frame bytes. This proves canonical form, not
    provenance: the result must be used only for diagnostics, quarantine classification, or salvage,
    never accepted, registered, replayed, or exported as trusted durable state. The trusted
    acceptance path is :func:`read_trusted_segment`, which additionally proves record identity.
    """

    if type(content) is not bytes:
        _fail("MH_SPOOL_READ", "segment content must be bytes")
    header_line, frame_lines = _split_lines(content)
    # Bound the real frame list before the expensive per-frame reconstruction, not just the header's
    # attacker-declared count, so a hostile many-frame file cannot amplify memory unchecked.
    if len(frame_lines) > MAX_SEGMENT_FRAMES:
        _fail("MH_SPOOL_COUNT", "the segment contains more frames than the reader admits")
    header = _parse_header(header_line)
    frames = tuple(
        _parse_frame(line, header, sequence) for sequence, line in enumerate(frame_lines, start=1)
    )
    if len(frames) != header.record_count:
        _fail("MH_SPOOL_COUNT", "the frame count does not match the header")
    if spool_content_sha256(frame_lines) != header.content_sha256:
        _fail("MH_SPOOL_DIGEST", "the header digest does not match the frame bytes")
    return ParsedSegment(
        header=header,
        frames=frames,
        byte_size=len(content),
        file_sha256=hashlib.sha256(content).hexdigest(),
    )


def _require_installation_id(installation_id: str) -> None:
    if (
        type(installation_id) is not str
        or INSTALLATION_ID_PATTERN.fullmatch(installation_id) is None
    ):
        # Contained here so a malformed caller-supplied id never reaches a downstream pydantic error
        # that would echo the rejected input.
        _fail("MH_SPOOL_IDENTITY", "a well-formed installation id is required")


def _open_regular(
    path: str | Path, *, require_private_parent: bool
) -> tuple[int, FileSnapshot, FileIdentity]:
    kind: SecureFileErrorKind | None = None
    descriptor: int | None = None
    snapshot: FileSnapshot | None = None
    parent: FileIdentity | None = None
    try:
        opened = open_regular_file_no_follow(path, require_private_parent=require_private_parent)
        descriptor = opened.descriptor
        snapshot = opened.snapshot
        parent = opened.parent_identity
    except SecureFileError as error:
        kind = error.kind
    if kind is not None:
        _fail(_READ_CODE_BY_KIND.get(kind, "MH_SPOOL_READ"), "the segment file could not be opened")
    if descriptor is None or snapshot is None or parent is None:  # pragma: no cover - defensive
        _fail("MH_SPOOL_READ", "the segment file could not be opened")
    return descriptor, snapshot, parent


def _is_trusted_regular_file(metadata: os.stat_result) -> bool:
    # The owned 0700 parent and the file's extended-ACL safety are enforced at the open layer by
    # ``open_regular_file_no_follow(require_private_parent=True)``; this only adds the leaf's mode,
    # owner, regular-file, and single-link checks. The trusted reader must keep opening with
    # ``require_private_parent=True`` or the ACL/parent guarantees would silently vanish.
    return (
        stat.S_ISREG(metadata.st_mode)
        and metadata.st_uid == _current_uid()
        and stat.S_IMODE(metadata.st_mode) == _TRUSTED_FILE_MODE
        and metadata.st_nlink == 1
    )


def _read_descriptor(descriptor: int, opened_snapshot: FileSnapshot, *, harden: bool) -> bytes:
    unsafe = False
    changed = False
    oversize = False
    read_failed = False
    data = b""
    try:
        metadata = os.fstat(descriptor)
        if harden and not _is_trusted_regular_file(metadata):
            # Not an owner-only 0600 single-link regular file: reject before reading any bytes.
            unsafe = True
        elif metadata.st_size > MAX_SEGMENT_FILE_BYTES:
            oversize = True
        else:
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(descriptor, 1 << 20)
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > MAX_SEGMENT_FILE_BYTES:
                    oversize = True
                    break
            data = b"".join(chunks)
            if harden and FileSnapshot.from_stat(os.fstat(descriptor)) != opened_snapshot:
                # The file was replaced or rewritten between selection and the end of the read.
                changed = True
    except OSError:
        read_failed = True
    finally:
        try:
            os.close(descriptor)
        except OSError:
            read_failed = True
    if unsafe:
        _fail("MH_SPOOL_UNSAFE", "the segment file is not an owner-only single-link regular file")
    if oversize:
        _fail("MH_SPOOL_SIZE", "the segment file exceeds the maximum size")
    if changed:
        _fail("MH_SPOOL_CHANGED", "the segment file changed during the read")
    if read_failed:
        _fail("MH_SPOOL_READ", "the segment file could not be read")
    return data


def read_untrusted_segment(path: str | Path) -> ParsedSegment:
    """Read and structurally parse a possibly-corrupt segment file (UNTRUSTED, diagnostics only).

    The file is opened read-only with no-follow semantics and its size is bounded before any bytes
    are read, but its ownership, mode, link count, and record provenance are NOT checked, because
    the caller is expected to be classifying a suspect file for quarantine or salvage. A missing
    file fails with ``MH_SPOOL_NOT_FOUND`` and a symlink or non-regular file with
    ``MH_SPOOL_NOT_REGULAR``. The result must never be accepted, registered, replayed, or exported
    as trusted durable state; use :func:`read_trusted_segment` for that.
    """

    descriptor, snapshot, _parent = _open_regular(path, require_private_parent=False)
    return parse_segment_bytes(_read_descriptor(descriptor, snapshot, harden=False))


def read_trusted_segment(
    path: str | Path,
    *,
    installation_id: str,
    expected_parent: FileIdentity | None = None,
) -> ParsedSegment:
    """Securely read and fully validate a durable segment as trusted state (the acceptance path).

    ``installation_id`` is mandatory: the file is opened no-follow under an owned ``0700`` parent,
    the descriptor is required to be a regular, owner-only ``0600``, single-link, ACL-safe file, the
    bytes are read under the size bound and re-checked against the open-time snapshot to reject any
    mutation during selection, and every record's deterministic identity is re-derived against the
    installation so a canonical-but-forged or foreign record fails closed. There is no argument that
    can bypass provenance. A caller that inventoried the parent directory earlier should pass its
    captured identity as ``expected_parent``: if the file's actual parent inode differs — the
    directory was replaced between enumeration and this read — the read fails closed with
    ``MH_SPOOL_CHANGED`` before a single content byte is consumed.
    """

    _require_installation_id(installation_id)
    descriptor, snapshot, parent = _open_regular(path, require_private_parent=True)
    if expected_parent is not None and parent != expected_parent:
        changed = True
        try:
            os.close(descriptor)
        except OSError:  # pragma: no cover - defensive: close failure on a valid descriptor
            pass
        if changed:
            _fail("MH_SPOOL_CHANGED", "the segment's parent directory changed since enumeration")
    parsed = parse_segment_bytes(_read_descriptor(descriptor, snapshot, harden=True))
    _verify_identity(parsed.frames, installation_id)
    return parsed
