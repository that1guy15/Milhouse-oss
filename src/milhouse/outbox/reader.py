"""The pure, offline-testable ``.milhouse`` outbox reader (W07 increment 1, plan section 4.9).

Given a file path, a prior cursor (or ``None``), and a bounded configuration, :func:`read_outbox`
returns the new frames since the cursor, the next cursor position, an optional P1 data-loss signal,
and privacy-safe diagnostics. It is a PURE primitive: it opens the outbox no-follow and reads it,
but it NEVER writes, never truncates or rotates the producer's file, never persists a cursor, and
never maps a frame to a canonical record -- those belong to later increments. It mirrors the
``local_log`` reader's fail-closed discipline (ADR 0016 / plan section 4.15): a torn, non-LF-
terminated tail of the ACTIVE file is left unconsumed for the next read, while any discontinuity in
already-consumed bytes fails closed.

Guarantees:

* **Unchanged input yields zero new frames.** Re-reading the same file at the same offset with a
  byte-identical consumed prefix advances nothing.
* **Append yields only new complete lines.** Only LF-terminated lines past the cursor are parsed.
* **Compliant rotation recovers without loss or duplication.** When the active inode differs from
  the cursor's, retained rotated files are discovered by their parsed INTEGER sequence (numeric
  order, not lexical), the cursor's file is read from its offset to EOF, the contiguous rotations
  above it are read whole, and reading continues into the new active file -- all in one call.
* **Truncation or removal of unacknowledged bytes is a P1 loss.** A file shorter than the cursor
  offset, a rewritten consumed prefix (hash mismatch), a gap in the rotated sequence above the
  cursor (a dropped intermediate segment), an unparseable or duplicate rotated name, a crossed
  rotated file with a torn tail, or a changed active inode with no way to locate the cursor's file
  all produce an explicit ``MH_OUTBOX_LOSS_*`` signal and advance nothing -- Milhouse cannot claim
  recovery of deleted bytes.
* **Invalid or oversized lines are rejected without raw persistence.** A line over
  ``max_line_bytes``, or one that fails :class:`OutboxFrameV1` validation, or one from a
  non-allowlisted producer, is skipped and counted by a FIXED code; its raw bytes never enter a
  frame, a diagnostic, a loss signal, or an exception. Skip-and-count keeps one bad line from
  blocking the valid lines around it while still advancing the cursor past it exactly once.

Every hard failure is a fixed ``MH_OUTBOX_*`` :class:`OutboxError`; every diagnostic and loss field
is an integer, a hex digest, or a fixed code -- never a producer byte.
"""

from __future__ import annotations

import hashlib
import os
import re
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Literal

from milhouse.config.filesystem import (
    SecureFileError,
    SecureFileErrorKind,
    lexical_absolute_path,
    open_regular_file_no_follow,
)
from milhouse.core.canonical import MAX_CANONICAL_INT
from milhouse.outbox.cursor import (
    OutboxPosition,
    encode_outbox_position,
    outbox_position_from_cursor,
)
from milhouse.outbox.errors import OutboxError
from milhouse.outbox.frame import OutboxFrameV1, parse_outbox_frame_line
from milhouse.state.cursors import SourceCursor

_LF = b"\n"

_LINE_OVERSIZE_CODE = "MH_OUTBOX_LINE_OVERSIZE"
_PRODUCER_DENIED_CODE = "MH_OUTBOX_PRODUCER_DENIED"

#: A valid ``rotation_glob``: safe filename literals around EXACTLY one ``*`` sequence wildcard.
_ROTATION_GLOB = re.compile(r"[A-Za-z0-9._-]*\*[A-Za-z0-9._-]*", flags=re.ASCII)


@dataclass(frozen=True, slots=True)
class OutboxReaderConfig:
    """The bounded knobs the reader needs (a subset of the ``file_outbox`` collector config).

    ``rotation_glob`` is a single-component filename glob resolved against the outbox's own
    directory; it is required to discover retained rotations. ``producer_allowlist`` -- when
    non-empty -- rejects any frame whose ``producer_id`` is not listed.
    """

    max_line_bytes: int = 65_536
    max_file_bytes: int = 104_857_600
    rotation_glob: str | None = None
    producer_allowlist: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for value, subject in (
            (self.max_line_bytes, "max_line_bytes"),
            (self.max_file_bytes, "max_file_bytes"),
        ):
            if type(value) is not int or not 0 < value <= MAX_CANONICAL_INT:
                raise OutboxError("MH_OUTBOX_CONFIG", f"a bounded positive {subject} is required")
        if self.max_line_bytes > self.max_file_bytes:
            raise OutboxError("MH_OUTBOX_CONFIG", "max_line_bytes must not exceed max_file_bytes")
        if self.rotation_glob is not None:
            if (
                type(self.rotation_glob) is not str
                or not self.rotation_glob
                or len(self.rotation_glob) > 255
            ):
                raise OutboxError("MH_OUTBOX_CONFIG", "a bounded rotation glob is required")
            # Exactly one ``*`` -- the monotonic integer sequence wildcard -- surrounded by literal
            # safe filename characters, so Path.glob matching and the sequence-parsing regex derived
            # from the same glob agree byte-for-byte and no second metacharacter can escape.
            if _ROTATION_GLOB.fullmatch(self.rotation_glob) is None:
                raise OutboxError(
                    "MH_OUTBOX_CONFIG",
                    "the rotation glob must be a single filename component with one '*' sequence "
                    "wildcard",
                )
        if type(self.producer_allowlist) is not tuple or any(
            type(entry) is not str for entry in self.producer_allowlist
        ):
            raise OutboxError(
                "MH_OUTBOX_CONFIG", "the producer allowlist must be a tuple of strings"
            )


@dataclass(frozen=True, slots=True)
class OutboxLossSignal:
    """A privacy-safe P1 data-loss signal: fixed code plus offsets, sizes, and hex digests only."""

    code: str
    cursor_device: int
    cursor_inode: int
    cursor_offset: int
    cursor_sha256: str
    observed_size: int | None = None
    observed_sha256: str | None = None
    priority: Literal["P1"] = "P1"


@dataclass(frozen=True, slots=True)
class OutboxDiagnostics:
    """Privacy-safe read diagnostics: only counts, codes, and byte totals -- never a payload."""

    frames_emitted: int
    rejected_lines: int
    rejected_codes: Mapping[str, int]
    bytes_consumed: int
    rotations_crossed: int
    torn_tail_bytes: int


@dataclass(frozen=True, slots=True)
class OutboxReadResult:
    """The outcome of one incremental read.

    On success ``next_position`` is the advanced cursor (encoded in ``next_position_string`` for the
    later durable ``advance_cursor`` write) and ``loss_signal`` is ``None``. On a data-loss find
    ``loss_signal`` is set, ``new_frames`` is empty, and ``next_position``/``next_position_string``
    equal the prior cursor unchanged -- the caller must raise the P1 alert and NOT advance.

    ``max_observed_sequence`` is the highest RETAINED rotated-file integer sequence this single read
    saw: ``M`` (the top of the contiguous rotated run) during a rotation read, the cursor's own
    sequence when the cursor is in a rotated file with nothing retained above it, and ``None`` when
    the cursor is in the active file (or no rotated files were seen). It is a pure per-read
    observation -- the reader NEVER reads or lowers any persisted state. The CALLER owns the durable
    monotonic rotation high-water and advances it as ``max(persisted, max_observed_sequence)``, then
    threads it back as ``read_outbox(..., last_acknowledged_sequence=...)`` so a later read can flag
    a deleted top-run of rotated segments (``MH_OUTBOX_LOSS_TOP_RUN_GONE``).
    """

    new_frames: tuple[OutboxFrameV1, ...]
    next_position: OutboxPosition | None
    next_position_string: str | None
    loss_signal: OutboxLossSignal | None
    diagnostics: OutboxDiagnostics
    max_observed_sequence: int | None = None


@dataclass(frozen=True, slots=True)
class _FileRead:
    device: int
    inode: int
    content: bytes


@dataclass(frozen=True, slots=True)
class _Parsed:
    frames: list[OutboxFrameV1] = field(default_factory=list)
    rejected: Counter[str] = field(default_factory=Counter)


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _has_torn_tail(content: bytes) -> bool:
    return content != b"" and not content.endswith(_LF)


def _read_regular_file(path: str | Path, max_file_bytes: int) -> _FileRead:
    """Open ``path`` no-follow and read it whole under ``max_file_bytes``; fail closed value-free.

    The active outbox may be appended concurrently, so the identity (device, inode) is required to
    stay stable across the read but the size is allowed to grow; the returned content is the exact
    bytes read to end-of-file, from which the reader derives its own complete-line boundary.
    """

    try:
        opened = open_regular_file_no_follow(path)
    except SecureFileError as error:
        raise _open_error(error) from None

    descriptor = opened.descriptor
    device = opened.snapshot.device
    inode = opened.snapshot.inode
    failure: OutboxError | None = None
    chunks: list[bytes] = []
    total = 0
    try:
        if opened.snapshot.size > max_file_bytes:
            raise OutboxError("MH_OUTBOX_FILE_OVERSIZE", "the outbox file exceeds its byte bound")
        while True:
            chunk = os.read(descriptor, 1 << 20)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > max_file_bytes:
                raise OutboxError(
                    "MH_OUTBOX_FILE_OVERSIZE", "the outbox file exceeds its byte bound"
                )
        after = os.fstat(descriptor)
        if (after.st_dev, after.st_ino) != (device, inode):
            raise OutboxError("MH_OUTBOX_READ", "the outbox file identity changed during the read")
    except OutboxError as error:
        failure = error
    except OSError:
        failure = OutboxError("MH_OUTBOX_READ", "the outbox file could not be read")
    finally:
        try:
            os.close(descriptor)
        except OSError:  # pragma: no cover - defensive close failure
            failure = failure or OutboxError("MH_OUTBOX_READ", "the outbox file could not be read")
    if failure is not None:
        raise failure
    return _FileRead(device=device, inode=inode, content=b"".join(chunks))


def _open_error(error: SecureFileError) -> OutboxError:
    if error.kind is SecureFileErrorKind.NOT_FOUND:
        return OutboxError("MH_OUTBOX_NOT_FOUND", "the outbox file does not exist")
    if error.kind is SecureFileErrorKind.NOT_REGULAR:
        return OutboxError(
            "MH_OUTBOX_NOT_REGULAR", "the outbox file must be a regular non-symlink file"
        )
    if error.kind is SecureFileErrorKind.SECURITY_UNSUPPORTED:
        return OutboxError("MH_OUTBOX_UNSUPPORTED", "safe outbox file access is unavailable")
    return OutboxError("MH_OUTBOX_READ", "the outbox file could not be opened")


def _iter_complete_lines(region: bytes) -> list[bytes]:
    """Split an all-complete (LF-terminated or empty) region into its lines, each keeping its LF."""

    if not region:
        return []
    parts = region.split(_LF)[:-1]
    return [part + _LF for part in parts]


def _parse_region(region: bytes, config: OutboxReaderConfig, into: _Parsed) -> None:
    """Parse every complete line in ``region``, rejecting oversized/invalid/denied lines by code.

    A rejected line's raw bytes are never captured: the oversize branch never parses, and the parse
    branch discards the value-safe :class:`OutboxError` after reading only its fixed ``.code``.
    """

    allowlist = config.producer_allowlist
    for line in _iter_complete_lines(region):
        if len(line) > config.max_line_bytes:
            into.rejected[_LINE_OVERSIZE_CODE] += 1
            continue
        payload = line[:-1] if line.endswith(_LF) else line
        try:
            frame = parse_outbox_frame_line(payload)
        except OutboxError as error:
            into.rejected[error.code] += 1
            continue
        if allowlist and frame.producer_id not in allowlist:
            into.rejected[_PRODUCER_DENIED_CODE] += 1
            continue
        into.frames.append(frame)


def _loss(
    code: str,
    prior: OutboxPosition,
    prior_string: str,
    *,
    observed_size: int | None = None,
    observed_sha256: str | None = None,
    max_observed_sequence: int | None = None,
) -> OutboxReadResult:
    signal = OutboxLossSignal(
        code=code,
        cursor_device=prior.device,
        cursor_inode=prior.inode,
        cursor_offset=prior.offset,
        cursor_sha256=prior.content_sha256,
        observed_size=observed_size,
        observed_sha256=observed_sha256,
    )
    diagnostics = OutboxDiagnostics(
        frames_emitted=0,
        rejected_lines=0,
        rejected_codes=MappingProxyType({}),
        bytes_consumed=0,
        rotations_crossed=0,
        torn_tail_bytes=0,
    )
    return OutboxReadResult(
        new_frames=(),
        next_position=prior,
        next_position_string=prior_string,
        loss_signal=signal,
        diagnostics=diagnostics,
        max_observed_sequence=max_observed_sequence,
    )


def _success(
    frames: list[OutboxFrameV1],
    rejected: Counter[str],
    *,
    next_position: OutboxPosition,
    bytes_consumed: int,
    rotations_crossed: int,
    torn_tail_bytes: int,
    max_observed_sequence: int | None = None,
) -> OutboxReadResult:
    diagnostics = OutboxDiagnostics(
        frames_emitted=len(frames),
        rejected_lines=sum(rejected.values()),
        rejected_codes=MappingProxyType(dict(rejected)),
        bytes_consumed=bytes_consumed,
        rotations_crossed=rotations_crossed,
        torn_tail_bytes=torn_tail_bytes,
    )
    return OutboxReadResult(
        new_frames=tuple(frames),
        next_position=next_position,
        next_position_string=encode_outbox_position(next_position),
        loss_signal=None,
        diagnostics=diagnostics,
        max_observed_sequence=max_observed_sequence,
    )


def read_outbox(
    *,
    file_path: str | Path,
    prior_cursor: SourceCursor | None,
    config: OutboxReaderConfig,
    last_acknowledged_sequence: int | None = None,
) -> OutboxReadResult:
    """Incrementally read the outbox from ``prior_cursor``; see the module docstring for details.

    ``last_acknowledged_sequence`` is the caller-maintained durable ROTATION high-water mark: the
    highest rotated-file integer sequence the reader has OBSERVED in prior reads (``None`` if never
    set; persisted in the ack's ``last_sequence`` field). It is consulted only during rotation
    recovery to detect a deleted top-run of the most-recent rotated segments -- see
    :func:`_recover_rotation`. Passing ``None`` is the fully backward-compatible increment-1
    behaviour. The reader never reads or writes this durable state itself; the caller advances it
    monotonically as ``max(persisted, result.max_observed_sequence)`` and threads it back here.
    """

    if not isinstance(config, OutboxReaderConfig):
        raise OutboxError("MH_OUTBOX_CONFIG", "an outbox reader configuration is required")
    if prior_cursor is not None and not isinstance(prior_cursor, SourceCursor):
        raise OutboxError("MH_OUTBOX_CURSOR", "a source cursor or None is required")
    if last_acknowledged_sequence is not None and (
        type(last_acknowledged_sequence) is not int
        or not 0 <= last_acknowledged_sequence <= MAX_CANONICAL_INT
    ):
        # ``bool`` is an ``int`` subtype; the ``type is int`` check rejects it so a stray flag
        # cannot pose as a high-water sequence. Fail closed rather than reason from a bogus mark.
        raise OutboxError(
            "MH_OUTBOX_HIGH_WATER", "a bounded non-negative high-water sequence or None is required"
        )

    prior = outbox_position_from_cursor(prior_cursor) if prior_cursor is not None else None
    prior_string = prior_cursor.position if prior_cursor is not None else None
    active = _read_regular_file(file_path, config.max_file_bytes)

    if prior is None or (active.device, active.inode) == (prior.device, prior.inode):
        return _read_same_file(active, prior, config)
    assert prior_string is not None
    return _recover_rotation(
        file_path, active, prior, prior_string, config, last_acknowledged_sequence
    )


def _read_same_file(
    active: _FileRead, prior: OutboxPosition | None, config: OutboxReaderConfig
) -> OutboxReadResult:
    content = active.content
    start = 0
    if prior is not None:
        prior_string = encode_outbox_position(prior)
        if len(content) < prior.offset:
            return _loss(
                "MH_OUTBOX_LOSS_TRUNCATED", prior, prior_string, observed_size=len(content)
            )
        prefix_hash = _sha256_hex(content[: prior.offset])
        if prefix_hash != prior.content_sha256:
            return _loss(
                "MH_OUTBOX_LOSS_REWRITE",
                prior,
                prior_string,
                observed_size=len(content),
                observed_sha256=prefix_hash,
            )
        start = prior.offset

    complete_end = content.rfind(_LF) + 1  # 0 when the file holds no complete line
    if complete_end < start:  # pragma: no cover - start is always a prior LF boundary
        complete_end = start
    region = content[start:complete_end]
    parsed = _Parsed()
    _parse_region(region, config, parsed)
    next_position = OutboxPosition(
        device=active.device,
        inode=active.inode,
        offset=complete_end,
        content_sha256=_sha256_hex(content[:complete_end]),
    )
    return _success(
        parsed.frames,
        parsed.rejected,
        next_position=next_position,
        bytes_consumed=complete_end - start,
        rotations_crossed=0,
        torn_tail_bytes=len(content) - complete_end,
    )


def _recover_rotation(
    file_path: str | Path,
    active: _FileRead,
    prior: OutboxPosition,
    prior_string: str,
    config: OutboxReaderConfig,
    last_acknowledged_sequence: int | None,
) -> OutboxReadResult:
    """Recover across a rotation, requiring a parseable, CONTIGUOUS rotated sequence (no gaps).

    Producer naming contract this enforces: each retained rotated file is named by the configured
    ``rotation_glob`` with its ``*`` wildcard a parseable, monotonic, CONTIGUOUS integer sequence;
    the active file is that sequence's live successor. The reader parses the integer (not a lexical
    key), orders numerically, finds the cursor's file by identity at sequence S, and requires the
    retained rotations above S to be exactly ``{S+1, S+2, ..., S+k}`` before continuing into the
    active file. ANY gap -- a missing intermediate sequence -- is un-recoverable P1 data loss
    (``MH_OUTBOX_LOSS_ROTATION_GONE``): a single-file cursor cannot re-materialize deleted bytes.

    Top-run detection via the high-water (increment 2a): the active file carries no sequence in its
    name, so the reader treats the highest retained rotation ``M`` as the active file's immediate
    predecessor. Deletion of a RUN of the TOPMOST rotated segments -- the most-recent ones adjacent
    to the active file, with nothing retained above the survivors -- leaves the retained set a
    contiguous run that passes the gap check above. To catch THAT, once ``{S+1..M}`` is proven
    contiguous the reader compares ``M`` against ``last_acknowledged_sequence`` (``H``, the durable
    high-water of the highest rotated sequence ever OBSERVED). If ``H`` is set and ``M < H`` the
    segments ``(M+1 .. H)`` that were once observed are gone from the top; because this branch runs
    only during rotation recovery (the cursor sits in a rotated file at ``S <= M < H``), those
    missing segments are strictly ABOVE the cursor and therefore UNCONSUMED -- a genuine P1 loss,
    ``MH_OUTBOX_LOSS_TOP_RUN_GONE``.

    Why this has NO false positive: a compliant producer deletes a rotated segment only once the
    ack covers it (fully consumed). Deleting a CONSUMED segment at or below the cursor never reaches
    this branch -- a consumed segment means the cursor already advanced to/past it, so the next read
    finds the cursor either in the ACTIVE file (which never enters this function) or in a HIGHER
    rotated file, and a missing lower file surfaces as the ``ROTATION_GONE`` cursor-file-missing
    case, not this one. This branch fires only for segments strictly ABOVE the cursor that were
    previously observed, i.e. genuinely unconsumed loss.

    Irreducible residual (documented, not papered over): a top-run is caught only for PREVIOUSLY
    OBSERVED segments (those the high-water recorded). Segments a producer creates AND deletes
    entirely BETWEEN two reads never enter the reader's observation, so they are absent from the
    high-water and remain undetectable -- fundamentally so for a cursor-based reader unless the
    producer sequences the active file (out of scope). Everything the reader has ever seen at the
    top is now detected.
    """

    if config.rotation_glob is None:
        # A different active inode with no way to discover retained rotations: never blindly resume
        # at the old offset in a different file.
        return _loss("MH_OUTBOX_LOSS_INODE_REUSE", prior, prior_string)

    directory = lexical_absolute_path(file_path).parent
    by_sequence, discovery_loss = _discover_rotations(directory, active, config)
    if discovery_loss is not None:
        return _loss(discovery_loss, prior, prior_string)

    # The highest retained rotated sequence seen THIS read (``None`` if the glob matched only the
    # active file). This is the pure per-read observation the caller folds into its high-water; it
    # is reported on every post-discovery return, loss or success alike, and the reader never uses
    # it to lower any persisted state.
    max_observed = max(by_sequence) if by_sequence else None

    cursor_sequence = next(
        (
            sequence
            for sequence, read in by_sequence.items()
            if (read.device, read.inode) == (prior.device, prior.inode)
        ),
        None,
    )
    if cursor_sequence is None:
        # The file the cursor was consuming is not among the retained, parseable rotations: its
        # unacknowledged bytes are gone and cannot be recovered.
        return _loss(
            "MH_OUTBOX_LOSS_ROTATION_GONE",
            prior,
            prior_string,
            max_observed_sequence=max_observed,
        )

    # The retained rotations strictly above the cursor MUST be the contiguous run
    # {S+1, S+2, ..., S+k}; any gap is a dropped unconsumed segment we cannot recover.
    above = sorted(sequence for sequence in by_sequence if sequence > cursor_sequence)
    if above != list(range(cursor_sequence + 1, cursor_sequence + 1 + len(above))):
        return _loss(
            "MH_OUTBOX_LOSS_ROTATION_GONE",
            prior,
            prior_string,
            max_observed_sequence=max_observed,
        )

    # Top-run high-water check: with ``{S+1..M}`` now proven contiguous, ``max_observed`` == M (the
    # cursor's own sequence when nothing is retained above it). If a strictly higher sequence H was
    # observed before but M has since fallen below it, the top run (M+1 .. H) was deleted. Those
    # segments are above the cursor (S <= M < H) hence unconsumed -> a genuine P1 loss. See the
    # docstring for the no-false-positive argument; ``max_observed is not None`` here because the
    # cursor itself is a retained rotation.
    if (
        last_acknowledged_sequence is not None
        and max_observed is not None
        and (max_observed < last_acknowledged_sequence)
    ):
        return _loss(
            "MH_OUTBOX_LOSS_TOP_RUN_GONE",
            prior,
            prior_string,
            max_observed_sequence=max_observed,
        )

    # Phase A: validate the whole chain BEFORE emitting anything, so any loss yields zero frames.
    cursor_file = by_sequence[cursor_sequence]
    if len(cursor_file.content) < prior.offset:
        return _loss(
            "MH_OUTBOX_LOSS_TRUNCATED",
            prior,
            prior_string,
            observed_size=len(cursor_file.content),
            max_observed_sequence=max_observed,
        )
    prefix_hash = _sha256_hex(cursor_file.content[: prior.offset])
    if prefix_hash != prior.content_sha256:
        return _loss(
            "MH_OUTBOX_LOSS_REWRITE",
            prior,
            prior_string,
            observed_size=len(cursor_file.content),
            observed_sha256=prefix_hash,
            max_observed_sequence=max_observed,
        )
    if _has_torn_tail(cursor_file.content):
        return _loss(
            "MH_OUTBOX_LOSS_ROTATED_TORN",
            prior,
            prior_string,
            observed_size=len(cursor_file.content),
            max_observed_sequence=max_observed,
        )

    regions: list[bytes] = [cursor_file.content[prior.offset :]]
    bytes_consumed = len(regions[0])
    for sequence in above:
        read = by_sequence[sequence]
        if _has_torn_tail(read.content):
            return _loss(
                "MH_OUTBOX_LOSS_ROTATED_TORN",
                prior,
                prior_string,
                observed_size=len(read.content),
                max_observed_sequence=max_observed,
            )
        regions.append(read.content)
        bytes_consumed += len(read.content)

    complete_end = active.content.rfind(_LF) + 1
    active_region = active.content[:complete_end]
    regions.append(active_region)
    bytes_consumed += complete_end

    # Phase B: parse every region now that the chain is proven continuous.
    parsed = _Parsed()
    for region in regions:
        _parse_region(region, config, parsed)

    next_position = OutboxPosition(
        device=active.device,
        inode=active.inode,
        offset=complete_end,
        content_sha256=_sha256_hex(active.content[:complete_end]),
    )
    return _success(
        parsed.frames,
        parsed.rejected,
        next_position=next_position,
        bytes_consumed=bytes_consumed,
        rotations_crossed=1 + len(above),
        torn_tail_bytes=len(active.content) - complete_end,
        max_observed_sequence=max_observed,
    )


def _discover_rotations(
    directory: Path, active: _FileRead, config: OutboxReaderConfig
) -> tuple[dict[int, _FileRead], str | None]:
    """Read retained rotated files keyed by their parsed integer sequence; fail closed on ambiguity.

    Each rotated filename is matched against a regex derived from the SAME ``rotation_glob``, with
    the single ``*`` wildcard bound to a run of ASCII digits, and the captured integer is the
    segment's monotonic sequence -- so ordering is numeric, not lexical (``...9`` before ``...10``).
    A match whose wildcard is not a pure integer run (``MH_OUTBOX_LOSS_ROTATION_UNPARSEABLE``), or
    two retained files parsing to the SAME sequence (``MH_OUTBOX_LOSS_ROTATION_AMBIGUOUS``), fail
    closed with a returned loss code, not a silent skip. The active file's identity (and any link to
    it) is excluded so a glob that also matches the active name cannot double-count a segment. Each
    file is opened no-follow and read whole under the size bound.

    Returns ``(sequence -> file, None)`` on success, or ``({}, loss_code)`` on a fail-closed skip.
    """

    assert config.rotation_glob is not None
    prefix, suffix = config.rotation_glob.split("*", 1)
    pattern = re.compile(
        "^" + re.escape(prefix) + r"(\d+)" + re.escape(suffix) + "$", flags=re.ASCII
    )
    by_sequence: dict[int, _FileRead] = {}
    for candidate in sorted(
        Path(directory).glob(config.rotation_glob), key=lambda entry: entry.name
    ):
        match = pattern.fullmatch(candidate.name)
        if match is None:
            return {}, "MH_OUTBOX_LOSS_ROTATION_UNPARSEABLE"
        read = _read_regular_file(candidate, config.max_file_bytes)
        if (read.device, read.inode) == (active.device, active.inode):
            continue  # the glob also matched the active file (or a hard link to it): not a rotation
        sequence = int(match.group(1))
        if sequence in by_sequence:
            return {}, "MH_OUTBOX_LOSS_ROTATION_AMBIGUOUS"
        by_sequence[sequence] = read
    return by_sequence, None


__all__ = [
    "OutboxDiagnostics",
    "OutboxLossSignal",
    "OutboxReadResult",
    "OutboxReaderConfig",
    "read_outbox",
]
