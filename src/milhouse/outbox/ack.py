"""The Milhouse-owned ``outbox-ack.json`` format and its atomic ``0600`` read/writer (section 4.9).

Ownership (ADR 0012 / plan section 4.9): the application appends ``feedback-outbox.jsonl`` and
Milhouse never rewrites it, but Milhouse OWNS ``outbox-ack.json`` -- a small atomic file recording
which producer/file identity and byte offset it has committed, plus the last committed line's digest
and the acknowledgement time. This module defines that value-safe format (:class:`OutboxAckV1`) and
a canonical, atomic, mode-``0600`` writer/reader that live strictly inside the configured
``<repo>/.milhouse`` directory after canonical-path and no-follow symlink checks, reusing the vetted
secure-file primitives (:mod:`milhouse.config.filesystem`) rather than hand-rolling file security.
Both the writer and reader pass ``require_private_parent=True``, so the ``.milhouse`` directory must
be an owner-only ``0700`` directory with no extended ACL -- the Milhouse-owned posture, stricter
than the app-owned outbox the reader tolerates.

The writer stages the canonical ack bytes with :func:`create_regular_file_no_follow` (a no-follow
directory-chain walk, private-parent check, ``O_EXCL`` create, ``0600`` mode, full write, ``fsync``,
and content read-back), then atomically ``os.replace``-es the staged name onto ``outbox-ack.json``
and fsyncs the directory -- so the ack is either the complete prior value or the complete new value,
never a torn one. The reader opens no-follow under the same private parent and requires an
owner-only, ``0600``, single-link, ACL-safe regular file, rejecting a symlinked or foreign path with
a fixed code. The post-``create`` /
pre-``replace`` one-syscall window is closed for cooperating writers by the exclusive maintenance
barrier and for a hostile same-account process by the installation-account trust boundary (ADR
0008 / amendment A06), matching :func:`remove_regular_file_no_follow`.

Writing the ack AFTER a durable segment commits is a later increment; this module owns only the
format and the atomic file surface, both of which are fully offline-testable here.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import stat
from pathlib import Path
from typing import Literal

from pydantic import ConfigDict

from milhouse.config.filesystem import (
    SecureFileError,
    SecureFileErrorKind,
    create_regular_file_no_follow,
    lexical_absolute_path,
    open_regular_file_no_follow,
    sync_parent_directory_no_follow,
)
from milhouse.core.canonical import CanonicalizationError, canonical_json_bytes
from milhouse.domain._validation import ValueSafeRecordModel
from milhouse.domain.identity import MachineIdV1, Sha256HexV1
from milhouse.domain.records import NonNegativeIntV1, UtcTimestampV1
from milhouse.outbox.errors import OutboxError

#: A generous ceiling for the canonical ack object (it holds a handful of small scalar fields).
MAX_ACK_BYTES = 4_096
_ACK_MODE = 0o600
_ACK_FILENAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,254}", flags=re.ASCII)
_ACK_KEYS = frozenset(
    {
        "acknowledged_at",
        "committed_offset",
        "content_sha256",
        "file_device",
        "file_inode",
        "last_line_sha256",
        "last_sequence",
        "producer_id",
        "schema_version",
    }
)


class OutboxAckV1(ValueSafeRecordModel):
    """The atomic acknowledgement Milhouse owns for one outbox producer/file (plan section 4.9).

    ``producer_id`` plus ``file_device``/``file_inode`` fix the identity of the acknowledged file,
    ``committed_offset`` is the byte length Milhouse has durably committed, ``content_sha256`` is
    the SHA-256 over that whole ``[0, committed_offset)`` prefix (the same anchor the cursor
    carries), ``last_line_sha256`` is the digest of the last committed line (the "last record hash",
    ``None`` for an empty commit), and ``acknowledged_at`` is the commit time.

    ``last_sequence`` is the durable ROTATION high-water mark: the highest rotated-file integer
    sequence the reader has ever OBSERVED (``None`` until a rotation is seen). It is the anchor the
    reader's top-run detection reads back as ``last_acknowledged_sequence`` (plan section 4.9 /
    :func:`milhouse.outbox.reader.read_outbox`): if the highest retained rotated sequence has since
    dropped below it, a run of the topmost (unconsumed) segments was deleted -- a P1 data loss that
    a stateless single-file cursor could not otherwise see. The caller advances this monotonically
    as ``max(persisted, reader_output)``; the reader never lowers it.
    """

    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        frozen=True,
        hide_input_in_errors=True,
        revalidate_instances="always",
        validate_default=True,
    )

    schema_version: Literal["1.0"] = "1.0"
    producer_id: MachineIdV1
    file_device: int
    file_inode: int
    committed_offset: int
    content_sha256: Sha256HexV1
    last_line_sha256: Sha256HexV1 | None = None
    last_sequence: NonNegativeIntV1 | None = None
    acknowledged_at: UtcTimestampV1


def outbox_ack_bytes(ack: OutboxAckV1) -> bytes:
    """Project one ack to its bounded canonical JSON bytes (no trailing line feed)."""

    if not isinstance(ack, OutboxAckV1):
        raise OutboxError("MH_OUTBOX_ACK", "an outbox ack is required")
    failed = False
    content = b""
    try:
        content = canonical_json_bytes(
            ack.model_dump(mode="python", exclude_none=True), max_bytes=MAX_ACK_BYTES
        )
    except CanonicalizationError:
        failed = True
    if failed:
        raise OutboxError("MH_OUTBOX_ACK", "the outbox ack exceeds its canonical byte bound")
    return content


def _require_platform() -> None:
    if (
        getattr(os, "O_NOFOLLOW", 0) == 0
    ):  # pragma: no cover - Milhouse supports only no-follow hosts
        raise OutboxError(
            "MH_OUTBOX_ACK_UNSUPPORTED", "safe outbox ack file operations are unavailable"
        )


def _ack_path(directory: str | Path, filename: str) -> Path:
    if (
        type(filename) is not str
        or _ACK_FILENAME.fullmatch(filename) is None
        or filename in {".", ".."}
    ):
        raise OutboxError("MH_OUTBOX_ACK_PATH", "a safe single-component ack filename is required")
    failed = False
    resolved: Path | None = None
    try:
        base = lexical_absolute_path(directory)
        resolved = lexical_absolute_path(base / filename)
    except Exception:
        failed = True
    if failed or resolved is None or resolved.parent != lexical_absolute_path(directory):
        # The joined leaf must stay directly inside the configured .milhouse dir: no traversal.
        raise OutboxError(
            "MH_OUTBOX_ACK_PATH", "the ack path must resolve inside the repo .milhouse directory"
        )
    return resolved


def _current_uid() -> int:
    geteuid = getattr(os, "geteuid", None)
    if geteuid is None:  # pragma: no cover - Milhouse supports only POSIX hosts
        raise OutboxError(
            "MH_OUTBOX_ACK_UNSUPPORTED", "the outbox ack requires a POSIX ownership model"
        )
    return int(geteuid())


def write_outbox_ack(directory: str | Path, filename: str, ack: OutboxAckV1) -> None:
    """Atomically publish ``ack`` as ``<directory>/<filename>`` at ``0600``, then fsync the dir.

    The bytes are staged with the secure no-follow primitive (which validates the whole directory
    chain, creates ``O_EXCL`` at ``0600``, writes, fsyncs, and reads the content back), then
    ``os.replace``-d onto the final name and the parent directory is fsynced. A pre-existing ack --
    or even a symlink planted at the final name -- is atomically replaced, never followed. Any
    failure raises a fixed ``MH_OUTBOX_ACK*`` code and best-effort removes the staged artifact.
    """

    _require_platform()
    if not isinstance(ack, OutboxAckV1):
        raise OutboxError("MH_OUTBOX_ACK", "an outbox ack is required")
    ack_path = _ack_path(directory, filename)
    content = outbox_ack_bytes(ack)
    staged_path = ack_path.parent / f".{filename}.{secrets.token_hex(16)}.tmp"

    try:
        create_regular_file_no_follow(
            staged_path, content, mode=_ACK_MODE, require_private_parent=True
        )
    except SecureFileError as error:
        raise _write_error(error) from None
    except OutboxError:
        raise
    except Exception:
        raise OutboxError(
            "MH_OUTBOX_ACK_WRITE", "the outbox ack could not be safely staged"
        ) from None

    replaced = False
    try:
        os.replace(os.fspath(staged_path), os.fspath(ack_path))
        replaced = True
        sync_parent_directory_no_follow(ack_path, require_private_parent=True)
    except SecureFileError:
        # The replace already landed; only the durability fsync failed -> commit-uncertain.
        raise OutboxError(
            "MH_OUTBOX_ACK_COMMIT_UNCERTAIN", "the outbox ack durability is unconfirmed"
        ) from None
    except OSError:
        if not replaced:
            _best_effort_unlink(staged_path)
            raise OutboxError(
                "MH_OUTBOX_ACK_WRITE", "the outbox ack could not be atomically published"
            ) from None
        raise OutboxError(
            "MH_OUTBOX_ACK_COMMIT_UNCERTAIN", "the outbox ack durability is unconfirmed"
        ) from None


def read_outbox_ack(directory: str | Path, filename: str) -> OutboxAckV1 | None:
    """Read and validate a prior ack, or ``None`` when the file does not exist.

    The file is opened no-follow (a symlinked leaf or ancestor fails closed) and must be an
    owner-only, ``0600``, single-link, ACL-safe regular file; its snapshot is re-checked after the
    bounded read to reject a mid-read swap. The bytes are parsed defensively into
    :class:`OutboxAckV1` -- a value-safe model, so a corrupt or foreign object fails with a fixed
    code that carries none of its content. A present-but-unsafe or malformed ack RAISES; only
    genuine absence returns ``None``.
    """

    _require_platform()
    ack_path = _ack_path(directory, filename)
    opened = None
    try:
        opened = open_regular_file_no_follow(ack_path, require_private_parent=True)
    except SecureFileError as error:
        if error.kind is SecureFileErrorKind.NOT_FOUND:
            return None
        raise _read_error(error) from None

    descriptor = opened.descriptor
    failure: OutboxError | None = None
    raw = b""
    try:
        before = os.fstat(descriptor)
        _require_ack_file(before)
        if before.st_size > MAX_ACK_BYTES:
            raise OutboxError("MH_OUTBOX_ACK_SIZE", "the outbox ack exceeds its byte bound")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, MAX_ACK_BYTES + 1)
            if not chunk:
                break
            chunks.append(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
        _require_ack_file(after)
        if (before.st_dev, before.st_ino, before.st_size) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
        ):
            raise OutboxError("MH_OUTBOX_ACK_CHANGED", "the outbox ack changed while it was read")
    except OutboxError as error:
        failure = error
    except OSError:
        failure = OutboxError("MH_OUTBOX_ACK_READ", "the outbox ack could not be read")
    finally:
        try:
            os.close(descriptor)
        except OSError:  # pragma: no cover - defensive close failure
            failure = failure or OutboxError(
                "MH_OUTBOX_ACK_READ", "the outbox ack could not be read"
            )
    if failure is not None:
        raise failure
    return _parse_ack(raw)


def _require_ack_file(metadata: os.stat_result) -> None:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != _current_uid()
        or stat.S_IMODE(metadata.st_mode) != _ACK_MODE
        or metadata.st_nlink != 1
    ):
        raise OutboxError(
            "MH_OUTBOX_ACK_UNSAFE", "the outbox ack must be an owner-only single-link 0600 file"
        )


def _parse_ack(raw: bytes) -> OutboxAckV1:
    failed = False
    value: object = None
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        failed = True
    if failed or type(value) is not dict:
        raise OutboxError("MH_OUTBOX_ACK", "the outbox ack must be a canonical JSON object")
    if not frozenset(value).issubset(_ACK_KEYS):
        raise OutboxError("MH_OUTBOX_ACK", "the outbox ack has unexpected fields")
    ack: OutboxAckV1 | None = None
    invalid = False
    try:
        ack = OutboxAckV1.model_validate_json(raw)
    except Exception:
        invalid = True
    if invalid or ack is None:
        raise OutboxError("MH_OUTBOX_ACK", "the outbox ack failed field validation")
    if outbox_ack_bytes(ack) != raw:
        raise OutboxError("MH_OUTBOX_ACK", "the outbox ack is not canonical")
    return ack


def _best_effort_unlink(path: Path) -> None:
    try:
        os.unlink(os.fspath(path))
    except OSError:  # pragma: no cover - best-effort staged cleanup
        pass


def _write_error(error: SecureFileError) -> OutboxError:
    mapping = {
        SecureFileErrorKind.SECURITY_UNSUPPORTED: (
            "MH_OUTBOX_ACK_UNSUPPORTED",
            "safe outbox ack creation is unavailable",
        ),
        SecureFileErrorKind.NOT_FOUND: (
            "MH_OUTBOX_ACK_PARENT_MISSING",
            "the .milhouse directory does not exist",
        ),
        SecureFileErrorKind.NOT_REGULAR: (
            "MH_OUTBOX_ACK_PATH",
            "the outbox ack path is not a regular file",
        ),
        SecureFileErrorKind.COMMIT_UNCERTAIN: (
            "MH_OUTBOX_ACK_COMMIT_UNCERTAIN",
            "the outbox ack durability is unconfirmed",
        ),
        SecureFileErrorKind.ACCESS_CONTROL_UNSAFE: (
            "MH_OUTBOX_ACK_UNSAFE",
            "the outbox ack path has unsafe access control",
        ),
        SecureFileErrorKind.PARENT_UNSAFE: (
            "MH_OUTBOX_ACK_UNSAFE",
            "the .milhouse directory is unsafe",
        ),
    }
    code, message = mapping.get(
        error.kind, ("MH_OUTBOX_ACK_WRITE", "the outbox ack could not be safely written")
    )
    return OutboxError(code, message)


def _read_error(error: SecureFileError) -> OutboxError:
    mapping = {
        SecureFileErrorKind.NOT_REGULAR: (
            "MH_OUTBOX_ACK_UNSAFE",
            "the outbox ack must be a regular non-symlink file",
        ),
        SecureFileErrorKind.SECURITY_UNSUPPORTED: (
            "MH_OUTBOX_ACK_UNSUPPORTED",
            "safe outbox ack loading is unavailable",
        ),
        SecureFileErrorKind.PARENT_UNSAFE: (
            "MH_OUTBOX_ACK_UNSAFE",
            "the .milhouse directory is unsafe",
        ),
        SecureFileErrorKind.ACCESS_CONTROL_UNSAFE: (
            "MH_OUTBOX_ACK_UNSAFE",
            "the outbox ack path has unsafe access control",
        ),
    }
    code, message = mapping.get(
        error.kind, ("MH_OUTBOX_ACK_READ", "the outbox ack could not be safely read")
    )
    return OutboxError(code, message)


__all__ = [
    "MAX_ACK_BYTES",
    "OutboxAckV1",
    "outbox_ack_bytes",
    "read_outbox_ack",
    "write_outbox_ack",
]
