"""The opaque outbox cursor position codec (W07, plan section 4.9).

A source cursor's ``position`` (``_cursors.position``, see :mod:`milhouse.state.cursors`) is an
opaque, source-defined, payload-free string. This module defines the outbox source's encoding of it:
a small versioned, self-describing canonical-JSON object binding the consumed file's identity
``(device, inode)``, the committed byte ``offset``, and ``content_sha256`` -- the SHA-256 over the
ENTIRE consumed prefix ``[0, offset)`` of that exact file.

Why that hash detects truncation and rewrite of already-consumed bytes: on every incremental read
the reader re-hashes the live file's ``[0, offset)`` prefix and compares it to ``content_sha256``. A
producer that truncated unacknowledged bytes shrinks the file below ``offset`` (caught by a size
check); a producer that rewrote consumed bytes in place changes the prefix hash (caught here). Only
an append that leaves ``[0, offset)`` byte-identical -- exactly what a compliant append-only
producer does -- reproduces the hash, so any consumed-byte discontinuity is a fail-closed P1 loss
signal rather than a silent resync. The string never carries a raw payload byte: only the integer
identity/offset and a hex digest.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

from milhouse.core.canonical import (
    MAX_CANONICAL_INT,
    CanonicalizationError,
    canonical_json_text,
)
from milhouse.outbox.errors import OutboxError
from milhouse.state.cursors import SourceCursor

#: The opaque position encoding version. Bumping it is how a future consumed-prefix hash mechanism
#: is introduced without silently reinterpreting an existing durable position string.
OUTBOX_POSITION_VERSION = 1
#: A defensive ceiling for a decoded position string, far above the fixed-shape object it must hold.
MAX_POSITION_BYTES = 512
_SHA256_HEX = re.compile(r"[0-9a-f]{64}", flags=re.ASCII)
#: The exact key set a v1 position object carries; any other set is refused.
_POSITION_KEYS = frozenset({"dev", "inode", "offset", "sha256", "v"})


@dataclass(frozen=True, slots=True)
class OutboxPosition:
    """The decoded outbox cursor position: the consumed file's identity, offset, and prefix hash.

    ``device``/``inode`` identify the exact file the offset refers to (so a rotation or inode reuse
    is detectable), ``offset`` is the byte length of the consumed, LF-terminated prefix, and
    ``content_sha256`` is the SHA-256 over that whole ``[0, offset)`` prefix.
    """

    device: int
    inode: int
    offset: int
    content_sha256: str

    def __post_init__(self) -> None:
        for value, subject in ((self.device, "device"), (self.inode, "inode")):
            if type(value) is not int or not 0 <= value <= MAX_CANONICAL_INT:
                raise OutboxError(
                    "MH_OUTBOX_POSITION", f"a bounded non-negative {subject} is required"
                )
        if type(self.offset) is not int or not 0 <= self.offset <= MAX_CANONICAL_INT:
            raise OutboxError("MH_OUTBOX_POSITION", "a bounded non-negative offset is required")
        if (
            type(self.content_sha256) is not str
            or _SHA256_HEX.fullmatch(self.content_sha256) is None
        ):
            raise OutboxError(
                "MH_OUTBOX_POSITION", "a lowercase hex sha-256 prefix digest is required"
            )


def encode_outbox_position(position: OutboxPosition) -> str:
    """Encode a decoded position to its opaque, versioned, canonical ``_cursors.position`` value."""

    if not isinstance(position, OutboxPosition):
        raise OutboxError("MH_OUTBOX_POSITION", "an outbox position is required")
    payload = {
        "dev": position.device,
        "inode": position.inode,
        "offset": position.offset,
        "sha256": position.content_sha256,
        "v": OUTBOX_POSITION_VERSION,
    }
    failed = False
    text = ""
    try:
        text = canonical_json_text(payload, max_bytes=MAX_POSITION_BYTES)
    except CanonicalizationError:
        failed = True
    if failed:
        raise OutboxError("MH_OUTBOX_POSITION", "the outbox position could not be encoded")
    return text


def decode_outbox_position(position: str) -> OutboxPosition:
    """Decode an opaque ``_cursors.position`` string, failing closed on any malformed value.

    Every structural violation -- an over-long string, non-UTF-8/non-object JSON, an unexpected key
    set, a wrong version, a non-integer identity/offset, or a malformed digest -- raises a fixed
    ``MH_OUTBOX_POSITION`` :class:`OutboxError`. The string is Milhouse-owned control metadata, but
    it is parsed as defensively as untrusted input so a tampered SQLite row cannot resume at a fake
    offset.
    """

    if (
        type(position) is not str
        or not position
        or len(position.encode("utf-8")) > MAX_POSITION_BYTES
    ):
        raise OutboxError("MH_OUTBOX_POSITION", "a bounded outbox position string is required")
    failed = False
    value: object = None
    try:
        value = json.loads(position)
    except (UnicodeDecodeError, ValueError, RecursionError):
        failed = True
    if failed or type(value) is not dict:
        raise OutboxError("MH_OUTBOX_POSITION", "an outbox position must be a JSON object")
    if frozenset(value) != _POSITION_KEYS or value.get("v") != OUTBOX_POSITION_VERSION:
        raise OutboxError("MH_OUTBOX_POSITION", "an unsupported or malformed outbox position")
    device, inode, offset, digest = value["dev"], value["inode"], value["offset"], value["sha256"]
    # ``bool`` is an ``int`` subtype; reject it so a stray flag cannot pose as an offset/identity.
    for candidate in (device, inode, offset):
        if type(candidate) is not int:
            raise OutboxError(
                "MH_OUTBOX_POSITION", "outbox position identity and offset must be integers"
            )
    if type(digest) is not str:
        raise OutboxError("MH_OUTBOX_POSITION", "the outbox position digest must be a string")
    # OutboxPosition.__post_init__ enforces the numeric and digest bounds; canonicality is below.
    decoded = OutboxPosition(device=device, inode=inode, offset=offset, content_sha256=digest)
    if encode_outbox_position(decoded) != position:
        # A non-canonical encoding (extra whitespace, reordered keys, redundant sign) is refused so
        # exactly one byte string ever represents a given position.
        raise OutboxError("MH_OUTBOX_POSITION", "the outbox position is not canonical")
    return decoded


def outbox_position_from_cursor(cursor: SourceCursor) -> OutboxPosition:
    """Decode the outbox position carried by a source cursor's opaque ``position`` string."""

    if not isinstance(cursor, SourceCursor):
        raise OutboxError("MH_OUTBOX_POSITION", "a source cursor is required")
    return decode_outbox_position(cursor.position)


__all__ = [
    "MAX_POSITION_BYTES",
    "OUTBOX_POSITION_VERSION",
    "OutboxPosition",
    "decode_outbox_position",
    "encode_outbox_position",
    "outbox_position_from_cursor",
]
