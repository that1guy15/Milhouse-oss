"""W07 ``.milhouse`` outbox: the untrusted frame envelope, cursor codec, ack file, and reader.

Increment 1 delivers a pure, offline-testable reader spine (plan section 4.9): a compliant producer
appends ``feedback-outbox.jsonl`` and Milhouse reads it without ever truncating, rotating, or
rewriting it. This package owns the versioned inbound envelope (:class:`OutboxFrameV1`), the opaque
cursor position codec anchored on a consumed-prefix hash, the Milhouse-owned atomic
``outbox-ack.json`` format, and :func:`read_outbox`, which turns a file/cursor/config into new
frames, a next cursor, an optional P1 data-loss signal, and privacy-safe diagnostics. Collector
wiring, the durable ``advance_cursor`` write, and the frame-to-record mapping are later increments.
"""

from __future__ import annotations

from milhouse.outbox.ack import (
    MAX_ACK_BYTES,
    OutboxAckV1,
    outbox_ack_bytes,
    read_outbox_ack,
    write_outbox_ack,
)
from milhouse.outbox.advance import CursorAdvanceV1
from milhouse.outbox.cursor import (
    OUTBOX_POSITION_VERSION,
    OutboxPosition,
    decode_outbox_position,
    encode_outbox_position,
    outbox_position_from_cursor,
)
from milhouse.outbox.errors import OutboxError
from milhouse.outbox.frame import (
    MAX_OUTBOX_FRAME_BYTES,
    OutboxActionabilityV1,
    OutboxFrameV1,
    parse_outbox_frame_line,
)
from milhouse.outbox.reader import (
    OutboxDiagnostics,
    OutboxLossSignal,
    OutboxReaderConfig,
    OutboxReadResult,
    read_outbox,
)

__all__ = [
    "MAX_ACK_BYTES",
    "MAX_OUTBOX_FRAME_BYTES",
    "OUTBOX_POSITION_VERSION",
    "CursorAdvanceV1",
    "OutboxAckV1",
    "OutboxActionabilityV1",
    "OutboxDiagnostics",
    "OutboxError",
    "OutboxFrameV1",
    "OutboxLossSignal",
    "OutboxPosition",
    "OutboxReadResult",
    "OutboxReaderConfig",
    "decode_outbox_position",
    "encode_outbox_position",
    "outbox_ack_bytes",
    "outbox_position_from_cursor",
    "parse_outbox_frame_line",
    "read_outbox",
    "read_outbox_ack",
    "write_outbox_ack",
]
