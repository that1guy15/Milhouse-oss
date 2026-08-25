"""Fixed, privacy-safe failures for the ``.milhouse`` outbox reader (W07, plan section 4.9).

Every outbox failure is a stable ``MH_OUTBOX_*`` code raised outside any active exception handler,
so no filesystem, JSON, or producer-supplied detail reaches the error's cause, context, args, or
traceback. The stable codes -- and the privacy-safe counts, offsets, and hex digests carried by the
reader's result -- are the only machine surface; a rejected line's raw bytes never appear anywhere.
"""

from __future__ import annotations

from milhouse.core.errors import MilhouseValueError


class OutboxError(MilhouseValueError):
    """A stable, value-free outbox reader/ack failure carrying only a code and static message."""
