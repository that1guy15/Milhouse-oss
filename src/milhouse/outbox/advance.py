"""The outbox collector's post-commit cursor-advance sidecar (W07 increment 2b, plan section 4.9).

A cursor-bearing collector (the ``file_outbox`` collector today) cannot advance its own durable
checkpoint: the pipeline owns every durable side effect, and a source cursor may advance ONLY in a
transaction that references an already-committed segment (pipeline rule 9). So the collector returns
a :class:`CursorAdvanceV1` alongside its drafts, and the pipeline -- strictly AFTER the segment is
durably committed -- advances the cursor and writes the acknowledgement from it. Non-cursor
collectors leave the sidecar ``None`` and are entirely unaffected.

The sidecar has exactly two shapes, and :meth:`~CursorAdvanceV1.__post_init__` enforces that they
are mutually exclusive and complete:

* **An advance** (``loss_signal is None``): ``next_position`` is the opaque encoded cursor position
  the pipeline hands to :func:`~milhouse.state.cursors.advance_cursor`, and ``ack`` /
  ``ack_directory`` / ``ack_filename`` are the fully-formed acknowledgement the pipeline writes with
  :func:`~milhouse.outbox.ack.write_outbox_ack` once the cursor has advanced. The collector, which
  already read the prior ack to seed the reader's rotation high-water, owns the monotonic
  ``last_sequence`` fold inside ``ack`` -- the pipeline writes the blob verbatim.
* **A data-loss short-circuit** (``loss_signal`` set): the read found an un-recoverable
  discontinuity, so the collector returned NO drafts; the pipeline commits and advances NOTHING and
  surfaces ``loss_signal.code`` as the collector's fixed error code. ``next_position`` stays
  ``None`` so the post-commit hook is a no-op even though (by contract) no segment was committed.

Everything here is internal control metadata handed back to the trusted pipeline, never a spooled
record: it carries a machine-local ack directory path and the privacy-safe cursor/ack scalars, but
never a producer payload byte.
"""

from __future__ import annotations

from dataclasses import dataclass

from milhouse.outbox.ack import OutboxAckV1
from milhouse.outbox.errors import OutboxError
from milhouse.outbox.reader import OutboxLossSignal


@dataclass(frozen=True, slots=True)
class CursorAdvanceV1:
    """One collector's post-commit cursor-advance instruction, or a data-loss short-circuit."""

    next_position: str | None = None
    ack_directory: str | None = None
    ack_filename: str | None = None
    ack: OutboxAckV1 | None = None
    max_observed_sequence: int | None = None
    loss_signal: OutboxLossSignal | None = None

    def __post_init__(self) -> None:
        # Validated in BOTH shapes: a loss sidecar must not carry a nonsense high-water either.
        if self.max_observed_sequence is not None and (
            type(self.max_observed_sequence) is not int or self.max_observed_sequence < 0
        ):
            raise OutboxError(
                "MH_OUTBOX_ADVANCE", "the observed rotation sequence must be a non-negative integer"
            )
        if self.loss_signal is not None:
            if not isinstance(self.loss_signal, OutboxLossSignal):
                raise OutboxError(
                    "MH_OUTBOX_ADVANCE", "a loss signal must be an outbox loss signal"
                )
            # A loss short-circuits: NOTHING advances, so the advance fields must all be absent.
            if (
                self.next_position is not None
                or self.ack is not None
                or self.ack_directory is not None
                or self.ack_filename is not None
            ):
                raise OutboxError(
                    "MH_OUTBOX_ADVANCE", "a loss short-circuit must carry no advance instruction"
                )
            return
        # An advance MUST be complete: the pipeline advances the cursor and writes the ack together.
        if (
            type(self.next_position) is not str
            or not self.next_position
            or type(self.ack_directory) is not str
            or not self.ack_directory
            or type(self.ack_filename) is not str
            or not self.ack_filename
            or not isinstance(self.ack, OutboxAckV1)
        ):
            raise OutboxError(
                "MH_OUTBOX_ADVANCE", "a cursor advance requires a position, ack, and ack location"
            )


__all__ = ["CursorAdvanceV1"]
