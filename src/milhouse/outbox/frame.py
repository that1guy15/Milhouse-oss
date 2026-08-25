"""The versioned, untrusted inbound outbox line envelope ``OutboxFrameV1`` (plan section 4.9:1079).

An outbox line is UNTRUSTED producer input. ``OutboxFrameV1`` is the value-safe, strictly bounded
model every complete line is parsed against: it enforces the declared ``schema_version`` range,
every field length and count cap, an absolute canonical byte ceiling, and rejects unknown or extra
fields. Like the canonical record models it inherits :class:`ValueSafeRecordModel`, so any failed
validation raises a fixed, rejected-value-free error -- the offending bytes or values never reach
the exception's message, args, cause, context, or traceback, and therefore never reach a log, a
diagnostic, or the reader's result. It is deliberately a SEPARATE contract from the canonical
``RecordDraftV1``: mapping a frame to a draft is a later increment, so this envelope can be
versioned and bounded independently of the internal record wire.

This module owns ONLY the typed envelope and its defensive line parser. It has no filesystem,
cursor, or acknowledgement concern.
"""

from __future__ import annotations

from typing import Annotated, Literal, Self

from pydantic import AfterValidator, ConfigDict, Field, model_validator

from milhouse.core.canonical import CanonicalizationError, canonical_json_bytes
from milhouse.core.immutable import freeze_list
from milhouse.domain._validation import ValueSafeRecordModel
from milhouse.domain.identity import MachineIdV1, MachineNameV1
from milhouse.domain.records import DimensionsV1, OpaqueIdV1, UtcTimestampV1
from milhouse.outbox.errors import OutboxError

#: Absolute structural ceiling for one frame's canonical projection. The reader additionally applies
#: the configured, typically smaller, ``max_line_bytes`` bound to the RAW line before parsing; this
#: model-level ceiling is a fail-closed backstop against structural amplification and equals the
#: canonical record byte bound a frame can ever legally map onto.
MAX_OUTBOX_FRAME_BYTES = 262_144
#: The maximum number of producer-supplied evidence references one frame may carry.
MAX_EVIDENCE_REFERENCES = 100

#: The one accepted inbound outbox line actionability vocabulary (mirrors the feedback contract).
OutboxActionabilityV1 = Literal["observe", "investigate", "agent_safe", "needs_approval"]

EvidenceReferencesV1 = Annotated[
    list[OpaqueIdV1],
    Field(max_length=MAX_EVIDENCE_REFERENCES),
    AfterValidator(freeze_list),
]


class OutboxFrameV1(ValueSafeRecordModel):
    """One versioned, bounded outbox line: the untrusted inbound envelope of plan section 4.9.

    ``schema_version`` is a closed ``"1.0"`` literal, so an unknown or future declared version is
    rejected rather than parsed. ``producer_id`` is the stable, bounded producer identity;
    ``target`` is the referenced bounded target id; ``kind`` names the observation kind;
    ``actionability`` is a closed vocabulary; ``evidence_references`` is a count-bounded list of
    opaque producer references; and ``data`` is a bounded structured mapping. Extra or unknown keys
    are forbidden, and the whole canonical projection is bounded by :data:`MAX_OUTBOX_FRAME_BYTES`.
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
    occurred_at: UtcTimestampV1
    target: MachineIdV1
    kind: MachineNameV1
    actionability: OutboxActionabilityV1
    evidence_references: EvidenceReferencesV1 = Field(default_factory=list)
    data: DimensionsV1 = Field(default_factory=dict)

    @model_validator(mode="after")
    def _validate_bounds(self) -> Self:
        try:
            canonical_json_bytes(
                self.model_dump(mode="python", exclude_none=True),
                max_bytes=MAX_OUTBOX_FRAME_BYTES,
            )
        except CanonicalizationError as error:
            raise ValueError("outbox frame is outside the canonical frame bounds") from error
        return self


def parse_outbox_frame_line(line: bytes) -> OutboxFrameV1:
    """Parse one complete outbox line into a validated :class:`OutboxFrameV1`, or fail value-free.

    ``line`` is UNTRUSTED producer bytes (the caller has already applied the ``max_line_bytes`` raw
    bound and stripped the trailing line feed). Parsing runs through pydantic's JSON path so
    canonical RFC3339 timestamp strings decode exactly as written, and the value-safe model
    guarantees a malformed value never reaches the raised error. Any failure -- non-UTF-8,
    non-object JSON, an unknown field, a bound violation, or a bad discriminator -- raises a fixed
    ``MH_OUTBOX_FRAME`` :class:`OutboxError` with NO offending bytes attached, so a caller can count
    the rejection without ever persisting, logging, or echoing the raw line.
    """

    if type(line) is not bytes:
        raise OutboxError("MH_OUTBOX_FRAME", "an outbox line must be raw bytes")
    failed = False
    frame: OutboxFrameV1 | None = None
    try:
        frame = OutboxFrameV1.model_validate_json(line)
    except Exception:
        # The value-safe model already detaches every rejected value; discarding the exception
        # entirely (never binding it, never re-raising from it) is belt-and-suspenders so not even a
        # fixed pydantic message or a __context__ chain can carry a byte outward.
        failed = True
    if failed or frame is None:
        raise OutboxError("MH_OUTBOX_FRAME", "an outbox line is not a valid v1 frame")
    return frame


__all__ = [
    "MAX_EVIDENCE_REFERENCES",
    "MAX_OUTBOX_FRAME_BYTES",
    "OutboxActionabilityV1",
    "OutboxFrameV1",
    "parse_outbox_frame_line",
]
