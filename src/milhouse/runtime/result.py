"""The frozen result a collector returns from one run (W05, plan section 4.8).

A collector NEVER writes to the spool. It returns a :class:`CollectorResult`: an ordered tuple of
:class:`~milhouse.domain.records.RecordDraftV1` drafts for the pipeline to redact, finalize, and
commit, a run status, and privacy-safe diagnostic counts (never a raw payload, secret, or path).
The pipeline owns validation, redaction, identity assignment, durable commit, and delivery — so a
collector cannot bypass the collect -> validate -> redact -> spool ordering.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Literal

from milhouse.core.canonical import MAX_CANONICAL_INT
from milhouse.core.immutable import freeze_dict
from milhouse.domain.records import RecordDraftV1
from milhouse.outbox.advance import CursorAdvanceV1
from milhouse.runtime.errors import PipelineError

CollectorStatus = Literal["ok", "failed"]

MAX_RESULT_DRAFTS = 100_000
MAX_DIAGNOSTIC_FIELDS = 64

_DIAGNOSTIC_KEY = re.compile(r"[a-z][a-z0-9_]{0,63}", flags=re.ASCII)


@dataclass(frozen=True, slots=True)
class CollectorResult:
    """One collector's ordered drafts, run status, and privacy-safe diagnostic counts.

    ``cursor_advance`` is the OPTIONAL post-commit sidecar a cursor-bearing collector (the
    ``file_outbox`` collector) returns so the pipeline can advance its durable source cursor and
    write its acknowledgement STRICTLY AFTER the segment commits (W07 increment 2b, plan section
    4.9). It is ``None`` for every non-cursor collector, whose behaviour is entirely unchanged. On a
    data-loss read it carries only ``loss_signal`` (with no drafts), so the pipeline commits and
    advances nothing and surfaces the loss code -- see
    :class:`~milhouse.outbox.advance.CursorAdvanceV1`.
    """

    status: CollectorStatus
    drafts: tuple[RecordDraftV1, ...] = ()
    diagnostics: Mapping[str, int] = field(default_factory=dict)
    cursor_advance: CursorAdvanceV1 | None = None

    def __post_init__(self) -> None:
        if self.status not in ("ok", "failed"):
            raise PipelineError("MH_RUNTIME_RESULT_STATUS", "a collector status is required")
        if type(self.drafts) is not tuple or len(self.drafts) > MAX_RESULT_DRAFTS:
            raise PipelineError(
                "MH_RUNTIME_RESULT_DRAFTS", "collector drafts must be a bounded tuple"
            )
        if any(not isinstance(draft, RecordDraftV1) for draft in self.drafts):
            raise PipelineError(
                "MH_RUNTIME_RESULT_DRAFTS", "each collector draft must be a record draft"
            )
        # Diagnostics are non-sensitive integer counts only (e.g. samples/failures). Reject anything
        # a collector could smuggle a raw value through: non-machine keys, booleans, or numbers
        # outside the canonical integer domain.
        if (
            not isinstance(self.diagnostics, Mapping)
            or len(self.diagnostics) > MAX_DIAGNOSTIC_FIELDS
        ):
            raise PipelineError(
                "MH_RUNTIME_RESULT_DIAGNOSTICS", "collector diagnostics must be bounded counts"
            )
        for key, value in self.diagnostics.items():
            if (
                type(key) is not str
                or _DIAGNOSTIC_KEY.fullmatch(key) is None
                or type(value) is not int
                or not 0 <= value <= MAX_CANONICAL_INT
            ):
                raise PipelineError(
                    "MH_RUNTIME_RESULT_DIAGNOSTICS",
                    "each diagnostic must be a machine key and a non-negative count",
                )
        if self.cursor_advance is not None and not isinstance(self.cursor_advance, CursorAdvanceV1):
            raise PipelineError(
                "MH_RUNTIME_RESULT_CURSOR", "a cursor advance sidecar must be a CursorAdvanceV1"
            )
        object.__setattr__(self, "diagnostics", freeze_dict(dict(self.diagnostics)))


__all__ = ["MAX_DIAGNOSTIC_FIELDS", "MAX_RESULT_DRAFTS", "CollectorResult", "CollectorStatus"]
