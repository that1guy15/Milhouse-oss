"""The ``file_outbox`` collector: incremental ``.milhouse`` outbox frames into event records (W07).

The file-outbox collector turns a compliant append-only ``.milhouse`` outbox
(``feedback-outbox.jsonl``) into canonical ``event`` records, one per new
:class:`~milhouse.outbox.frame.OutboxFrameV1`, resuming from its durable source cursor on every run.
It is bound at construction to the resolved absolute outbox path and the (owner-only ``0700``)
``.milhouse`` acknowledgement directory -- exactly as the site-canary collector binds its URL and
HTTP client -- and it NEVER writes: it reads the prior ack to seed the reader's rotation high-water,
reads the outbox incrementally through the pure :func:`~milhouse.outbox.reader.read_outbox`, maps
each new frame to a draft, and hands the pipeline a
:class:`~milhouse.outbox.advance.CursorAdvanceV1` so the pipeline can advance the cursor and write
the ack STRICTLY AFTER the durable commit (W07 increment 2b). Every durable side effect stays the
pipeline's.

Three safety properties this collector upholds (the crux of the increment):

* **(a) never advance without a commit.** An empty or unchanged read -- or a read that yielded only
  rejected lines -- returns NO drafts and NO advance sidecar, so the pipeline commits and advances
  nothing and the next run re-reads from the same position (idempotent). The cursor advance rides
  the sidecar and is applied by the pipeline only after ``commit_segment`` returns.
* **(b) deterministic record identity from the frame bytes.** Each frame's observation coordinate is
  derived purely from the frame's own canonical bytes (its producer, its declared ``occurred_at``,
  and a SHA-256 over the whole frame) -- NEVER from the run instant or a counter. The envelope's
  identity- and content-affecting fields are likewise frame-derived, while the run-instant
  timestamps it also carries (``observed_at`` / ``ingested_at`` / ``expires_at`` / ``operation_id``
  / ``collector_run_id``) are excluded from both the record identity and the content projection. So
  a commit-then-crash-before-advance replay re-reads the same frame and
  :func:`~milhouse.domain.records.finalize_record` yields the SAME ``record_id`` -- which the
  spool/exporter delivery ledger collapses. This is THE at-least-once safety property.
* **(c) a data loss short-circuits.** If :func:`read_outbox` reports a ``loss_signal`` (truncation,
  a rewritten consumed prefix, a dropped/torn rotated segment, a deleted top-run, or inode reuse),
  the collector returns NO drafts, a ``failed`` status, and a sidecar carrying only the loss signal.
  The pipeline commits nothing, advances nothing, and surfaces the fixed loss code -- Milhouse never
  advances past bytes it cannot prove it read.

Privacy: a rejected or malformed line's raw bytes never leave the reader; the drafts carry only the
producer's declared, bounded frame fields (mapped through the value-safe record models), and the
record's target is the collector's configured target, never a raw producer path or the outbox URL.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import cast

from milhouse.collectors.errors import CollectorError
from milhouse.config._models import CollectorConfig
from milhouse.config._models import FileOutboxCollector as FileOutboxConfig
from milhouse.core.canonical import canonical_json_bytes
from milhouse.core.clock import format_timestamp
from milhouse.domain.identity import ObservationCoordinateV1
from milhouse.domain.records import (
    MAX_DIMENSION_VALUE_BYTES,
    CollectorDescriptorV1,
    EventDataV1,
    RecordDraftV1,
    ScalarV1,
    SourceDescriptorV1,
)
from milhouse.outbox import (
    CursorAdvanceV1,
    OutboxAckV1,
    OutboxFrameV1,
    OutboxReaderConfig,
    read_outbox,
    read_outbox_ack,
)
from milhouse.privacy.redact import LayeredRedactor
from milhouse.runtime.context import CollectorContext
from milhouse.runtime.registry import Collector, CollectorRegistry
from milhouse.runtime.result import CollectorResult

#: The configuration discriminator and registry key for this first-party collector.
FILE_OUTBOX_TYPE = "file_outbox"

_IMPLEMENTATION_VERSION = "1.0.0"
_COLLECTOR_TYPE = "file.outbox"
_SOURCE_TYPE = "source.outbox"
_RECORD_NAME = "outbox.frame"
_OBSERVATION_KIND = "outbox.frame"
#: A fixed v4-shaped namespace for outbox source identity; stable so records stay idempotent across
#: runs, restores, and config changes (it never folds in a mutable config value or a local path).
_OUTBOX_NAMESPACE = "mh_ns1_0b17c0d1e2f34a5b8c6d7e8f9a0b1c2d"
#: Nominal record expiry; true retention is governed by the segment header and storage TTL.
_NOMINAL_EXPIRY = timedelta(days=30)


@dataclass(frozen=True, slots=True)
class FileOutboxBinding:
    """The per-collector resolved paths the CLI binds a file-outbox factory to.

    ``outbox_path`` is the resolved absolute outbox file; ``ack_directory`` is the owner-only
    ``0700`` ``.milhouse`` directory that holds Milhouse's atomic acknowledgement (normally the
    outbox file's own parent).
    """

    outbox_path: Path
    ack_directory: Path


class FileOutboxCollector:
    """A resolved file-outbox collector: its descriptor plus one pure, bounded ``collect`` call."""

    __slots__ = (
        "_ack_directory",
        "_ack_filename",
        "_outbox_path",
        "_reader_config",
        "_source_generation_digest",
        "descriptor",
    )

    def __init__(
        self,
        config: FileOutboxConfig,
        *,
        outbox_path: Path,
        ack_directory: Path,
    ) -> None:
        if not isinstance(config, FileOutboxConfig):
            raise CollectorError("MH_COLLECTOR_CONFIG", "a file_outbox configuration is required")
        self._outbox_path = outbox_path
        self._ack_directory = ack_directory
        self._ack_filename = config.ack_filename
        self._reader_config = OutboxReaderConfig(
            max_line_bytes=config.max_line_bytes,
            max_file_bytes=config.max_file_bytes,
            rotation_glob=config.rotation_glob,
            producer_allowlist=tuple(config.producer_allowlist),
        )
        self._source_generation_digest = _source_generation_digest()
        self.descriptor = CollectorDescriptorV1(
            id=config.id,
            type=_COLLECTOR_TYPE,
            implementation_version=_IMPLEMENTATION_VERSION,
        )

    def collect(self, context: CollectorContext) -> CollectorResult:
        """Read new outbox frames from the cursor and return event drafts plus a cursor-advance."""

        prior_ack = read_outbox_ack(self._ack_directory, self._ack_filename)
        high_water = prior_ack.last_sequence if prior_ack is not None else None
        result = read_outbox(
            file_path=self._outbox_path,
            prior_cursor=context.prior_cursor,
            config=self._reader_config,
            last_acknowledged_sequence=high_water,
        )

        if result.loss_signal is not None:
            # INVARIANT (c): a data loss commits and advances NOTHING. Return no drafts and a
            # sidecar carrying only the loss signal; the pipeline surfaces ``loss_signal.code`` as
            # the fixed error and never advances past bytes it cannot prove it read.
            return CollectorResult(
                status="failed",
                drafts=(),
                diagnostics={"loss": 1},
                cursor_advance=CursorAdvanceV1(loss_signal=result.loss_signal),
            )

        rejected = result.diagnostics.rejected_lines
        if not result.new_frames:
            # INVARIANT (a): no new frames -> no drafts -> no commit -> no advance. This also covers
            # a region of only rejected lines: the cursor stays put and they are re-scanned (and
            # re-counted) idempotently next run, advancing only once a valid frame lets one commit.
            return CollectorResult(
                status="ok",
                drafts=(),
                diagnostics={"frames": 0, "rejected": rejected},
            )

        drafts = tuple(
            self._draft(context, frame, offset=offset)
            for frame, offset in zip(result.new_frames, result.frame_offsets, strict=True)
        )

        # The reader guarantees a non-loss read with frames carries an advanced position + its
        # encoded string; build the ack the pipeline writes AFTER it commits and advances.
        position = result.next_position
        next_position_string = result.next_position_string
        assert position is not None and next_position_string is not None
        ack = OutboxAckV1(
            producer_id=context.collector.id,
            file_device=position.device,
            file_inode=position.inode,
            committed_offset=position.offset,
            content_sha256=position.content_sha256,
            # The reader yields PARSED frames, not raw line bytes, so a raw last-line digest is not
            # available here; the field is optional and unread, so it is left unset rather than
            # populated with a differently-derived value that could be mistaken for a raw-line hash.
            last_line_sha256=None,
            # The collector owns the monotonic rotation high-water fold (it read the prior ack), so
            # the ack the pipeline writes verbatim never regresses ``last_sequence``.
            last_sequence=_fold_high_water(high_water, result.max_observed_sequence),
            acknowledged_at=context.now,
        )
        sidecar = CursorAdvanceV1(
            next_position=next_position_string,
            ack_directory=str(self._ack_directory),
            ack_filename=self._ack_filename,
            ack=ack,
            max_observed_sequence=result.max_observed_sequence,
        )
        return CollectorResult(
            status="ok",
            drafts=drafts,
            diagnostics={
                "frames": len(drafts),
                "rejected": rejected,
                "rotations": result.diagnostics.rotations_crossed,
            },
            cursor_advance=sidecar,
        )

    def _draft(
        self, context: CollectorContext, frame: OutboxFrameV1, *, offset: int
    ) -> RecordDraftV1:
        # INVARIANT (b): the observation coordinate -- the ONLY per-frame varying part of the record
        # identity -- is derived purely from the frame BYTES, never from ``context.now`` or a
        # counter, so a replay of the same frame re-derives the same record_id and the delivery
        # ledger dedups it. Its parts are the producer, the producer's declared occurred_at, a
        # SHA-256 over the whole frame, AND the frame's per-file byte ``offset`` -- the plan
        # section 4.9 "file identity plus byte offset" FALLBACK identity. The offset is what
        # DISTINGUISHES two genuinely distinct but byte-identical frames (same producer, same-
        # millisecond occurred_at, identical body -> identical content digest): they sit at
        # different offsets, so they get distinct record_ids and ReplacingMergeTree does NOT merge
        # them. The offset is stable across a compliant rotation (a rename never moves bytes) and a
        # restore (same bytes), so invariant (b) holds: the crash-before-advance replay re-reads the
        # same frame at the same offset -> same id. Residual: two byte-identical frames at the SAME
        # offset in two DIFFERENT files (per-file offset) would still collide -- an accepted edge.
        now = context.now
        stamp = format_timestamp(now)
        digest = _frame_digest(frame)
        observation = ObservationCoordinateV1(
            kind=_OBSERVATION_KIND,
            parts={
                "producer": frame.producer_id,
                "occurred_at": format_timestamp(frame.occurred_at),
                "offset": offset,
                "content": digest,
            },
        )
        source = SourceDescriptorV1(
            id=context.collector.id,
            type=_SOURCE_TYPE,
            producer="collector",
            observation_namespace_id=_OUTBOX_NAMESPACE,
            source_generation_digest=self._source_generation_digest,
            observation=observation,
        )
        # PRIVACY: ``frame.data`` is UNTRUSTED producer input. The pipeline's defense-in-depth pass
        # only re-scans enumerated free-text leaves (for an event, just ``message``) and explicitly
        # does NOT rewrite structured attributes -- the collector is the PRIMARY redaction authority
        # for structured fields. So the collector MUST redact these string values here, or a
        # producer URL / email / token in ``frame.data`` would reach the durable record (and
        # ClickHouse in full mode) unredacted. Redaction is deterministic for a fixed key, and
        # ``data`` is excluded from the record identity and derives the content hash only after
        # redaction, so this never
        # perturbs invariant (b). (The identity digest above hashes the RAW frame, but that is a
        # one-way SHA-256 folded into an opaque record_id; no raw byte is ever stored or surfaced.)
        data = EventDataV1(
            category=frame.kind,
            status=frame.actionability,
            attributes=_redact_attributes(frame.data, redactor=context.redactor),
        )
        return RecordDraftV1(
            record_type="event",
            name=_RECORD_NAME,
            # occurred_at is the producer's declared instant (frame-derived, identity-stable); the
            # observed/ingested/expiry instants are the run instant and never affect record identity
            # or the content hash.
            occurred_at=frame.occurred_at,
            observed_at=now,
            ingested_at=now,
            expires_at=now + _NOMINAL_EXPIRY,
            operation_id=f"{context.collector.id}:{stamp}",
            collector_run_id=f"{context.collector.id}:{stamp}",
            scope="target",
            source=source,
            collector=context.collector,
            target=context.target,
            severity="info",
            trust_level="authenticated",
            privacy_class="internal",
            redaction_version="r1-e1",
            data=data,
        )


def _redact_attributes(
    attributes: Mapping[str, ScalarV1], *, redactor: LayeredRedactor
) -> dict[str, ScalarV1]:
    """Redact the free-text string values of untrusted producer attributes, preserving structure.

    The collector is the primary redaction authority for structured fields (the pipeline's pass does
    not rewrite attributes). Every string value is run through the layered redactor (URLs, emails,
    paths, and known secrets become fixed markers) and then CLAMPED to the dimension-value byte
    bound; non-string scalars pass through unchanged. The keys are Milhouse-validated dimension
    keys, not producer free text, so they are left as-is.

    Why the clamp is load-bearing: a producer value is bounded to ``MAX_DIMENSION_VALUE_BYTES`` at
    parse, but redaction EXPANDS a short token into a ~24-byte marker, so a value densely packed
    with redactable tokens can redact past that bound (the redactor caps only at its own larger
    limit). Handing such a value to ``EventDataV1.attributes`` -- which re-validates at the
    dimension bound -- would RAISE, so the frame would never commit and the cursor would never
    advance: the identical frame would re-fail every run, a PERMANENT STALL of the whole outbox that
    an untrusted producer could trigger (a denial-of-ingestion). Clamping the already-redacted value
    keeps every attribute within the bound, so ``EventDataV1`` never raises. The clamp only trims
    redaction-marker tail text (never raw producer data, which redaction already removed).
    """

    return {
        key: (_clamp_dimension_value(redactor.redact(value).value) if type(value) is str else value)
        for key, value in attributes.items()
    }


def _clamp_dimension_value(value: str) -> str:
    """Truncate a string to at most ``MAX_DIMENSION_VALUE_BYTES`` UTF-8 bytes on a char boundary.

    The bound is imported from the domain records module (never hardcoded), so it tracks the
    ``DimensionsV1`` validation exactly. Truncation is byte-bounded but UTF-8-safe
    (``errors="ignore"`` drops only the partial trailing multibyte sequence), and a fixed marker
    signals the clamp while staying inside the budget.
    """

    encoded = value.encode("utf-8")
    if len(encoded) <= MAX_DIMENSION_VALUE_BYTES:
        return value
    marker = "[mh:clamp]"
    budget = MAX_DIMENSION_VALUE_BYTES - len(marker)  # marker is pure ASCII, so len == byte length
    return encoded[:budget].decode("utf-8", errors="ignore") + marker


def _frame_digest(frame: OutboxFrameV1) -> str:
    """A SHA-256 over the frame's whole canonical projection: deterministic from the frame bytes."""

    return hashlib.sha256(
        canonical_json_bytes(frame.model_dump(mode="python", exclude_none=True))
    ).hexdigest()


def _fold_high_water(prior: int | None, observed: int | None) -> int | None:
    """Fold the durable rotation high-water forward monotonically: ``max(prior, observed)``."""

    if observed is None:
        return prior
    if prior is None:
        return observed
    return max(prior, observed)


def _source_generation_digest() -> str:
    """A stable 64-hex source-generation digest for the outbox collector's source lineage.

    It binds ONLY the collector type and implementation version -- both constant -- so it never
    changes with a config edit or a machine-local path, keeping every already-committed frame's
    record identity stable across config changes, restores, and hosts.
    """

    material = f"{_COLLECTOR_TYPE}\x00{_IMPLEMENTATION_VERSION}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def build_collector(
    config: FileOutboxConfig, *, outbox_path: Path, ack_directory: Path
) -> FileOutboxCollector:
    """Build one file-outbox collector bound to its resolved outbox path and ack directory."""

    return FileOutboxCollector(config, outbox_path=outbox_path, ack_directory=ack_directory)


def file_outbox_factory(
    outbox_paths: dict[str, FileOutboxBinding],
) -> Callable[[CollectorConfig], Collector]:
    """Build the path-bound first-party factory dispatching each config id to its resolved binding.

    ``outbox_paths`` maps each configured ``file_outbox`` collector id to its resolved
    :class:`FileOutboxBinding`. The registry hands the returned factory the shared collector-config
    union; a config whose id is unbound -- or that is not a file_outbox configuration -- fails
    closed with ``MH_COLLECTOR_CONFIG`` rather than reading an unresolved relative path.
    """

    def factory(config: CollectorConfig) -> Collector:
        binding = outbox_paths.get(str(getattr(config, "id", "")))
        if binding is None:
            raise CollectorError(
                "MH_COLLECTOR_CONFIG", "no resolved outbox path is bound for this collector"
            )
        return build_collector(
            cast(FileOutboxConfig, config),
            outbox_path=binding.outbox_path,
            ack_directory=binding.ack_directory,
        )

    return factory


def register_file_outbox(
    registry: CollectorRegistry, *, outbox_paths: dict[str, FileOutboxBinding]
) -> None:
    """Register the file-outbox factory, path-bound per collector id, into a runtime registry."""

    registry.register(FILE_OUTBOX_TYPE, file_outbox_factory(outbox_paths))


__all__ = [
    "FILE_OUTBOX_TYPE",
    "FileOutboxBinding",
    "FileOutboxCollector",
    "build_collector",
    "file_outbox_factory",
    "register_file_outbox",
]
