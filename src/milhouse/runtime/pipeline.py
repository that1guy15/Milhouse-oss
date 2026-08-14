"""The mode-aware runtime pipeline enforcing collect -> validate -> redact -> spool [-> export].

The pipeline is the single authority that turns configured collectors into durable records. For each
configured collector it resolves the bound collector through the registry, hands it an immutable
:class:`~milhouse.runtime.context.CollectorContext`, and takes back a
:class:`~milhouse.runtime.result.CollectorResult` of drafts. It then, per plan section 4.8 and the
G05 gate ordering:

1. **redacts** every draft's free text through the shared :class:`LayeredRedactor` — strictly BEFORE
   identity assignment, so redactable content can never reach the spool. Redaction stamps the record
   with the redaction policy that actually processed it, because the pipeline (not the collector) is
   the redaction authority before the first durable write;
2. **validates and finalizes** each redacted draft into a canonical
   :class:`~milhouse.domain.records.RecordEnvelopeV1`;
3. **spools** the collector's records as one self-describing segment through
   :meth:`~milhouse.spooling.commit.DurableSpool.commit_segment`, under the shared commit barrier;
4. in ``full`` mode, **drives the existing G03/G04b export tail** —
   :func:`~milhouse.spooling.replay.replay_segments` over the configured exporters — reusing the
   proven exactly-once-logical delivery machine rather than reimplementing delivery. In
   ``spool_only`` mode it stops after the durable commit.

Two safety properties hold. **Per-collector isolation:** one collector raising — or one draft
failing to redact, finalize, or commit — is captured into the run summary as a fixed code and never
aborts the other collectors or the run. **Non-fatal export:** with the warehouse unreachable in
``full`` mode, collection and commit still succeed; the delivery failure is surfaced in the summary
(loud but non-crashing), mirroring the ``storage export`` command. The returned summary carries only
privacy-safe counts, configured identifiers, and fixed codes — never a secret, PII, path, or raw
payload.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from types import MappingProxyType
from typing import Literal

from milhouse.config._models import CollectorConfig, RetentionConfig, TargetConfig
from milhouse.core.clock import WallClock, format_timestamp
from milhouse.core.errors import normalize_error
from milhouse.domain.records import (
    RecordDraftV1,
    RecordEnvelopeV1,
    TargetDescriptorV1,
    finalize_record,
)
from milhouse.privacy.redact import LayeredRedactor
from milhouse.runtime.context import CollectorContext
from milhouse.runtime.errors import PipelineError
from milhouse.runtime.registry import CollectorRegistry
from milhouse.spooling import (
    DurableSpool,
    Exporter,
    SegmentHeaderV1,
    SpoolFrameV1,
    replay_segments,
    spool_content_sha256,
    spool_frame_line,
)
from milhouse.spooling.reader import INSTALLATION_ID_PATTERN
from milhouse.state import ControlDatabase, GlobalCommitBarrier
from milhouse.storage import CLICKHOUSE_EXPORTER_ID

RuntimeMode = Literal["full", "spool_only"]

# The exact free-text leaves each record data payload can carry. Redaction runs over these before
# identity is assigned, so no unredacted free text can reach a durable segment. This is the
# pipeline's defense-in-depth pass over the collector's own redaction (RecordDraftV1 is redacted by
# contract). It covers the record types collectors emit today (canary -> event); as collectors that
# produce metric/run/span land in later increments, EXTEND this map so the net stays complete for
# every record type _RETENTION_FIELDS admits.
_FREE_TEXT_FIELDS: Mapping[str, tuple[str, ...]] = MappingProxyType(
    {
        "event": ("message",),
        "alert": ("summary",),
        "incident": ("summary",),
        "feedback_item": ("title", "summary", "recommendation"),
        "feedback_transition": ("rationale",),
    }
)

# Record type -> the retention window field that governs its durable segment. A collector-produced
# record type without a governing window fails closed rather than guessing a retention policy.
_RETENTION_FIELDS: Mapping[str, str] = MappingProxyType(
    {
        "event": "events_days",
        "metric": "metrics_days",
        "run": "runs_days",
        "span": "trace_events_days",
        "alert": "alerts_days",
        "feedback_item": "feedback_days",
        "feedback_transition": "feedback_days",
    }
)

_SHA256_HEX_LENGTH = 64
_BATCH_SUFFIX_LENGTH = 24


@dataclass(frozen=True, slots=True)
class CollectorRunSummary:
    """The privacy-safe outcome of one collector on a single pipeline run."""

    collector_id: str
    status: Literal["ok", "failed", "error"]
    error_code: str | None
    drafts_produced: int
    records_committed: int
    records_delivered: int
    records_failed: int
    batch_id: str | None


@dataclass(frozen=True, slots=True)
class PipelineRunSummary:
    """The privacy-safe outcome of one whole pipeline run across every configured collector."""

    mode: RuntimeMode
    export_error_code: str | None
    collectors: tuple[CollectorRunSummary, ...]

    @property
    def records_committed(self) -> int:
        return sum(collector.records_committed for collector in self.collectors)

    @property
    def records_delivered(self) -> int:
        return sum(collector.records_delivered for collector in self.collectors)

    @property
    def records_failed(self) -> int:
        return sum(collector.records_failed for collector in self.collectors)


@dataclass(slots=True)
class _CollectorWork:
    """Mutable per-collector accumulator, frozen into a summary at the end of the run."""

    collector_id: str
    status: Literal["ok", "failed", "error"] = "ok"
    error_code: str | None = None
    drafts_produced: int = 0
    records_committed: int = 0
    records_delivered: int = 0
    records_failed: int = 0
    batch_id: str | None = None

    def freeze(self) -> CollectorRunSummary:
        return CollectorRunSummary(
            collector_id=self.collector_id,
            status=self.status,
            error_code=self.error_code,
            drafts_produced=self.drafts_produced,
            records_committed=self.records_committed,
            records_delivered=self.records_delivered,
            records_failed=self.records_failed,
            batch_id=self.batch_id,
        )


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise PipelineError(code, message)


class RuntimePipeline:
    """A configured, mode-aware runtime pipeline over one control plane and durable spool."""

    __slots__ = (
        "_barrier",
        "_clock",
        "_config_generation",
        "_control",
        "_exporters",
        "_installation_id",
        "_mode",
        "_redactor",
        "_registry",
        "_required_exporters",
        "_retention",
        "_spool_root",
    )

    def __init__(
        self,
        *,
        mode: RuntimeMode,
        config_generation: str,
        registry: CollectorRegistry,
        redactor: LayeredRedactor,
        control: ControlDatabase,
        barrier: GlobalCommitBarrier,
        spool_root: str | Path,
        installation_id: str,
        clock: WallClock,
        retention: RetentionConfig,
        exporters: Mapping[str, Exporter] = MappingProxyType({}),
    ) -> None:
        _require(
            mode in ("full", "spool_only"),
            "MH_RUNTIME_PIPELINE_MODE",
            "a runtime mode is required",
        )
        _require(
            type(config_generation) is str
            and len(config_generation) == _SHA256_HEX_LENGTH
            and all(character in "0123456789abcdef" for character in config_generation),
            "MH_RUNTIME_PIPELINE_CONFIG_GENERATION",
            "a 64-hex configuration-generation digest is required",
        )
        _require(
            type(registry) is CollectorRegistry,
            "MH_RUNTIME_PIPELINE_REGISTRY",
            "a collector registry is required",
        )
        _require(
            type(redactor) is LayeredRedactor,
            "MH_RUNTIME_PIPELINE_REDACTOR",
            "a layered redactor is required",
        )
        _require(
            type(control) is ControlDatabase,
            "MH_RUNTIME_PIPELINE_CONTROL",
            "a control database is required",
        )
        _require(
            type(barrier) is GlobalCommitBarrier,
            "MH_RUNTIME_PIPELINE_BARRIER",
            "a commit barrier is required",
        )
        _require(
            type(installation_id) is str
            and INSTALLATION_ID_PATTERN.fullmatch(installation_id) is not None,
            "MH_RUNTIME_PIPELINE_INSTALLATION",
            "a well-formed installation id is required",
        )
        _require(
            type(retention) is RetentionConfig,
            "MH_RUNTIME_PIPELINE_RETENTION",
            "a retention configuration is required",
        )
        _require(
            callable(getattr(clock, "now", None)),
            "MH_RUNTIME_PIPELINE_CLOCK",
            "an injected wall clock is required",
        )
        exporter_map = dict(exporters)
        _require(
            all(isinstance(item, Exporter) for item in exporter_map.values()),
            "MH_RUNTIME_PIPELINE_EXPORTERS",
            "each configured exporter must satisfy the exporter protocol",
        )
        # Mode binds the delivery obligation a committed segment records: spool_only carries none;
        # full records exactly the configured exporter ids and drives them after every commit.
        if mode == "spool_only":
            _require(
                not exporter_map,
                "MH_RUNTIME_PIPELINE_EXPORTERS",
                "spool_only mode must configure no exporters",
            )
        else:
            _require(
                bool(exporter_map),
                "MH_RUNTIME_PIPELINE_EXPORTERS",
                "full mode requires at least one exporter",
            )
        self._mode = mode
        self._config_generation = config_generation
        self._registry = registry
        self._redactor = redactor
        self._control = control
        self._barrier = barrier
        self._spool_root = spool_root
        self._installation_id = installation_id
        self._clock = clock
        self._retention = retention
        self._exporters: Mapping[str, Exporter] = MappingProxyType(exporter_map)
        self._required_exporters = tuple(sorted(exporter_map))

    def run(
        self,
        collectors: Sequence[CollectorConfig],
        targets: Sequence[TargetConfig] = (),
    ) -> PipelineRunSummary:
        """Collect, redact, spool, and (in full mode) deliver every configured collector once.

        A single run instant from the injected clock drives every context, commit, and delivery, so
        the run is deterministic given its inputs. Each collector is isolated: a failure is recorded
        and the run continues. The durable commit always precedes delivery; delivery failure is
        non-fatal and surfaced in the summary.
        """

        now = self._clock.now()
        target_by_id = {target.id: target for target in targets}
        # One writer acquisition for the whole run performs mandatory spool/ledger reconciliation.
        spool = DurableSpool(
            database=self._control,
            barrier=self._barrier,
            spool_root=self._spool_root,
            installation_id=self._installation_id,
        )
        work: list[_CollectorWork] = []
        for config in collectors:
            item = _CollectorWork(collector_id=str(getattr(config, "id", "")))
            work.append(item)
            try:
                self._run_collector(config, item, spool=spool, target_by_id=target_by_id, now=now)
            except Exception as error:
                # Per-collector isolation: never abort the run; capture only the fixed code.
                item.status = "error"
                item.error_code = normalize_error(error).code
                item.records_committed = 0
                item.batch_id = None

        # Full mode ALWAYS drives the delivery tail, even on a run that committed nothing this pass:
        # the tail drains the whole ledger (delivery_status=None), so a backlog a prior warehouse
        # outage left `failed`/`pending` — or a commit-uncertain segment reconciliation registered —
        # is recovered on the next reachable run. Gating export on "this run committed something"
        # would strand that backlog whenever the configured collectors are idle (e.g. a canary that
        # only emits on a state change). Per-collector delivery counts are still attributed strictly
        # to this run's committed batch_ids (see _drive_export), so an idle run reports none.
        export_error_code = None
        if self._mode == "full":
            export_error_code = self._drive_export(work, now=now)

        return PipelineRunSummary(
            mode=self._mode,
            export_error_code=export_error_code,
            collectors=tuple(item.freeze() for item in work),
        )

    def _run_collector(
        self,
        config: CollectorConfig,
        item: _CollectorWork,
        *,
        spool: DurableSpool,
        target_by_id: Mapping[str, TargetConfig],
        now: datetime,
    ) -> None:
        collector = self._registry.resolve(config)
        descriptor = collector.descriptor
        _require(
            descriptor.id == config.id,
            "MH_RUNTIME_PIPELINE_COLLECTOR",
            "the resolved collector id does not match its configuration",
        )
        target = _target_descriptor(config, target_by_id)
        context = CollectorContext(
            now=now,
            installation_id=self._installation_id,
            collector=descriptor,
            target=target,
            request_timeout_seconds=int(getattr(config, "request_timeout_seconds", 30)),
            redactor=self._redactor,
        )
        result = collector.collect(context)
        item.status = result.status
        item.drafts_produced = len(result.drafts)
        if not result.drafts:
            return
        records = tuple(self._finalize(draft) for draft in result.drafts)
        header, frames = self._build_segment(config, records, now=context.now)
        committed = spool.commit_segment(header, frames, committed_at=context.now)
        item.records_committed = committed.record_count
        item.batch_id = committed.batch_id

    def _finalize(self, draft: RecordDraftV1) -> RecordEnvelopeV1:
        """Redact a draft's free text, then assign its deterministic canonical identity."""

        redacted = _redact_draft(draft, redactor=self._redactor)
        return finalize_record(redacted, installation_id=self._installation_id)

    def _build_segment(
        self,
        config: CollectorConfig,
        records: tuple[RecordEnvelopeV1, ...],
        *,
        now: datetime,
    ) -> tuple[SegmentHeaderV1, tuple[SpoolFrameV1, ...]]:
        scopes = {record.scope for record in records}
        privacy_classes = {record.privacy_class for record in records}
        target_ids = {record.target.id if record.target is not None else None for record in records}
        record_types = {record.record_type for record in records}
        _require(
            len(scopes) == 1 and len(privacy_classes) == 1 and len(target_ids) == 1,
            "MH_RUNTIME_PIPELINE_SEGMENT",
            "a collector's records must share one scope, target, and privacy class",
        )
        _require(
            len(record_types) == 1,
            "MH_RUNTIME_PIPELINE_SEGMENT",
            "a collector's records must share one record type",
        )
        batch_id = _batch_id(str(config.id), records, now=now)
        frames = tuple(
            SpoolFrameV1(batch_id=batch_id, sequence=index, record=record)
            for index, record in enumerate(records, start=1)
        )
        lines = [spool_frame_line(frame) for frame in frames]
        header = SegmentHeaderV1(
            batch_id=batch_id,
            config_generation=self._config_generation,
            scope=next(iter(scopes)),
            target_id=next(iter(target_ids)),
            privacy_class=next(iter(privacy_classes)),
            retention_days=self._retention_days(next(iter(record_types))),
            required_exporters=self._required_exporters,
            record_count=len(frames),
            content_sha256=spool_content_sha256(lines),
        )
        return header, frames

    def _retention_days(self, record_type: str) -> int:
        attribute = _RETENTION_FIELDS.get(record_type)
        if attribute is None:
            raise PipelineError(
                "MH_RUNTIME_PIPELINE_RETENTION",
                "no retention window governs the collector's record type",
            )
        return int(getattr(self._retention, attribute))

    def _drive_export(self, work: Sequence[_CollectorWork], *, now: datetime) -> str | None:
        """Drive the existing replay/delivery tail; a delivery failure is non-fatal and recorded.

        OWNERSHIP GUARD (W06 wiring obligation): this pipeline is exporter-agnostic — it holds only
        ``Exporter`` protocol objects — so, exactly like :func:`replay_segments`, it does
        NOT itself take the ClickHouse single-installation ownership guard (that check is
        ClickHouse-specific and lives with the client, per PR #128). The command layer that
        CONSTRUCTS a :class:`~milhouse.storage.delivery.ClickHouseExporter` and hands it to this
        pipeline in ``full`` mode MUST call ``storage.require_owner`` first, exactly as the
        ``storage export`` command does; otherwise a second installation pointed at another
        installation's ClickHouse could deliver to it. This is the same command-layer placement the
        ownership guard already uses; W06 wires the `collect` command.
        """

        committed_at_delivery = {item.batch_id: item for item in work if item.batch_id is not None}
        try:
            report = replay_segments(
                self._control,
                self._barrier,
                spool_root=self._spool_root,
                installation_id=self._installation_id,
                exporters=self._exporters,
                now=now,
                # Drain all committed segments (idempotent for delivered), so this run also
                # retries a segment a prior outage left failed — the proven G03/G04b recovery shape.
                delivery_status=None,
            )
        except Exception as error:
            # A spool-integrity failure in the tail never loses the durable commit; surface a code.
            return normalize_error(error).code
        for attempt in report.delivery_attempts:
            if attempt.exporter_id != CLICKHOUSE_EXPORTER_ID:
                continue
            item = committed_at_delivery.get(attempt.batch_id)
            if item is None:
                continue
            # Two independent guards (not if/elif) so both arcs of each are exercised; an outcome
            # that is neither delivered nor failed (e.g. a withheld segment) records neither.
            if attempt.outcome in ("delivered", "already_delivered"):
                item.records_delivered = item.records_committed
            if attempt.outcome == "failed":
                item.records_failed = item.records_committed
        return None


def _target_descriptor(
    config: CollectorConfig, target_by_id: Mapping[str, TargetConfig]
) -> TargetDescriptorV1 | None:
    """Build the target descriptor for a target-scoped collector from its configured target."""

    target_id = getattr(config, "target", None)
    if target_id is None:
        return None
    target = target_by_id.get(str(target_id))
    _require(
        target is not None,
        "MH_RUNTIME_PIPELINE_TARGET",
        "the collector target is not a declared target",
    )
    assert target is not None  # narrowed by the guard above
    return TargetDescriptorV1(
        id=target.id,
        name=target.name,
        kind=target.kind,
        environment=target.environment,
    )


def _redact_draft(draft: RecordDraftV1, *, redactor: LayeredRedactor) -> RecordDraftV1:
    """Redact a draft's free-text leaves and stamp the applied redaction policy version.

    This runs strictly BEFORE :func:`finalize_record`, so a draft carrying redactable content is
    always redacted before it can reach the spool. Redaction is defense in depth: even a collector
    that neglected to redact cannot smuggle raw free text past this gate.
    """

    values = draft.model_dump(mode="python", exclude_none=True)
    data = values.get("data")
    if type(data) is dict:  # pragma: no branch - a validated draft always dumps a dict payload
        data_type = data.get("type")
        for field_name in _FREE_TEXT_FIELDS.get(str(data_type), ()):
            text = data.get(field_name)
            if type(text) is str:
                data[field_name] = redactor.redact(text).value
    # The pipeline is the redaction authority before the first durable write: record the policy that
    # actually processed the content, not whatever version the collector claimed.
    values["redaction_version"] = redactor.version
    return RecordDraftV1.model_validate(values)


def _batch_id(collector_id: str, records: tuple[RecordEnvelopeV1, ...], *, now: datetime) -> str:
    """Derive a deterministic, unique batch id from the collector, run instant, and record ids.

    Deterministic (no wall-clock or random call in library code): identical inputs produce an
    identical id, so a re-run of the exact same collection is idempotent at the segment file and
    ledger, while any change in the run instant or the derived record ids yields a distinct segment.
    """

    stamp = format_timestamp(now)
    material = "\n".join((stamp, *(record.record_id for record in records))).encode("utf-8")
    suffix = hashlib.sha256(material).hexdigest()[:_BATCH_SUFFIX_LENGTH]
    return f"{collector_id}-{suffix}"


__all__ = [
    "CollectorRunSummary",
    "PipelineRunSummary",
    "RuntimeMode",
    "RuntimePipeline",
]
