"""The mode-aware runtime pipeline enforcing collect -> validate -> redact -> spool [-> export].

The pipeline is the single authority that turns configured collectors into durable records. For each
configured collector it resolves the bound collector through the registry, hands it an immutable
:class:`~milhouse.runtime.context.CollectorContext`, and takes back a
:class:`~milhouse.runtime.result.CollectorResult` of drafts. It then, per plan section 4.8 and the
G05 gate ordering:

1. **redacts** every draft's enumerated free-text leaves through the shared :class:`LayeredRedactor`
   — strictly BEFORE identity assignment — as a defense-in-depth pass. The collector remains the
   PRIMARY redaction authority: a :class:`~milhouse.domain.records.RecordDraftV1` is redacted by
   contract, including structured fields such as ``dimensions``/``attributes`` (DimensionsV1 scalar
   values), which this pass does NOT rewrite. This pass re-scans only the enumerated FreeTextV1
   free-text leaves and stamps the record with the redaction policy that actually processed them,
   because the pipeline runs the last redaction pass before the first durable write;
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
from datetime import datetime, timedelta
from pathlib import Path
from types import MappingProxyType
from typing import Literal

from milhouse.config._models import (
    CanaryStateAlertRule,
    CollectorConfig,
    GithubIssuesNotification,
    NotificationConfig,
    RetentionConfig,
    TargetConfig,
    TelegramNotification,
)
from milhouse.core.clock import WallClock, format_timestamp
from milhouse.core.errors import normalize_error
from milhouse.domain.identity import (
    ObservationCoordinateV1,
    derive_notification_intent_id,
)
from milhouse.domain.records import (
    AlertDataV1,
    EventDataV1,
    NotificationIntentDataV1,
    RecordDraftV1,
    RecordEnvelopeV1,
    SourceDescriptorV1,
    TargetDescriptorV1,
    finalize_record,
)
from milhouse.outbox import CursorAdvanceV1, write_outbox_ack
from milhouse.privacy.redact import LayeredRedactor
from milhouse.runtime.alerting import (
    CANARY_STATE_RULE_VERSION,
    AlertOutcome,
    AlertRuleSpec,
    evaluate_canary_state_rule,
)
from milhouse.runtime.context import CollectorContext
from milhouse.runtime.errors import PipelineError
from milhouse.runtime.registry import CollectorRegistry
from milhouse.runtime.result import CollectorResult
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
from milhouse.state import (
    ControlDatabase,
    GlobalCommitBarrier,
    SourceCursor,
    advance_alert_state,
    advance_cursor,
    read_alert_state,
    read_cursor,
)
from milhouse.storage import CLICKHOUSE_EXPORTER_ID

#: One availability sample the alert stage consumes: the mapped outcome and the triggering record id
#: (``None`` when a collector failed with no availability record to cite -- the site_canary no
#: longer does this, since its probe failure now emits a degraded event, but a generic collector
#: that returns failed-with-no-drafts still can).
_AvailabilitySample = tuple[AlertOutcome, str | None]

RuntimeMode = Literal["full", "spool_only"]

# The exact FreeTextV1 free-text leaves each collector-producible record payload can carry. This is
# the pipeline's defense-in-depth pass over the collector's own redaction (a RecordDraftV1 is
# redacted by contract, structured fields included); it re-scans only these enumerated leaves and
# does NOT rewrite structured dimensions/attributes. The keys cover EXACTLY the collector-producible
# record types -- kept symmetric with _RETENTION_FIELDS -- so metric/run/span appear with an empty
# leaf tuple; a record type absent from this map fails closed at redaction (see _redact_draft)
# rather than reaching the spool un-scanned.
_FREE_TEXT_FIELDS: Mapping[str, tuple[str, ...]] = MappingProxyType(
    {
        "event": ("message",),
        "metric": (),
        "run": (),
        "span": (),
        "alert": ("summary",),
        "notification_intent": ("summary",),
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
        # A notification intent shares its alert's retention window (it is derived from, and expires
        # with, one alert transition). A dedicated retention field is a follow-up, not this slice.
        "notification_intent": "alerts_days",
        "feedback_item": "feedback_days",
        "feedback_transition": "feedback_days",
    }
)

_SHA256_HEX_LENGTH = 64
_BATCH_SUFFIX_LENGTH = 24

_NOTIFICATION_INTENT_SOURCE_TYPE = "alert.notification_intent"
_NOTIFICATION_INTENT_RECORD_NAME = "alert.notification_intent"
_NOTIFICATION_INTENT_OBSERVATION_KIND = "alert.notification_intent"
#: A fixed v4-shaped namespace for system-derived notification-intent identity; stable so an intent
#: re-derived for the same (transition, channel) stays idempotent.
_NOTIFICATION_INTENT_NAMESPACE = "mh_ns1_b2f88c3d4e514a6b9c0d1e2f3a4b5c6d"
#: Nominal record expiry; true retention is governed by the segment header and storage TTL.
_NOTIFICATION_INTENT_EXPIRY = timedelta(days=365)
#: A FIXED, privacy-safe summary. It is NEVER interpolated: it names no channel secret, chat id,
#: provider, repository, URL, or target, so no such value can ever reach the durable intent record.
_NOTIFICATION_INTENT_SUMMARY = (
    "A configured notification channel recorded a durable intent to notify for this alert "
    "transition. No message was sent; delivery is out of scope for this record."
)


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
    #: Alert transitions this run emitted, counted by kind. ``alerts_error_code`` is the first fixed
    #: code an isolated alert-rule evaluation failed with, or ``None``. All privacy-safe.
    alerts_fired: int = 0
    alerts_resolved: int = 0
    alerts_error_code: str | None = None
    #: Durable notification-intent records this run emitted (one per committed alert transition x
    #: applicable configured channel). ``intents_error_code`` is the first fixed code an isolated
    #: per-channel intent emission failed with, or ``None``. All privacy-safe — never a channel
    #: secret, chat id, provider, repository, URL, or target.
    intents_emitted: int = 0
    intents_error_code: str | None = None

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
        "_alert_rules",
        "_barrier",
        "_clock",
        "_config_generation",
        "_control",
        "_exporters",
        "_installation_id",
        "_mode",
        "_notifications",
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
        alert_rules: Sequence[CanaryStateAlertRule] = (),
        notifications: Sequence[NotificationConfig] = (),
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
        # deliver_segment resolves an exporter by the map KEY and requires it to self-identify
        # (exporter.exporter_id == key). A mismatched key would return no_exporter and silently
        # strand committed records, so require the key to equal the exporter's own id here.
        _require(
            all(
                getattr(exporter, "exporter_id", None) == key
                for key, exporter in exporter_map.items()
            ),
            "MH_RUNTIME_PIPELINE_EXPORTERS",
            "each exporter must be keyed by its own exporter_id",
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
        alert_rule_tuple = tuple(alert_rules)
        _require(
            all(isinstance(rule, CanaryStateAlertRule) for rule in alert_rule_tuple),
            "MH_RUNTIME_PIPELINE_ALERT_RULES",
            "each alert rule must be a canary_state alert rule",
        )
        notification_tuple = tuple(notifications)
        _require(
            all(
                isinstance(channel, (TelegramNotification, GithubIssuesNotification))
                for channel in notification_tuple
            ),
            "MH_RUNTIME_PIPELINE_NOTIFICATIONS",
            "each notification must be a configured telegram or github_issues channel",
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
        self._alert_rules: tuple[CanaryStateAlertRule, ...] = alert_rule_tuple
        self._notifications: tuple[NotificationConfig, ...] = notification_tuple

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
        # collector id -> the availability sample its run produced (canary rules alert on this).
        availability: dict[str, _AvailabilitySample] = {}
        for config in collectors:
            item = _CollectorWork(collector_id=str(getattr(config, "id", "")))
            work.append(item)
            try:
                self._run_collector(
                    config,
                    item,
                    spool=spool,
                    target_by_id=target_by_id,
                    availability=availability,
                    now=now,
                )
            except Exception as error:
                # Per-collector isolation: never abort the run; capture only the fixed code.
                item.status = "error"
                item.error_code = normalize_error(error).code
                item.records_committed = 0
                item.batch_id = None

        # Alert stage: AFTER the whole collector loop (so every availability record is committed and
        # citable as evidence) and BEFORE the export tail (so full mode drains any alert segment
        # this run emits). Each rule is isolated; a failure never aborts the run or the other rules.
        # It also threads out the committed alert records this run emitted, so the next stage can
        # cite each one by id.
        alerts_fired, alerts_resolved, alerts_error_code, committed_alerts = self._drive_alerts(
            collectors=collectors,
            spool=spool,
            target_by_id=target_by_id,
            availability=availability,
            now=now,
        )

        # Notification-intent stage: AFTER alerts are committed (so each intent cites the alert
        # record and shares its retention window) and BEFORE the export tail (so full mode drains
        # any intent segment this run emits). This stage only RECORDS the intent to notify -- it
        # never sends, previews, retries, rate-limits, or tracks delivery state (all W14). Each
        # channel is isolated: one bad channel never aborts the others or the run.
        intents_emitted, intents_error_code = self._drive_notification_intents(
            committed_alerts=committed_alerts,
            spool=spool,
            now=now,
        )

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
            alerts_fired=alerts_fired,
            alerts_resolved=alerts_resolved,
            alerts_error_code=alerts_error_code,
            intents_emitted=intents_emitted,
            intents_error_code=intents_error_code,
        )

    def _run_collector(
        self,
        config: CollectorConfig,
        item: _CollectorWork,
        *,
        spool: DurableSpool,
        target_by_id: Mapping[str, TargetConfig],
        availability: dict[str, _AvailabilitySample],
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
        # Read the collector's durable source cursor BEFORE building the context so a cursor-bearing
        # collector resumes its incremental read from it (generic opt-in: a non-cursor collector
        # ignores it, and this read never creates a row, so its runtime behaviour is unchanged). The
        # SAME snapshot's revision is the compare-and-set base for the post-commit advance below, so
        # the frontier can only advance from the position this run actually read.
        prior_cursor = read_cursor(self._control, source=str(config.id))
        context = CollectorContext(
            now=now,
            installation_id=self._installation_id,
            collector=descriptor,
            target=target,
            request_timeout_seconds=int(getattr(config, "request_timeout_seconds", 30)),
            redactor=self._redactor,
            prior_cursor=prior_cursor,
        )
        result = collector.collect(context)
        if not isinstance(result, CollectorResult):
            # Fail closed on a duck-typed result: only a real CollectorResult has passed the
            # status/draft-count/diagnostics validation. Caught by the per-collector isolation.
            raise PipelineError(
                "MH_RUNTIME_PIPELINE_RESULT", "the collector returned an invalid result"
            )
        item.status = result.status
        item.drafts_produced = len(result.drafts)
        advance = result.cursor_advance
        if advance is not None and advance.loss_signal is not None:
            # INVARIANT (c): a data-loss read commits NOTHING and advances NOTHING. Surface the
            # fixed loss code as the collector's error, and return BEFORE the availability sample so
            # a loss never becomes an alert failure sample (firing on a loss is a deferred
            # follow-up, not this slice). The reader guarantees no drafts accompany a loss.
            item.status = "failed"
            item.error_code = advance.loss_signal.code
            return
        if result.status == "failed":
            # A collector that failed with no drafts is a failure sample with no privacy-safe
            # record to cite as evidence. The site_canary no longer reaches this path (its probe
            # failure now emits a degraded event); it remains for a generic failed-with-no-drafts
            # collector, whose transition then defers to the first evidence-bearing failure.
            availability[str(config.id)] = ("failure", None)
        if not result.drafts:
            # INVARIANT (a): no drafts -> no commit -> no advance. An empty/unchanged outbox read
            # leaves the cursor untouched, so the next run re-reads from the same position -- an
            # idempotent no-op, never a silent skip past unread bytes.
            return
        records = tuple(self._finalize(draft) for draft in result.drafts)
        header, frames = self._build_segment(str(config.id), records, now=context.now)
        committed = spool.commit_segment(header, frames, committed_at=context.now)
        item.records_committed = committed.record_count
        item.batch_id = committed.batch_id
        # INVARIANT (a): the cursor advances STRICTLY AFTER the segment is durably committed above.
        if advance is not None and advance.next_position is not None:
            self._advance_source_cursor(
                item, advance, source=str(config.id), prior_cursor=prior_cursor, now=now
            )
        # Capture the committed availability record as the alert sample; its record id is the
        # evidence a firing/resolution transition cites.
        sample = _availability_sample(records)
        if sample is not None:
            availability[str(config.id)] = sample

    def _advance_source_cursor(
        self,
        item: _CollectorWork,
        advance: CursorAdvanceV1,
        *,
        source: str,
        prior_cursor: SourceCursor | None,
        now: datetime,
    ) -> None:
        """Advance the durable cursor and write the ack, in isolation, AFTER the segment committed.

        The commit-before-frontier ordering the source cursors and the alert-rule state already use
        (see :meth:`_evaluate_rule`): the segment is durably committed, so this only moves the
        checkpoint forward against ``committed.batch_id``. The cursor is the PRIMARY checkpoint and
        is advanced FIRST -- under a revision compare-and-set against the exact ``prior_cursor``
        this run read -- then the auxiliary ack (whose ``last_sequence`` high-water the collector
        folded monotonically) is written. Any failure here is isolated exactly like an alert
        advance: it NEVER unwinds the durable commit and NEVER aborts the run; it records a fixed
        code, and the un-advanced cursor makes the next run re-read and re-commit the same frames --
        which, because the frame->record identity is deterministic (invariant (b)), the downstream
        delivery ledger collapses. This is commit-before-frontier AT-LEAST-ONCE, not exactly-once.
        """

        assert advance.next_position is not None  # guarded by the caller
        try:
            advance_cursor(
                self._control,
                source=source,
                position=advance.next_position,
                batch_id=item.batch_id or "",
                now=now,
                expected_revision=prior_cursor.revision if prior_cursor is not None else 0,
            )
            if (
                advance.ack is not None
                and advance.ack_directory is not None
                and advance.ack_filename is not None
            ):
                write_outbox_ack(advance.ack_directory, advance.ack_filename, advance.ack)
        except Exception as error:
            # The commit is durable; a failed advance is retried next run (at-least-once). Record
            # the fixed code without touching the committed segment or the other collectors.
            item.error_code = normalize_error(error).code

    def _drive_alerts(
        self,
        *,
        collectors: Sequence[CollectorConfig],
        spool: DurableSpool,
        target_by_id: Mapping[str, TargetConfig],
        availability: Mapping[str, _AvailabilitySample],
        now: datetime,
    ) -> tuple[int, int, str | None, tuple[RecordEnvelopeV1, ...]]:
        """Evaluate every configured alert rule against this run's samples; return the alert counts.

        Each rule is isolated exactly like a collector: a single rule raising is captured as a fixed
        code and never aborts the run or the other rules. A rule whose collector did not run this
        pass (no sample) is a silent no-op. Alongside the counts, this returns every alert record
        actually committed this run, so the notification-intent stage can cite each one by id.
        """

        fired_total = 0
        resolved_total = 0
        error_code: str | None = None
        committed_alerts: list[RecordEnvelopeV1] = []
        if not self._alert_rules:
            return fired_total, resolved_total, error_code, ()
        collector_by_id = {str(config.id): config for config in collectors}
        for rule in self._alert_rules:
            try:
                fired, resolved, committed = self._evaluate_rule(
                    rule,
                    collector_by_id=collector_by_id,
                    spool=spool,
                    target_by_id=target_by_id,
                    availability=availability,
                    now=now,
                )
                fired_total += fired
                resolved_total += resolved
                if committed is not None:
                    committed_alerts.append(committed)
            except Exception as error:
                if error_code is None:
                    error_code = normalize_error(error).code
        return fired_total, resolved_total, error_code, tuple(committed_alerts)

    def _evaluate_rule(
        self,
        rule: CanaryStateAlertRule,
        *,
        collector_by_id: Mapping[str, CollectorConfig],
        spool: DurableSpool,
        target_by_id: Mapping[str, TargetConfig],
        availability: Mapping[str, _AvailabilitySample],
        now: datetime,
    ) -> tuple[int, int, RecordEnvelopeV1 | None]:
        """Run one rule's engine, commit any transition, then CAS-advance the durable rule state.

        Returns the firing/resolution counts and the committed alert record (or ``None`` when this
        sample produced no transition), so the caller can thread the record into the intent stage.
        """

        sample = availability.get(str(rule.collector))
        collector_config = collector_by_id.get(str(rule.collector))
        if sample is None or collector_config is None:
            # The referenced collector produced no sample this run (idle, errored, or unconfigured).
            return 0, 0, None
        target = _target_descriptor(collector_config, target_by_id)
        _require(
            target is not None,
            "MH_RUNTIME_PIPELINE_ALERT",
            "a canary alert rule requires a target-scoped collector",
        )
        assert target is not None  # narrowed by the guard above
        outcome, triggering_record_id = sample
        spec = AlertRuleSpec(
            rule_id=str(rule.id),
            rule_version=CANARY_STATE_RULE_VERSION,
            collector=str(rule.collector),
            consecutive_failures=rule.consecutive_failures,
            consecutive_successes=rule.consecutive_successes,
            cooldown_seconds=rule.cooldown_seconds,
        )
        current = read_alert_state(self._control, spec.rule_id, spec.rule_version)
        evaluation = evaluate_canary_state_rule(
            spec,
            outcome=outcome,
            triggering_record_id=triggering_record_id,
            target=target,
            now=now,
            current=current,
        )
        fired = 0
        resolved = 0
        committed: RecordEnvelopeV1 | None = None
        if evaluation.draft is not None:
            record = self._finalize(evaluation.draft)
            header, frames = self._build_segment(spec.rule_id, (record,), now=now)
            # Commit the durable alert segment FIRST, then CAS-advance the per-rule state below --
            # the same commit-before-frontier ordering the source cursors and derivation checkpoints
            # use, so the frontier never runs ahead of a committed record. This is
            # commit-before-frontier AT-LEAST-ONCE, not full idempotency: a crash (or an
            # ``advance_alert_state`` failure) between this commit and the state advance leaves the
            # per-rule state un-advanced, so the next cycle re-evaluates the still-failing target
            # and can re-emit a firing -- a DUPLICATE firing record for one outage, sharing the
            # ``alert_key`` and possibly the same ``revision`` (only the instant-derived transition
            # id and record id differ). That is the accepted "never miss a fire, may duplicate one"
            # tradeoff, not exactly-once. A commit failure is isolated per rule.
            spool.commit_segment(header, frames, committed_at=now)
            committed = record
            if evaluation.transition == "firing":
                fired = 1
            else:
                resolved = 1
        update = evaluation.update
        advance_alert_state(
            self._control,
            spec.rule_id,
            spec.rule_version,
            consecutive_fail_count=update.consecutive_fail_count,
            consecutive_success_count=update.consecutive_success_count,
            current_state=update.current_state,
            cooldown_until=update.cooldown_until,
            last_sample_at=update.last_sample_at,
            last_transition_id=update.last_transition_id,
            now=now,
            expected_revision=update.expected_revision,
        )
        return fired, resolved, committed

    def _drive_notification_intents(
        self,
        *,
        committed_alerts: Sequence[RecordEnvelopeV1],
        spool: DurableSpool,
        now: datetime,
    ) -> tuple[int, str | None]:
        """Emit one durable notification-intent record per committed alert x applicable channel.

        A channel APPLIES when it is ``enabled`` AND its ``allowed_classifications`` admits the
        alert record's ``privacy_class``. This stage records only the INTENT to notify — it never
        sends, previews, retries, rate-limits, or tracks delivery/"sent" state (all W14). Each
        (alert, channel) intent commits its own homogeneous ``notification_intent`` segment (never
        mixed with the alert segment), isolated per channel: one channel raising is captured as the
        first fixed code and never aborts the other channels or the run.
        """

        emitted = 0
        error_code: str | None = None
        if not self._notifications or not committed_alerts:
            return emitted, error_code
        for alert in committed_alerts:
            for channel in self._notifications:
                if not channel.enabled:
                    continue
                if alert.privacy_class not in channel.allowed_classifications:
                    continue
                try:
                    draft = _notification_intent_draft(alert, channel, now=now)
                    record = self._finalize(draft)
                    source_id = f"{alert.source.id}-{channel.id}"
                    header, frames = self._build_segment(source_id, (record,), now=now)
                    spool.commit_segment(header, frames, committed_at=now)
                    emitted += 1
                except Exception as error:
                    # Per-channel isolation: capture only the fixed code; never abort the others.
                    if error_code is None:
                        error_code = normalize_error(error).code
        return emitted, error_code

    def _finalize(self, draft: RecordDraftV1) -> RecordEnvelopeV1:
        """Redact a draft's free text, then assign its deterministic canonical identity."""

        redacted = _redact_draft(draft, redactor=self._redactor)
        return finalize_record(redacted, installation_id=self._installation_id)

    def _build_segment(
        self,
        source_id: str,
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
            "a segment's records must share one scope, target, and privacy class",
        )
        _require(
            len(record_types) == 1,
            "MH_RUNTIME_PIPELINE_SEGMENT",
            "a segment's records must share one record type",
        )
        batch_id = _batch_id(source_id, records, now=now)
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
            # Attribute EVERY terminal outcome of this run's clickhouse attempts so a committed
            # record is never indistinguishable from "still pending": delivered/already_delivered
            # count as delivered, while every other outcome (failed/no_exporter/expired/segment_gone
            # -- a withheld, unmatched, or vanished segment) counts as failed. Full multi-exporter
            # aggregation across more than one required exporter is deferred; attribution stays
            # scoped to CLICKHOUSE_EXPORTER_ID.
            if attempt.outcome in ("delivered", "already_delivered"):
                item.records_delivered = item.records_committed
            else:
                item.records_failed = item.records_committed
        return None


def _availability_sample(records: tuple[RecordEnvelopeV1, ...]) -> _AvailabilitySample | None:
    """Map a collector's committed availability event to an alert sample and its evidence id.

    A ``healthy`` availability event is a success sample; a ``degraded`` one is a failure sample.
    The committed record's id is the evidence a resulting transition cites. A collector that
    produced no availability event contributes no sample.
    """

    for record in records:
        data = record.data
        if (
            record.record_type == "event"
            and isinstance(data, EventDataV1)
            and data.category == "availability"
        ):
            if data.status == "healthy":
                return ("success", record.record_id)
            if data.status == "degraded":
                return ("failure", record.record_id)
    return None


def _notification_source_generation_digest(rule_id: str, rule_version: int, channel_id: str) -> str:
    """Derive a stable 64-hex source-generation digest for a channel's notification-intent source.

    It binds the source type, the originating rule and its version, and the channel id -- all stable
    across re-runs of the same (transition, channel) -- so a re-derived intent keeps one identity.
    """

    material = f"{_NOTIFICATION_INTENT_SOURCE_TYPE}\x00{rule_id}\x00{rule_version}\x00{channel_id}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _notification_intent_draft(
    alert: RecordEnvelopeV1,
    channel: NotificationConfig,
    *,
    now: datetime,
) -> RecordDraftV1:
    """Build one system-produced notification-intent draft for one committed alert x one channel.

    The intent references the alert ONLY by its record id (as evidence) and names the channel ONLY
    by its non-secret configured ``id`` and ``type``: it carries no bot token, chat id, provider,
    repository, URL, or target name/url anywhere. ``producer="system"`` with no collector provenance
    mirrors the alert draft, and the (transition_id, channel_id) coordinate placed in
    ``source.observation`` makes :func:`~milhouse.domain.records.finalize_record` derive a record
    identity that is idempotent for one transition/channel pair and distinct across pairs. The
    summary is a fixed privacy-safe constant, never interpolated; the severity couples to the
    envelope, matching the alert.
    """

    payload = alert.data
    assert isinstance(payload, AlertDataV1)  # the caller only threads committed alert records
    target = alert.target
    assert target is not None  # an alert transition is always target-scoped
    channel_id = channel.id
    transition_id = payload.transition_id
    observation = ObservationCoordinateV1(
        kind=_NOTIFICATION_INTENT_OBSERVATION_KIND,
        parts={"transition": transition_id, "channel": channel_id},
    )
    source = SourceDescriptorV1(
        id=payload.rule_id,
        type=_NOTIFICATION_INTENT_SOURCE_TYPE,
        producer="system",
        observation_namespace_id=_NOTIFICATION_INTENT_NAMESPACE,
        source_generation_digest=_notification_source_generation_digest(
            payload.rule_id, payload.rule_version, channel_id
        ),
        observation=observation,
    )
    data = NotificationIntentDataV1(
        intent_id=derive_notification_intent_id(transition_id=transition_id, channel_id=channel_id),
        alert_key=payload.alert_key,
        transition_id=transition_id,
        channel_id=channel_id,
        channel_type=channel.type,
        severity=alert.severity,
        summary=_NOTIFICATION_INTENT_SUMMARY,
        evidence_ids=[alert.record_id],
    )
    stamp = format_timestamp(now)
    return RecordDraftV1(
        record_type="notification_intent",
        name=_NOTIFICATION_INTENT_RECORD_NAME,
        occurred_at=now,
        observed_at=now,
        ingested_at=now,
        expires_at=now + _NOTIFICATION_INTENT_EXPIRY,
        operation_id=f"{payload.rule_id}:{channel_id}:{stamp}",
        scope="target",
        source=source,
        target=target,
        severity=alert.severity,
        trust_level="system",
        privacy_class="internal",
        redaction_version="r1-e1",
        data=data,
    )


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
    """Re-scan a draft's enumerated free-text leaves and stamp the applied redaction policy version.

    This runs strictly BEFORE :func:`finalize_record`, as a defense-in-depth pass over the
    collector's own redaction (the collector remains the primary redaction authority, responsible
    for structured fields this pass does not rewrite). A record type no redaction policy governs
    fails closed, mirroring :meth:`RuntimePipeline._retention_days`, rather than reaching the spool
    un-scanned.
    """

    values = draft.model_dump(mode="python", exclude_none=True)
    data = values.get("data")
    if type(data) is dict:  # pragma: no branch - a validated draft always dumps a dict payload
        fields = _FREE_TEXT_FIELDS.get(str(data.get("type")))
        if fields is None:
            # Fail closed on an unmapped record type: never guess a redaction policy, and never let
            # an un-scanned payload reach the durable spool.
            raise PipelineError(
                "MH_RUNTIME_PIPELINE_REDACTION", "no redaction policy governs the record type"
            )
        for field_name in fields:
            text = data.get(field_name)
            if type(text) is str:
                data[field_name] = redactor.redact(text).value
    # This pass ran the last redaction before the first durable write: record the policy that
    # actually processed the free-text leaves, not whatever version the collector claimed.
    values["redaction_version"] = redactor.version
    return RecordDraftV1.model_validate(values)


def _batch_id(source_id: str, records: tuple[RecordEnvelopeV1, ...], *, now: datetime) -> str:
    """Derive a deterministic, unique batch id for any committed segment from its source id, run
    instant, and record ids.

    Deterministic (no wall-clock or random call in library code): identical inputs produce an
    identical id, while any change in the run instant or the derived record ids yields a distinct
    segment. ``source_id`` is whatever produced the segment -- a collector id for an availability
    segment, a rule id for an alert segment -- so this stays record-source-agnostic. A same-instant
    re-run is NOT a silent no-op: the writer refuses to overwrite the existing segment name
    (``MH_SPOOL_EXISTS``), surfaced to the caller as a fixed code, so the durable data is never
    duplicated even though the re-run does not silently succeed.
    """

    stamp = format_timestamp(now)
    material = "\n".join((stamp, *(record.record_id for record in records))).encode("utf-8")
    suffix = hashlib.sha256(material).hexdigest()[:_BATCH_SUFFIX_LENGTH]
    return f"{source_id}-{suffix}"


__all__ = [
    "CollectorRunSummary",
    "PipelineRunSummary",
    "RuntimeMode",
    "RuntimePipeline",
]
