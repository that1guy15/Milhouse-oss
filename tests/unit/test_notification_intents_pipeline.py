"""Integration: committed alert transitions drive durable notification-intent records (W05 inc 4).

Drives the real ``site_canary`` collector through the :class:`RuntimePipeline` with one
``canary_state`` alert rule and configured notification channels, and asserts that when an alert
transition commits, the runtime ALSO emits one durable notification-intent record per applicable
channel -- WITHOUT sending anything (delivery/transports/retry/rate-limit/"sent" state are all W14).

It proves channel applicability (``enabled`` AND an ``allowed_classifications`` that admits the
alert's privacy class), that a steady poll with no transition emits none, that each intent cites the
alert record id, that a homogeneous ``notification_intent`` segment is drained by the full-mode
export tail, that NO channel secret/chat-id/provider/repository/url/target-url string leaks into the
intent bytes/summary/run summary, and that a failing channel is isolated from the others.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from _http_fakes import fixed_resolver, responding_transport, stream_response
from _record_factories import INSTALLATION_ID, NOW
from _runtime_harness import (
    build_control,
    canary_config,
    clickhouse_exporters,
    make_pipeline,
    target_config,
)
from _storage_fakes import FakeClickHouseClient

from milhouse.collectors.site_canary import SITE_CANARY_TYPE, build_collector
from milhouse.config._models import (
    CanaryStateAlertRule,
    GithubIssuesNotification,
    SiteCanaryCollector,
    TargetConfig,
    TelegramNotification,
)
from milhouse.core.clock import FixedClock
from milhouse.http import BoundedHttpClient
from milhouse.runtime.errors import PipelineError
from milhouse.runtime.pipeline import (
    _FREE_TEXT_FIELDS,
    _NOTIFICATION_INTENT_SUMMARY,
    _RETENTION_FIELDS,
)
from milhouse.runtime.registry import CollectorRegistry
from milhouse.spooling import read_trusted_segment

_PUBLIC = "93.184.216.34"


def _rule() -> CanaryStateAlertRule:
    return CanaryStateAlertRule(
        id="rule1",
        type="canary_state",
        collector="canary1",
        consecutive_failures=1,
        consecutive_successes=1,
        cooldown_seconds=0,
    )


def _telegram(
    channel_id: str,
    *,
    enabled: bool = True,
    classifications: list[str] | None = None,
    bot_token_env: str = "PLACEHOLDER_BOT_TOKEN_ENV",
    chat_id_env: str = "PLACEHOLDER_CHAT_ID_ENV",
) -> TelegramNotification:
    return TelegramNotification(
        id=channel_id,
        type="telegram",
        enabled=enabled,
        bot_token_env=bot_token_env,
        chat_id_env=chat_id_env,
        allowed_classifications=classifications or ["internal"],  # type: ignore[arg-type]
    )


def _github(
    channel_id: str,
    *,
    enabled: bool = True,
    provider: str = "placeholder-provider",
    repository: str = "placeholder-owner/placeholder-repo",
    label: str = "placeholder-label",
) -> GithubIssuesNotification:
    return GithubIssuesNotification(
        id=channel_id,
        type="github_issues",
        enabled=enabled,
        provider=provider,
        repository=repository,
        label_allowlist=[label],
        enabled_priorities=["P1"],
        enabled_actionabilities=["observe"],
        allowed_classifications=["internal"],
    )


def _registry(status: int) -> CollectorRegistry:
    transport, _ = responding_transport(lambda request: stream_response(status))

    def factory(config: object) -> object:
        client = BoundedHttpClient(resolver=fixed_resolver(_PUBLIC), transport=transport)
        return build_collector(config, client=client)  # type: ignore[arg-type]

    registry = CollectorRegistry()
    registry.register(SITE_CANARY_TYPE, factory)
    return registry


def _run(
    database,
    barrier,
    spool_root,
    *,
    status: int,
    notifications,
    mode: str = "spool_only",
    exporters=None,
    canary=None,
    target=None,
):
    pipeline = make_pipeline(
        mode=mode,
        registry=_registry(status),
        control=database,
        barrier=barrier,
        spool_root=spool_root,
        clock=FixedClock(NOW),
        alert_rules=[_rule()],
        notifications=notifications,
        exporters=exporters,
    )
    return pipeline.run(
        [canary or canary_config("canary1")],
        [target or target_config("t1")],
    )


def _records(spool_root: Path, record_type: str) -> list:
    records = []
    for path in sorted((spool_root / "pending").glob("*/*.jsonl")):
        parsed = read_trusted_segment(path, installation_id=INSTALLATION_ID)
        for frame in parsed.frames:
            if frame.record.record_type == record_type:
                records.append(frame.record)
    return records


def _intent_segment_bytes(spool_root: Path) -> bytes:
    """The concatenated raw durable bytes of every homogeneous notification_intent segment."""

    blob = b""
    for path in sorted((spool_root / "pending").glob("*/*.jsonl")):
        parsed = read_trusted_segment(path, installation_id=INSTALLATION_ID)
        if all(frame.record.record_type == "notification_intent" for frame in parsed.frames):
            blob += path.read_bytes()
    return blob


# --- applicability: one intent per applicable channel, citing the alert -------------------------


def test_a_firing_alert_emits_one_intent_per_applicable_channel_citing_the_alert(
    tmp_path: Path,
) -> None:
    database, barrier, spool_root = build_control(tmp_path)
    try:
        summary = _run(
            database,
            barrier,
            spool_root,
            status=503,
            notifications=[_telegram("telegram1"), _github("github1")],
        )
        assert (summary.alerts_fired, summary.alerts_resolved) == (1, 0)
        assert summary.intents_emitted == 2
        assert summary.intents_error_code is None

        alerts = _records(spool_root, "alert")
        assert len(alerts) == 1
        alert = alerts[0]

        intents = _records(spool_root, "notification_intent")
        assert len(intents) == 2
        by_channel = {intent.data.channel_id: intent for intent in intents}
        assert set(by_channel) == {"telegram1", "github1"}
        assert by_channel["telegram1"].data.channel_type == "telegram"
        assert by_channel["github1"].data.channel_type == "github_issues"
        for intent in intents:
            # Every intent references exactly the committed alert record as its evidence ...
            assert list(intent.data.evidence_ids) == [alert.record_id]
            # ... shares the alert's transition identity and coupled severity ...
            assert intent.data.alert_key == alert.data.alert_key
            assert intent.data.transition_id == alert.data.transition_id
            assert intent.severity == intent.data.severity == alert.severity == "error"
            # ... is system-produced, target-scoped, internal, with the FIXED summary ...
            assert intent.source.producer == "system"
            assert intent.collector is None
            assert intent.scope == "target"
            assert intent.privacy_class == "internal"
            assert intent.data.summary == _NOTIFICATION_INTENT_SUMMARY
    finally:
        database.close()


def test_re_deriving_the_same_transition_and_channel_yields_the_identical_intent_identity(
    tmp_path: Path,
) -> None:
    # Idempotency: the (transition_id, channel_id) coordinate makes the intent record id stable, so
    # a second identical build of the same alert x channel derives the same record and intent ids.
    from milhouse.domain.records import finalize_record
    from milhouse.runtime.pipeline import _notification_intent_draft

    database, barrier, spool_root = build_control(tmp_path)
    try:
        _run(
            database,
            barrier,
            spool_root,
            status=503,
            notifications=[_telegram("telegram1")],
        )
        alert = _records(spool_root, "alert")[0]
        channel = _telegram("telegram1")
        first = finalize_record(
            _notification_intent_draft(alert, channel, now=NOW), installation_id=INSTALLATION_ID
        )
        second = finalize_record(
            _notification_intent_draft(alert, channel, now=NOW), installation_id=INSTALLATION_ID
        )
        assert first.record_id == second.record_id
        assert first.data.intent_id == second.data.intent_id
        # A different channel for the same transition derives a distinct record identity.
        other = finalize_record(
            _notification_intent_draft(alert, _telegram("telegram2"), now=NOW),
            installation_id=INSTALLATION_ID,
        )
        assert other.record_id != first.record_id
        assert other.data.intent_id != first.data.intent_id
    finally:
        database.close()


def test_a_disabled_or_classification_excluded_channel_emits_no_intent(tmp_path: Path) -> None:
    database, barrier, spool_root = build_control(tmp_path)
    try:
        summary = _run(
            database,
            barrier,
            spool_root,
            status=503,
            notifications=[
                _telegram("disabled1", enabled=False),  # enabled=False -> never applies
                _telegram("publiconly1", classifications=["public"]),  # excludes "internal"
            ],
        )
        assert summary.alerts_fired == 1
        assert summary.intents_emitted == 0
        assert summary.intents_error_code is None
        assert _records(spool_root, "notification_intent") == []
    finally:
        database.close()


def test_a_steady_poll_with_no_transition_emits_no_intent(tmp_path: Path) -> None:
    database, barrier, spool_root = build_control(tmp_path)
    try:
        # A healthy probe with an inactive rule produces no transition, so no alert, so no intent --
        # even with an applicable channel configured.
        summary = _run(
            database,
            barrier,
            spool_root,
            status=200,
            notifications=[_telegram("telegram1")],
        )
        assert (summary.alerts_fired, summary.alerts_resolved) == (0, 0)
        assert summary.intents_emitted == 0
        assert _records(spool_root, "alert") == []
        assert _records(spool_root, "notification_intent") == []
    finally:
        database.close()


# --- the intent segment is drained by the existing export tail ----------------------------------


def test_a_homogeneous_intent_segment_is_drained_by_the_full_mode_export(tmp_path: Path) -> None:
    database, barrier, spool_root = build_control(tmp_path)
    try:
        client = FakeClickHouseClient()
        summary = _run(
            database,
            barrier,
            spool_root,
            status=503,
            notifications=[_telegram("telegram1")],
            mode="full",
            exporters=clickhouse_exporters(client),
        )
        assert summary.intents_emitted == 1
        assert summary.export_error_code is None
        # The reused G03/G04b export tail drained the intent segment into the records table.
        inserted_types = set()
        for _db, table, rows, columns in client.inserts:
            if table != "records" or "record_type" not in columns:
                continue
            index = list(columns).index("record_type")
            inserted_types.update(str(row[index]) for row in rows)
        assert "notification_intent" in inserted_types
    finally:
        database.close()


# --- privacy: no channel secret / url / target-url leaks into the intent ------------------------


def test_no_channel_secret_or_url_or_target_leaks_into_the_intent(tmp_path: Path) -> None:
    leak_markers = [
        "LEAKBOTTOKEN",
        "LEAKCHATID",
        "leakprovider",
        "leakowner/leakrepo",
        "leaklabel",
        "leakcanaryurl.example",
        "leaktargeturl.example",
    ]
    canary = SiteCanaryCollector(
        id="canary1",
        target="t1",
        type="site_canary",
        url="https://leakcanaryurl.example/probe",
        expected_statuses=[200],
    )
    target = TargetConfig(
        id="t1",
        name="Example Target",
        kind="web_service",
        environment="test",
        base_url="https://leaktargeturl.example",
    )
    database, barrier, spool_root = build_control(tmp_path)
    try:
        summary = _run(
            database,
            barrier,
            spool_root,
            status=503,
            notifications=[
                _telegram("telegram1", bot_token_env="LEAKBOTTOKEN", chat_id_env="LEAKCHATID"),
                _github(
                    "github1",
                    provider="leakprovider",
                    repository="leakowner/leakrepo",
                    label="leaklabel",
                ),
            ],
            canary=canary,
            target=target,
        )
        assert summary.intents_emitted == 2

        intent_bytes = _intent_segment_bytes(spool_root)
        assert intent_bytes  # the intent segments exist and were read
        summary_repr = repr(summary)
        for marker in leak_markers:
            # No channel secret ref, provider, repository, label, canary url, or target url reaches
            # the durable intent bytes, its fixed summary, or the privacy-safe run summary.
            assert marker.encode("utf-8") not in intent_bytes
            assert marker not in _NOTIFICATION_INTENT_SUMMARY
            assert marker not in summary_repr
        for intent in _records(spool_root, "notification_intent"):
            for marker in leak_markers:
                assert marker not in intent.data.summary
    finally:
        database.close()


# --- per-channel isolation ----------------------------------------------------------------------


def test_a_failing_channel_is_isolated_and_never_aborts_the_others(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import milhouse.runtime.pipeline as pipeline_module

    original = pipeline_module._notification_intent_draft

    def flaky(alert, channel, *, now):
        if channel.id == "boom":
            raise RuntimeError("channel boom with a secret PLACEHOLDER_BOT_TOKEN_ENV")
        return original(alert, channel, now=now)

    monkeypatch.setattr(pipeline_module, "_notification_intent_draft", flaky)

    database, barrier, spool_root = build_control(tmp_path)
    try:
        summary = _run(
            database,
            barrier,
            spool_root,
            status=503,
            notifications=[_telegram("boom"), _telegram("good1")],
        )
        # The failing channel is isolated with a fixed code; the healthy channel still emitted, and
        # the alert itself still committed -- the run was never aborted.
        assert summary.alerts_fired == 1
        assert summary.intents_emitted == 1
        assert summary.intents_error_code == "MH_INTERNAL_UNEXPECTED"
        intents = _records(spool_root, "notification_intent")
        assert [intent.data.channel_id for intent in intents] == ["good1"]
        assert "PLACEHOLDER_BOT_TOKEN_ENV" not in repr(summary)
    finally:
        database.close()


# --- construction guard and static wiring -------------------------------------------------------


def test_a_non_channel_notification_fails_closed_at_construction(tmp_path: Path) -> None:
    database, barrier, spool_root = build_control(tmp_path)
    try:
        with pytest.raises(PipelineError) as caught:
            make_pipeline(
                mode="spool_only",
                registry=_registry(200),
                control=database,
                barrier=barrier,
                spool_root=spool_root,
                clock=FixedClock(NOW),
                notifications=["not a channel"],
            )
        assert caught.value.code == "MH_RUNTIME_PIPELINE_NOTIFICATIONS"
    finally:
        database.close()


def test_notification_intent_is_wired_into_the_redaction_and_retention_maps() -> None:
    # A record type absent from either map fails closed (see _redact_draft / _retention_days), so a
    # new type MUST be in both to redact its segment and earn a retention window.
    assert _FREE_TEXT_FIELDS["notification_intent"] == ("summary",)
    assert _RETENTION_FIELDS["notification_intent"] == "alerts_days"
