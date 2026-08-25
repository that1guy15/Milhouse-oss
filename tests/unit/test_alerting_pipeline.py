"""Integration: canary availability results drive the alert engine through ``RuntimePipeline``.

Registers the real ``site_canary`` factory (with an offline injected client) into a
:class:`CollectorRegistry`, configures one ``canary_state`` alert rule, and drives a sequence of
probes through the spool-only :class:`RuntimePipeline` against a mock transport. It asserts that a
firing/resolution transition commits exactly one ``alert`` segment (system-produced, citing the
availability record) while a steady-state poll commits none, and that the per-rule alert state is
advanced through the durable control plane on every sample.
"""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import httpx
from _http_fakes import (
    fixed_resolver,
    raising_transport,
    responding_transport,
    stream_response,
)
from _record_factories import INSTALLATION_ID, NOW
from _runtime_harness import build_control, canary_config, make_pipeline, target_config

from milhouse.config._models import CanaryStateAlertRule
from milhouse.core.clock import FixedClock
from milhouse.http import BoundedHttpClient
from milhouse.runtime.alerting import CANARY_STATE_RULE_VERSION
from milhouse.runtime.registry import CollectorRegistry
from milhouse.spooling import read_trusted_segment
from milhouse.state import read_alert_state

_PUBLIC = "93.184.216.34"


def _rule(*, failures: int = 1, successes: int = 1, cooldown: int = 0) -> CanaryStateAlertRule:
    return CanaryStateAlertRule(
        id="rule1",
        type="canary_state",
        collector="canary1",
        consecutive_failures=failures,
        consecutive_successes=successes,
        cooldown_seconds=cooldown,
    )


def _registry(status: int) -> tuple[CollectorRegistry, list[httpx.Request]]:
    transport, captured = responding_transport(lambda request: stream_response(status))

    def factory(config: object) -> object:
        from milhouse.collectors.site_canary import build_collector

        client = BoundedHttpClient(resolver=fixed_resolver(_PUBLIC), transport=transport)
        return build_collector(config, client=client)  # type: ignore[arg-type]

    registry = CollectorRegistry()
    from milhouse.collectors.site_canary import SITE_CANARY_TYPE

    registry.register(SITE_CANARY_TYPE, factory)
    return registry, captured


def _raising_registry() -> CollectorRegistry:
    # Every poll's client raises a transport fault, which the bounded client surfaces as an
    # HttpClientError -- a fully-unreachable target that never returns a response.
    transport = raising_transport(httpx.ConnectError("down"))

    def factory(config: object) -> object:
        from milhouse.collectors.site_canary import build_collector

        client = BoundedHttpClient(resolver=fixed_resolver(_PUBLIC), transport=transport)
        return build_collector(config, client=client)  # type: ignore[arg-type]

    registry = CollectorRegistry()
    from milhouse.collectors.site_canary import SITE_CANARY_TYPE

    registry.register(SITE_CANARY_TYPE, factory)
    return registry


def _probe(database, barrier, spool_root, *, status, clock, rules):
    registry, _ = _registry(status)
    pipeline = make_pipeline(
        mode="spool_only",
        registry=registry,
        control=database,
        barrier=barrier,
        spool_root=spool_root,
        clock=clock,
        alert_rules=rules,
    )
    return pipeline.run([canary_config("canary1")], [target_config("t1")])


def _alert_records(spool_root: Path) -> list:
    records = []
    for path in sorted((spool_root / "pending").glob("*/*.jsonl")):
        parsed = read_trusted_segment(path, installation_id=INSTALLATION_ID)
        for frame in parsed.frames:
            if frame.record.record_type == "alert":
                records.append(frame.record)
    return records


def _availability_records(spool_root: Path) -> list:
    records = []
    for path in sorted((spool_root / "pending").glob("*/*.jsonl")):
        parsed = read_trusted_segment(path, installation_id=INSTALLATION_ID)
        for frame in parsed.frames:
            record = frame.record
            if record.record_type == "event" and record.data.category == "availability":
                records.append(record)
    return records


def _state(database):
    return read_alert_state(database, "rule1", CANARY_STATE_RULE_VERSION)


def test_a_degraded_canary_fires_a_steady_poll_is_a_noop_and_a_healthy_canary_resolves(
    tmp_path: Path,
) -> None:
    database, barrier, spool_root = build_control(tmp_path)
    rules = [_rule()]
    try:
        # Run 1: a degraded probe (503) reaches the one-failure threshold and fires.
        first = _probe(
            database, barrier, spool_root, status=503, clock=FixedClock(NOW), rules=rules
        )
        assert (first.alerts_fired, first.alerts_resolved) == (1, 0)
        assert first.alerts_error_code is None
        state = _state(database)
        assert state is not None and state.current_state == "firing"
        alerts = _alert_records(spool_root)
        assert len(alerts) == 1
        firing = alerts[0]
        assert firing.data.state == "firing"
        assert firing.source.producer == "system"
        assert firing.collector is None
        assert firing.severity == firing.data.severity == "error"
        assert len(firing.data.evidence_ids) == 1  # cites the availability record

        # Run 2: another degraded probe is a steady state -- no NEW alert segment, state advances.
        second = _probe(
            database,
            barrier,
            spool_root,
            status=503,
            clock=FixedClock(NOW + timedelta(minutes=1)),
            rules=rules,
        )
        assert (second.alerts_fired, second.alerts_resolved) == (0, 0)
        assert len(_alert_records(spool_root)) == 1  # unchanged: the transition did not repeat
        advanced = _state(database)
        assert advanced is not None and advanced.current_state == "firing"
        assert advanced.revision > state.revision  # the per-rule state still advanced

        # Run 3: a healthy probe (200) reaches the one-success threshold and resolves.
        third = _probe(
            database,
            barrier,
            spool_root,
            status=200,
            clock=FixedClock(NOW + timedelta(minutes=2)),
            rules=rules,
        )
        assert (third.alerts_fired, third.alerts_resolved) == (0, 1)
        alerts = _alert_records(spool_root)
        assert len(alerts) == 2
        assert {record.data.state for record in alerts} == {"firing", "resolved"}
        assert _state(database).current_state == "resolved"
    finally:
        database.close()


def test_a_healthy_canary_with_a_rule_never_fires(tmp_path: Path) -> None:
    database, barrier, spool_root = build_control(tmp_path)
    try:
        summary = _probe(
            database, barrier, spool_root, status=200, clock=FixedClock(NOW), rules=[_rule()]
        )
        assert (summary.alerts_fired, summary.alerts_resolved) == (0, 0)
        assert _alert_records(spool_root) == []
        # The success sample still advances (persists) the rule state at the inactive baseline.
        state = _state(database)
        assert state is not None and state.current_state == "inactive"
        assert state.consecutive_success_count == 1
    finally:
        database.close()


def test_without_configured_rules_no_alert_is_evaluated(tmp_path: Path) -> None:
    database, barrier, spool_root = build_control(tmp_path)
    try:
        summary = _probe(database, barrier, spool_root, status=503, clock=FixedClock(NOW), rules=[])
        assert (summary.alerts_fired, summary.alerts_resolved) == (0, 0)
        assert summary.alerts_error_code is None
        assert _alert_records(spool_root) == []
        assert _state(database) is None  # no rule ran, so no state row exists
        # The availability event itself is still committed (one non-alert segment).
        assert summary.records_committed == 1
    finally:
        database.close()


def test_a_rule_whose_collector_did_not_run_is_a_silent_noop(tmp_path: Path) -> None:
    database, barrier, spool_root = build_control(tmp_path)
    ghost = CanaryStateAlertRule(
        id="rule1",
        type="canary_state",
        collector="ghost",  # not among this run's collectors, so it produces no sample
        consecutive_failures=1,
        consecutive_successes=1,
        cooldown_seconds=0,
    )
    try:
        summary = _probe(
            database, barrier, spool_root, status=503, clock=FixedClock(NOW), rules=[ghost]
        )
        assert (summary.alerts_fired, summary.alerts_resolved) == (0, 0)
        assert summary.alerts_error_code is None
        assert _alert_records(spool_root) == []
        assert _state(database) is None  # the rule never sampled, so its state never advanced
    finally:
        database.close()


def test_a_fully_unreachable_canary_fires_after_consecutive_failures(tmp_path: Path) -> None:
    # Every poll's client RAISES HttpClientError, so the target never returns a response. The
    # canary must still emit a degraded probe-failure event each poll, giving the alert engine a
    # citable evidence record so a fully-down target fires once the threshold is reached.
    database, barrier, spool_root = build_control(tmp_path)
    rules = [_rule(failures=2)]

    def run(clock: FixedClock) -> object:
        pipeline = make_pipeline(
            mode="spool_only",
            registry=_raising_registry(),
            control=database,
            barrier=barrier,
            spool_root=spool_root,
            clock=clock,
            alert_rules=rules,
        )
        return pipeline.run([canary_config("canary1")], [target_config("t1")])

    try:
        # Poll 1: one failure, below the two-failure threshold -- nothing fires yet, but the
        # failing probe still commits one degraded availability evidence record.
        first = run(FixedClock(NOW))
        assert (first.alerts_fired, first.alerts_resolved) == (0, 0)
        assert first.alerts_error_code is None
        assert _alert_records(spool_root) == []
        assert first.records_committed == 1

        # Poll 2: the second consecutive failure reaches the threshold and fires.
        second = run(FixedClock(NOW + timedelta(minutes=1)))
        assert (second.alerts_fired, second.alerts_resolved) == (1, 0)
        alerts = _alert_records(spool_root)
        assert len(alerts) == 1
        firing = alerts[0]
        assert firing.data.state == "firing"
        assert firing.source.producer == "system"
        assert firing.collector is None
        assert firing.severity == firing.data.severity == "error"
        # The firing cites exactly one evidence id, and it resolves to a degraded probe-failure
        # availability record -- proving a fully-down target alerts on a citable record.
        assert len(firing.data.evidence_ids) == 1
        evidence_id = firing.data.evidence_ids[0]
        by_id = {record.record_id: record for record in _availability_records(spool_root)}
        assert evidence_id in by_id
        cited = by_id[evidence_id]
        assert cited.data.status == "degraded"
        assert dict(cited.data.attributes) == {"probe_failed": 1}
        state = _state(database)
        assert state is not None and state.current_state == "firing"
    finally:
        database.close()


def test_a_broken_alert_store_is_isolated_per_rule(tmp_path: Path) -> None:
    database, barrier, spool_root = build_control(tmp_path)
    with database.transaction() as connection:
        connection.execute("DROP TABLE _alert_rule_state")
    # Two rules on the same collector both fail closed on the broken store; the first sets the code
    # and the loop continues to the second without aborting the run.
    first = CanaryStateAlertRule(
        id="rule1",
        type="canary_state",
        collector="canary1",
        consecutive_failures=1,
        consecutive_successes=1,
        cooldown_seconds=0,
    )
    second = CanaryStateAlertRule(
        id="rule2",
        type="canary_state",
        collector="canary1",
        consecutive_failures=1,
        consecutive_successes=1,
        cooldown_seconds=0,
    )
    try:
        summary = _probe(
            database, barrier, spool_root, status=503, clock=FixedClock(NOW), rules=[first, second]
        )
        # Each rule's evaluation fails closed on the broken store; it is captured as a fixed code
        # and never aborts the run. The availability collector still committed its record.
        assert summary.alerts_error_code == "MH_STATE_ALERT"
        assert (summary.alerts_fired, summary.alerts_resolved) == (0, 0)
        assert summary.records_committed == 1
    finally:
        database.close()
