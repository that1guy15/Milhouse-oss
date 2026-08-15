"""Integration: the site-canary collector driven through the increment-1 runtime pipeline.

Registers the real ``site_canary`` factory (with an offline injected client) into a
:class:`CollectorRegistry`, runs it through the spool-only :class:`RuntimePipeline` against a mock
transport, and asserts exactly one redacted ``event`` segment is committed through the durable spool
and reads back with the expected availability status.
"""

from __future__ import annotations

from pathlib import Path

import httpx
from _http_fakes import fixed_resolver, responding_transport, stream_response
from _record_factories import INSTALLATION_ID, NOW
from _runtime_harness import build_control, canary_config, make_pipeline, target_config

from milhouse.collectors.site_canary import SITE_CANARY_TYPE, build_collector
from milhouse.core.clock import FixedClock
from milhouse.http import BoundedHttpClient
from milhouse.runtime.registry import CollectorRegistry
from milhouse.spooling import read_trusted_segment

_CLOCK = FixedClock(instant=NOW)
_PUBLIC = "93.184.216.34"
_DAY = "2026-07-21"


def _registry(response_factory, *, resolver=None) -> tuple[CollectorRegistry, list[httpx.Request]]:
    transport, captured = responding_transport(response_factory)

    def factory(config: object) -> object:
        client = BoundedHttpClient(
            resolver=resolver or fixed_resolver(_PUBLIC), transport=transport
        )
        return build_collector(config, client=client)  # type: ignore[arg-type]

    registry = CollectorRegistry()
    registry.register(SITE_CANARY_TYPE, factory)
    return registry, captured


def _run(tmp_path: Path, response_factory, *, resolver=None):
    database, barrier, spool_root = build_control(tmp_path)
    try:
        registry, captured = _registry(response_factory, resolver=resolver)
        pipeline = make_pipeline(
            mode="spool_only",
            registry=registry,
            control=database,
            barrier=barrier,
            spool_root=spool_root,
            clock=_CLOCK,
        )
        summary = pipeline.run([canary_config("canary1")], [target_config("t1")])
        return summary, spool_root, captured
    finally:
        database.close()


def test_a_healthy_probe_commits_one_redacted_event_segment(tmp_path: Path) -> None:
    summary, spool_root, captured = _run(tmp_path, lambda request: stream_response(200))
    assert summary.records_committed == 1
    item = summary.collectors[0]
    assert item.status == "ok"
    assert item.batch_id is not None
    assert len(captured) == 1  # exactly one outbound probe

    path = spool_root / "pending" / _DAY / f"{item.batch_id}.jsonl"
    parsed = read_trusted_segment(path, installation_id=INSTALLATION_ID)
    assert len(parsed.frames) == 1
    record = parsed.frames[0].record
    assert record.record_type == "event"
    assert record.data.category == "availability"
    assert record.data.status == "healthy"
    assert record.data.attributes["http_status"] == 200
    # The pipeline is the redaction authority and stamps the policy it actually applied.
    assert record.redaction_version == "r2-e1"


def test_a_degraded_probe_still_commits_one_event_segment(tmp_path: Path) -> None:
    summary, spool_root, _ = _run(tmp_path, lambda request: stream_response(503))
    assert summary.records_committed == 1
    item = summary.collectors[0]
    assert item.status == "ok"
    assert item.batch_id is not None

    path = spool_root / "pending" / _DAY / f"{item.batch_id}.jsonl"
    record = read_trusted_segment(path, installation_id=INSTALLATION_ID).frames[0].record
    assert record.data.status == "degraded"


def test_a_blocked_target_commits_one_degraded_probe_failure_event(
    tmp_path: Path,
) -> None:
    summary, spool_root, captured = _run(
        tmp_path, lambda request: stream_response(200), resolver=fixed_resolver("10.0.0.5")
    )
    item = summary.collectors[0]
    # A fully-blocked target stays alertable: the probe failure commits ONE degraded availability
    # event carrying only a privacy-safe probe_failed count -- never a false-healthy record.
    assert item.status == "ok"
    assert item.records_committed == 1
    assert item.batch_id is not None
    assert summary.records_committed == 1
    assert captured == []  # the SSRF guard blocked before any transport use

    path = spool_root / "pending" / _DAY / f"{item.batch_id}.jsonl"
    record = read_trusted_segment(path, installation_id=INSTALLATION_ID).frames[0].record
    assert record.record_type == "event"
    assert record.data.category == "availability"
    assert record.data.status == "degraded"
    assert dict(record.data.attributes) == {"probe_failed": 1}
    assert "http_status" not in record.data.attributes
