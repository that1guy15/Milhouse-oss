"""Shared offline harness for the W05 runtime pipeline/registry suites (not collected by pytest).

Builds an initialized control database, barrier, and spool root on ``tmp_path``, a layered redactor
with a known secret, and a fake first-party collector whose drafts carry a redactable free-text
message. The fake collector satisfies the runtime ``Collector`` protocol and returns drafts only —
never touching the spool — so the pipeline owns every durable side effect.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any

from _record_factories import INSTALLATION_ID, NOW

from milhouse.config._models import (
    RetentionConfig,
    SiteCanaryCollector,
    TargetConfig,
)
from milhouse.domain.records import (
    CollectorDescriptorV1,
    EventDataV1,
    RecordDraftV1,
    SourceDescriptorV1,
)
from milhouse.privacy.pseudonym import Pseudonymizer
from milhouse.privacy.redact import LayeredRedactor
from milhouse.runtime import CollectorContext, CollectorRegistry, CollectorResult, RuntimePipeline
from milhouse.state import GlobalCommitBarrier, initialize_control_state, open_control_database
from milhouse.storage import CLICKHOUSE_EXPORTER_ID, ClickHouseExporter

# A distinctive known secret; the redactor replaces it with the fixed secret marker, so the spooled
# bytes can be asserted redacted.
KNOWN_SECRET = "supersecretvalue123"
SECRET_MARKER = "[mh:s]"
CONFIG_GENERATION = "a" * 64
GROUP = "milhouse.collectors"


def build_control(tmp_path: Path) -> tuple[Any, GlobalCommitBarrier, Path]:
    """Create an initialized control database, commit barrier, and spool root under tmp_path."""

    control = tmp_path / "control"
    control.mkdir(mode=0o700)
    os.chmod(control, 0o700)
    database = open_control_database(control / "milhouse.sqlite3")
    barrier = GlobalCommitBarrier(control / "commit.lock")
    initialize_control_state(database, barrier=barrier, applied_at=NOW)
    spool_root = tmp_path / "spool"
    spool_root.mkdir(mode=0o700)
    os.chmod(spool_root, 0o700)
    return database, barrier, spool_root


def make_redactor() -> LayeredRedactor:
    """A layered redactor that pseudonymizes ``KNOWN_SECRET`` to the fixed secret marker."""

    return LayeredRedactor(Pseudonymizer(b"k" * 32), known_secrets=(KNOWN_SECRET,))


def target_config(target_id: str = "t1") -> TargetConfig:
    return TargetConfig(id=target_id, name="Example Target", kind="web_service", environment="test")


def canary_config(collector_id: str = "canary1", *, target: str = "t1") -> SiteCanaryCollector:
    return SiteCanaryCollector(
        id=collector_id,
        target=target,
        type="site_canary",
        url="https://example.test/health",
        expected_statuses=[200],
    )


def retention_config() -> RetentionConfig:
    return RetentionConfig(
        events_days=30,
        metrics_days=30,
        runs_days=30,
        alerts_days=30,
        feedback_days=30,
        agent_summaries_days=30,
        trace_events_days=30,
        reports_days=30,
        logs_days=30,
    )


def _event_draft(context: CollectorContext, *, message: str, sequence: int) -> RecordDraftV1:
    """Build one target-scoped event draft carrying a redactable free-text ``message``."""

    source = SourceDescriptorV1.model_validate(
        {
            "id": "canary-source",
            "type": "source.event",
            "producer": "collector",
            "observation_namespace_id": "mh_ns1_00000000000040008000000000000000",
            "source_generation_digest": "0" * 64,
            "observation": {"kind": "source.revision", "parts": {"revision": 1}},
        }
    )
    return RecordDraftV1.model_validate(
        {
            "record_type": "event",
            "name": "site.canary",
            "occurred_at": context.now,
            "observed_at": context.now + timedelta(seconds=1),
            "ingested_at": context.now + timedelta(seconds=2),
            "expires_at": context.now + timedelta(days=30),
            # Distinct per collector so records never collide across a multi-collector run.
            "source_event_id": f"{context.collector.id}-ev-{sequence}",
            "operation_id": f"{context.collector.id}-op",
            "collector_run_id": f"{context.collector.id}-run",
            "scope": "target",
            "source": source,
            "collector": context.collector,
            "target": context.target,
            "severity": "info",
            "trust_level": "authenticated",
            "privacy_class": "internal",
            # An intentionally stale version; the pipeline restamps it with the applied policy.
            "redaction_version": "r1-e1",
            "data": EventDataV1(category="availability", status="healthy", message=message),
        }
    )


@dataclass
class FakeCollector:
    """A fake first-party collector: returns event drafts, never writes to the spool."""

    descriptor: CollectorDescriptorV1
    messages: tuple[str, ...]
    status: str = "ok"
    raises: bool = False

    def collect(self, context: CollectorContext) -> CollectorResult:
        if self.raises:
            raise RuntimeError("collector boom with a secret " + KNOWN_SECRET)
        drafts = tuple(
            _event_draft(context, message=message, sequence=index)
            for index, message in enumerate(self.messages, start=1)
        )
        return CollectorResult(
            status=self.status,  # type: ignore[arg-type]
            drafts=drafts,
            diagnostics={"samples": len(drafts)},
        )


def fake_factory(messages: tuple[str, ...], *, status: str = "ok", raises: bool = False) -> Any:
    """A first-party factory that binds ``config.id`` into the collector's descriptor."""

    def factory(config: Any) -> FakeCollector:
        descriptor = CollectorDescriptorV1(
            id=config.id, type="site.canary", implementation_version="1.0.0"
        )
        return FakeCollector(descriptor=descriptor, messages=messages, status=status, raises=raises)

    return factory


def registry_with(type_name: str, factory: Any) -> CollectorRegistry:
    registry = CollectorRegistry()
    registry.register(type_name, factory)
    return registry


def make_pipeline(
    *,
    mode: str,
    registry: CollectorRegistry,
    control: Any,
    barrier: GlobalCommitBarrier,
    spool_root: Path,
    clock: Any,
    exporters: Any = None,
) -> RuntimePipeline:
    return RuntimePipeline(
        mode=mode,  # type: ignore[arg-type]
        config_generation=CONFIG_GENERATION,
        registry=registry,
        redactor=make_redactor(),
        control=control,
        barrier=barrier,
        spool_root=spool_root,
        installation_id=INSTALLATION_ID,
        clock=clock,
        retention=retention_config(),
        exporters={} if exporters is None else exporters,
    )


def clickhouse_exporters(client: Any, database: str = "milhouse") -> dict[str, ClickHouseExporter]:
    return {CLICKHOUSE_EXPORTER_ID: ClickHouseExporter(client, database)}
