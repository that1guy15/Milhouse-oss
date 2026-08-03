"""Spool-only ``demo`` for the Milhouse CLI: a credential-free end-to-end data-flow.

Builds one synthetic canary event, redaction-classifies it as a canonical record, writes it to the
durable spool through the W03 commit barrier, then reads it back through the trusted reader and
verifies it round-trips. No network, no providers, no ClickHouse — the whole flow is local and
spool-only. This is a preparatory product vertical on the accepted W02 (records/identity) and W03
(durable spool) foundations; it does not claim the W05 runtime or W06 gates.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta

from milhouse.cli import bootstrap
from milhouse.config import RuntimePaths
from milhouse.domain.records import (
    CollectorDescriptorV1,
    EventDataV1,
    RecordDraftV1,
    RecordEnvelopeV1,
    SourceDescriptorV1,
    TargetDescriptorV1,
    finalize_record,
)
from milhouse.spooling import (
    DurableSpool,
    SegmentHeaderV1,
    SpoolFrameV1,
    read_trusted_segment,
    spool_content_sha256,
    spool_frame_line,
)
from milhouse.state import GlobalCommitBarrier, open_control_database

#: A fixed synthetic configuration-generation digest for the demo segment (64 lowercase hex).
_DEMO_CONFIG_GENERATION = "d" * 64
_DEMO_NAMESPACE = "mh_ns1_00000000000040008000000000000000"
_DEMO_RETENTION_DAYS = 30


@dataclass(frozen=True, slots=True)
class DemoReport:
    """The outcome of one spool-only demo pass."""

    batch_id: str
    day: str
    records_spooled: int
    read_back_ok: bool


def _demo_record(installation_id: str, *, now: datetime) -> RecordEnvelopeV1:
    """Finalize one synthetic 'site canary healthy' event into a canonical record."""

    source = SourceDescriptorV1.model_validate(
        {
            "id": "demo-canary-source",
            "type": "source.event",
            "producer": "collector",
            "observation_namespace_id": _DEMO_NAMESPACE,
            "source_generation_digest": "0" * 64,
            "observation": {"kind": "source.revision", "parts": {"revision": 1}},
        }
    )
    values: dict[str, object] = {
        "record_type": "event",
        "name": "source.event",
        "occurred_at": now,
        "observed_at": now + timedelta(seconds=1),
        "ingested_at": now + timedelta(seconds=2),
        "expires_at": now + timedelta(days=_DEMO_RETENTION_DAYS),
        "source_event_id": "demo-canary-1",
        "operation_id": "demo-operation-1",
        "collector_run_id": "demo-run-1",
        "scope": "target",
        "source": source,
        "collector": CollectorDescriptorV1(
            id="demo-canary", type="site.canary", implementation_version="1.0.0"
        ),
        "target": TargetDescriptorV1(
            id="demo-target", name="Demo Target", kind="web.service", environment="demo"
        ),
        "severity": "info",
        "trust_level": "authenticated",
        "privacy_class": "internal",
        "redaction_version": "r1-e1",
        "data": EventDataV1(category="availability", status="healthy", message="ok"),
    }
    return finalize_record(RecordDraftV1.model_validate(values), installation_id=installation_id)


def _demo_header(batch_id: str, frames: list[SpoolFrameV1]) -> SegmentHeaderV1:
    lines = [spool_frame_line(frame) for frame in frames]
    return SegmentHeaderV1(
        batch_id=batch_id,
        config_generation=_DEMO_CONFIG_GENERATION,
        scope="target",
        target_id="demo-target",
        privacy_class="internal",
        retention_days=_DEMO_RETENTION_DAYS,
        required_exporters=("clickhouse",),
        record_count=len(frames),
        content_sha256=spool_content_sha256(lines),
    )


def run_demo(paths: RuntimePaths, *, now: datetime) -> DemoReport:
    """Initialize if needed, spool one synthetic record through the barrier, and read it back.

    Returns a :class:`DemoReport`; raises :class:`bootstrap.BootstrapError` if the installation
    identity cannot be established. Each run spools a fresh uniquely-named segment so it is always
    re-runnable, and never mutates or deletes prior spool data.
    """

    bootstrap.initialize(paths, now=now)
    installation_id = bootstrap.read_installation_id(paths)
    if installation_id is None:  # pragma: no cover - initialize established it just above
        raise bootstrap.BootstrapError(
            "MH_DEMO_IDENTITY", "the installation identity is not available"
        )

    batch_id = "demo-" + uuid.uuid4().hex[:16]
    record = _demo_record(installation_id, now=now)
    frames = [SpoolFrameV1(batch_id=batch_id, sequence=1, record=record)]
    header = _demo_header(batch_id, frames)

    control = paths.state_root / bootstrap.CONTROL_DIRNAME
    database = open_control_database(bootstrap.database_path(paths))
    try:
        barrier = GlobalCommitBarrier(control / bootstrap.BARRIER_NAME)
        store = DurableSpool(
            database=database,
            barrier=barrier,
            spool_root=paths.spool,
            installation_id=installation_id,
        )
        committed = store.commit_segment(header, frames, committed_at=now)
        segment_path = paths.spool / "pending" / committed.day / f"{batch_id}.jsonl"
        parsed = read_trusted_segment(segment_path, installation_id=installation_id)
        read_back_ok = (
            len(parsed.frames) == committed.record_count == len(frames)
            and parsed.frames[0].record.record_id == record.record_id
        )
        return DemoReport(
            batch_id=batch_id,
            day=committed.day,
            records_spooled=committed.record_count,
            read_back_ok=read_back_ok,
        )
    finally:
        database.close()
