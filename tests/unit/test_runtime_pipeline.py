"""The mode-aware runtime pipeline: ordering, modes, isolation, and privacy-safe summaries (W05).

Exercises the G05 ordering ``collect -> validate -> redact -> spool [-> export]`` against a real
control database, commit barrier, and durable spool on ``tmp_path`` and (in full mode) the in-memory
``FakeClickHouseClient``. It proves redaction precedes the durable write (the spooled bytes are
redacted), that ``spool_only`` stops after commit, that ``full`` drives the existing export tail,
that one collector failing never aborts the others, and that the summary and every error carry no
secret, path, or raw payload.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from _record_factories import INSTALLATION_ID, NOW
from _runtime_harness import (
    KNOWN_SECRET,
    SECRET_MARKER,
    build_control,
    canary_config,
    clickhouse_exporters,
    fake_factory,
    make_pipeline,
    registry_with,
    target_config,
)
from _storage_fakes import FakeClickHouseClient

from milhouse.core.clock import FixedClock
from milhouse.domain.records import CollectorDescriptorV1
from milhouse.runtime.errors import PipelineError
from milhouse.runtime.registry import CollectorRegistry
from milhouse.spooling import read_trusted_segment

_CLOCK = FixedClock(instant=NOW)
# Space-delimited so the registered known-secret rule fires (a ``token=`` prefix would instead trip
# the generic credential-assignment rule); either way the raw value never reaches the spool.
_MESSAGE = f"canary sample {KNOWN_SECRET} observed"


def _segment_path(spool_root: Path, day: str, batch_id: str) -> Path:
    return spool_root / "pending" / day / f"{batch_id}.jsonl"


def _exporter_rows(database: object) -> int:
    return int(
        database.connection.execute(  # type: ignore[attr-defined]
            "SELECT count(*) FROM _segment_exporters"
        ).fetchone()[0]
    )


# --- redaction strictly precedes the durable write ---------------------------------------------


def test_redaction_precedes_spool_so_the_committed_bytes_are_redacted(tmp_path: Path) -> None:
    database, barrier, spool_root = build_control(tmp_path)
    try:
        registry = registry_with("site_canary", fake_factory((_MESSAGE,)))
        pipeline = make_pipeline(
            mode="spool_only",
            registry=registry,
            control=database,
            barrier=barrier,
            spool_root=spool_root,
            clock=_CLOCK,
        )
        summary = pipeline.run([canary_config("canary1")], [target_config("t1")])
        assert summary.records_committed == 1
        collector = summary.collectors[0]
        assert collector.batch_id is not None

        path = _segment_path(spool_root, "2026-07-21", collector.batch_id)
        raw = path.read_bytes()
        # The raw secret never reached the durable segment; the redaction marker did.
        assert KNOWN_SECRET.encode("utf-8") not in raw
        assert SECRET_MARKER.encode("utf-8") in raw

        parsed = read_trusted_segment(path, installation_id=INSTALLATION_ID)
        record = parsed.frames[0].record
        assert record.data.message is not None and KNOWN_SECRET not in record.data.message
        # The pipeline (not the collector) is the redaction authority: it stamps the applied policy.
        assert record.redaction_version == "r2-e1"
    finally:
        database.close()


# --- mode: spool_only --------------------------------------------------------------------------


def test_spool_only_mode_stops_after_commit_and_attempts_no_export(tmp_path: Path) -> None:
    database, barrier, spool_root = build_control(tmp_path)
    try:
        registry = registry_with("site_canary", fake_factory((_MESSAGE, "second")))
        pipeline = make_pipeline(
            mode="spool_only",
            registry=registry,
            control=database,
            barrier=barrier,
            spool_root=spool_root,
            clock=_CLOCK,
        )
        summary = pipeline.run([canary_config("canary1")], [target_config("t1")])
        assert summary.mode == "spool_only"
        assert summary.records_committed == 2
        assert summary.records_delivered == 0
        assert summary.records_failed == 0
        assert summary.export_error_code is None
        # spool_only records no delivery obligation, so no exporter ledger rows exist to drive.
        assert _exporter_rows(database) == 0
    finally:
        database.close()


# --- mode: full --------------------------------------------------------------------------------


def test_full_mode_drives_the_export_tail_and_the_fake_client_receives_rows(
    tmp_path: Path,
) -> None:
    database, barrier, spool_root = build_control(tmp_path)
    try:
        client = FakeClickHouseClient()
        registry = registry_with("site_canary", fake_factory((_MESSAGE,)))
        pipeline = make_pipeline(
            mode="full",
            registry=registry,
            control=database,
            barrier=barrier,
            spool_root=spool_root,
            clock=_CLOCK,
            exporters=clickhouse_exporters(client),
        )
        summary = pipeline.run([canary_config("canary1")], [target_config("t1")])
        assert summary.records_committed == 1
        assert summary.records_delivered == 1
        assert summary.records_failed == 0
        assert summary.export_error_code is None
        # The reused delivery tail forwarded the event to the fake ClickHouse client exactly once.
        assert [table for _db, table, *_ in client.inserts] == ["records"]
    finally:
        database.close()


def test_full_mode_export_failure_is_non_fatal_collection_and_commit_still_succeed(
    tmp_path: Path,
) -> None:
    class _RaisingClient(FakeClickHouseClient):
        def insert(self, *args: object, **kwargs: object) -> None:
            raise RuntimeError("clickhouse unavailable")

    database, barrier, spool_root = build_control(tmp_path)
    try:
        registry = registry_with("site_canary", fake_factory((_MESSAGE,)))
        pipeline = make_pipeline(
            mode="full",
            registry=registry,
            control=database,
            barrier=barrier,
            spool_root=spool_root,
            clock=_CLOCK,
            exporters=clickhouse_exporters(_RaisingClient()),
        )
        summary = pipeline.run([canary_config("canary1")], [target_config("t1")])
        # The durable commit still succeeded; only delivery failed, surfaced (loud, non-crashing).
        assert summary.records_committed == 1
        assert summary.records_delivered == 0
        assert summary.records_failed == 1
        assert summary.collectors[0].batch_id is not None
    finally:
        database.close()


def test_full_mode_ignores_a_non_clickhouse_exporter_attempt_in_the_summary(
    tmp_path: Path,
) -> None:
    class _OtherExporter:
        @property
        def exporter_id(self) -> str:
            return "other"

        def deliver(self, record: object, frames: object) -> None:
            return None

    client = FakeClickHouseClient()
    database, barrier, spool_root = build_control(tmp_path)
    try:
        registry = registry_with("site_canary", fake_factory((_MESSAGE,)))
        exporters = clickhouse_exporters(client)
        exporters["other"] = _OtherExporter()  # type: ignore[assignment]
        pipeline = make_pipeline(
            mode="full",
            registry=registry,
            control=database,
            barrier=barrier,
            spool_root=spool_root,
            clock=_CLOCK,
            exporters=exporters,
        )
        summary = pipeline.run([canary_config("canary1")], [target_config("t1")])
        # The clickhouse delivery counts; the second exporter's attempt is not folded into the
        # per-collector delivered/failed counts (only the clickhouse tail is summarized here).
        assert summary.records_delivered == 1
        assert summary.records_failed == 0
    finally:
        database.close()


def test_full_mode_drain_over_a_prior_delivered_segment_is_ignored_for_this_run(
    tmp_path: Path,
) -> None:
    # The drain re-reads every committed segment. A segment delivered on an earlier run is
    # already_delivered and belongs to no collector in this run, so it is skipped when mapping
    # per-collector delivery counts.
    database, barrier, spool_root = build_control(tmp_path)
    try:
        registry = registry_with("site_canary", fake_factory((_MESSAGE,)))
        first = make_pipeline(
            mode="full",
            registry=registry,
            control=database,
            barrier=barrier,
            spool_root=spool_root,
            clock=_CLOCK,
            exporters=clickhouse_exporters(FakeClickHouseClient()),
        )
        first.run([canary_config("prior")], [target_config("t1")])

        second = make_pipeline(
            mode="full",
            registry=registry,
            control=database,
            barrier=barrier,
            spool_root=spool_root,
            clock=_CLOCK,
            exporters=clickhouse_exporters(FakeClickHouseClient()),
        )
        summary = second.run([canary_config("current")], [target_config("t1")])
        # Only the current run's collector is summarized; the prior already-delivered segment does
        # not inflate this run's per-collector counts.
        assert [item.collector_id for item in summary.collectors] == ["current"]
        assert summary.records_delivered == 1
    finally:
        database.close()


def test_full_mode_drains_a_prior_outage_backlog_even_when_this_run_commits_nothing(
    tmp_path: Path,
) -> None:
    # The delivery tail drains the whole ledger (delivery_status=None), so a segment a prior
    # warehouse outage left `failed` is recovered on the next reachable run -- even a run whose
    # collectors are idle and commit nothing this pass. Gating export on "committed something this
    # run" would strand that backlog whenever the configured collectors are quiescent (e.g. a
    # state-change-only canary). This is the regression guard for that gap.
    class _RaisingClient(FakeClickHouseClient):
        def insert(self, *args: object, **kwargs: object) -> None:
            raise RuntimeError("clickhouse unavailable")

    database, barrier, spool_root = build_control(tmp_path)
    try:
        # Run 1: warehouse down; the committed segment fails to deliver -- a durable backlog.
        outage = make_pipeline(
            mode="full",
            registry=registry_with("site_canary", fake_factory((_MESSAGE,))),
            control=database,
            barrier=barrier,
            spool_root=spool_root,
            clock=_CLOCK,
            exporters=clickhouse_exporters(_RaisingClient()),
        )
        first = outage.run([canary_config("backlog")], [target_config("t1")])
        assert first.records_committed == 1
        assert first.records_failed == 1

        # Run 2: the warehouse is back, but the collector is idle and commits nothing this run.
        recovered_client = FakeClickHouseClient()
        idle = make_pipeline(
            mode="full",
            registry=registry_with("site_canary", fake_factory(())),
            control=database,
            barrier=barrier,
            spool_root=spool_root,
            clock=_CLOCK,
            exporters=clickhouse_exporters(recovered_client),
        )
        summary = idle.run([canary_config("idle")], [target_config("t1")])
        # This run's idle collector committed and delivered nothing of its own...
        assert summary.records_committed == 0
        assert summary.records_delivered == 0
        assert summary.export_error_code is None
        # ...but the export tail still ran and drained the prior-outage backlog to the recovered
        # warehouse: the previously-failed segment is now delivered exactly once.
        assert [table for _db, table, *_ in recovered_client.inserts] == ["records"]
    finally:
        database.close()


# --- per-collector isolation -------------------------------------------------------------------


def test_one_collector_raising_never_aborts_the_others(tmp_path: Path) -> None:
    def factory(config: object) -> object:
        from _runtime_harness import FakeCollector

        descriptor = CollectorDescriptorV1(
            id=config.id,  # type: ignore[attr-defined]
            type="site.canary",
            implementation_version="1.0.0",
        )
        if descriptor.id == "boom":
            return FakeCollector(descriptor=descriptor, messages=(), raises=True)
        return FakeCollector(descriptor=descriptor, messages=(_MESSAGE,))

    database, barrier, spool_root = build_control(tmp_path)
    try:
        registry = CollectorRegistry()
        registry.register("site_canary", factory)
        pipeline = make_pipeline(
            mode="spool_only",
            registry=registry,
            control=database,
            barrier=barrier,
            spool_root=spool_root,
            clock=_CLOCK,
        )
        summary = pipeline.run(
            [canary_config("boom"), canary_config("good1")],
            [target_config("t1")],
        )
        by_id = {item.collector_id: item for item in summary.collectors}
        # The failing collector is isolated with a fixed code and no commit ...
        assert by_id["boom"].status == "error"
        assert by_id["boom"].error_code == "MH_INTERNAL_UNEXPECTED"
        assert by_id["boom"].records_committed == 0
        assert by_id["boom"].batch_id is None
        # ... while the healthy collector still committed its records.
        assert by_id["good1"].status == "ok"
        assert by_id["good1"].records_committed == 1
        assert summary.records_committed == 1
    finally:
        database.close()


def test_the_run_summary_and_isolated_errors_carry_no_secret(tmp_path: Path) -> None:
    # The raising collector embeds the secret in its exception message; it must not leak anywhere.
    database, barrier, spool_root = build_control(tmp_path)
    try:
        registry = registry_with("site_canary", fake_factory((), raises=True))
        pipeline = make_pipeline(
            mode="spool_only",
            registry=registry,
            control=database,
            barrier=barrier,
            spool_root=spool_root,
            clock=_CLOCK,
        )
        summary = pipeline.run([canary_config("canary1")], [target_config("t1")])
        item = summary.collectors[0]
        assert item.status == "error"
        assert item.error_code == "MH_INTERNAL_UNEXPECTED"
        # No summary field renders the secret the collector tried to raise.
        assert KNOWN_SECRET not in repr(summary)
    finally:
        database.close()


# --- construction guards -----------------------------------------------------------------------


def test_full_mode_requires_an_exporter_and_spool_only_forbids_one(tmp_path: Path) -> None:
    database, barrier, spool_root = build_control(tmp_path)
    try:
        registry = registry_with("site_canary", fake_factory((_MESSAGE,)))
        with pytest.raises(PipelineError) as full_without_exporter:
            make_pipeline(
                mode="full",
                registry=registry,
                control=database,
                barrier=barrier,
                spool_root=spool_root,
                clock=_CLOCK,
            )
        assert full_without_exporter.value.code == "MH_RUNTIME_PIPELINE_EXPORTERS"

        with pytest.raises(PipelineError) as spool_only_with_exporter:
            make_pipeline(
                mode="spool_only",
                registry=registry,
                control=database,
                barrier=barrier,
                spool_root=spool_root,
                clock=_CLOCK,
                exporters=clickhouse_exporters(FakeClickHouseClient()),
            )
        assert spool_only_with_exporter.value.code == "MH_RUNTIME_PIPELINE_EXPORTERS"
    finally:
        database.close()
