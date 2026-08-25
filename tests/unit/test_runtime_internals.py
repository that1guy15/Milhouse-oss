"""White-box coverage of the runtime fail-closed helpers (W05).

Exercises the defensive branches of the registry's plugin loader/binder and the pipeline's segment,
retention, target, and export helpers directly — the paths that guard against hostile plugin
metadata or a malformed collector and that behavioral tests reach only rarely. Every rejection is a
fixed code and no failure renders a distribution name, object reference, or path.
"""

from __future__ import annotations

import importlib.metadata
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from _record_factories import NOW, event_record
from _runtime_harness import (
    build_control,
    canary_config,
    fake_factory,
    make_pipeline,
    registry_with,
    target_config,
)

from milhouse.config._models import PluginAllowlistEntry
from milhouse.core.clock import FixedClock
from milhouse.domain.records import CollectorDescriptorV1, EventDataV1, RecordDraftV1
from milhouse.runtime import CollectorRegistry, CollectorResult
from milhouse.runtime import registry as registry_module
from milhouse.runtime.errors import PipelineError, RegistryError
from milhouse.runtime.pipeline import (
    _availability_sample,
    _redact_draft,
    _target_descriptor,
)

_CLOCK = FixedClock(instant=NOW)
_GROUP = "milhouse.collectors"


class _StubCollector:
    descriptor = CollectorDescriptorV1(id="p", type="site.canary", implementation_version="1.0.0")

    def collect(self, context: object) -> CollectorResult:
        return CollectorResult(status="ok")


class _FakeEntryPoint:
    def __init__(self, group: str, value: str, *, result: object = None, raises: bool = False):
        self.group = group
        self.value = value
        self._result = result
        self._raises = raises

    def load(self) -> object:
        if self._raises:
            raise RuntimeError("load boom")
        return self._result


class _FakeDistribution:
    def __init__(
        self,
        version: str,
        entry_points: list[_FakeEntryPoint],
        *,
        version_raises: bool = False,
        entry_points_raises: bool = False,
    ) -> None:
        self._version = version
        self._entry_points = entry_points
        self._version_raises = version_raises
        self._entry_points_raises = entry_points_raises

    @property
    def version(self) -> str:
        if self._version_raises:
            raise RuntimeError("version boom")
        return self._version

    @property
    def entry_points(self) -> list[_FakeEntryPoint]:
        if self._entry_points_raises:
            raise RuntimeError("entry points boom")
        return self._entry_points


_ENTRY = PluginAllowlistEntry(
    distribution="fakeplugin", version="1.0.0", group=_GROUP, entry_point="mod:make"
)


def _patch_distributions(monkeypatch: pytest.MonkeyPatch, result: Any) -> None:
    def _distributions(*, name: str) -> Any:
        if callable(result):
            return result()
        return result

    monkeypatch.setattr(importlib.metadata, "distributions", _distributions)


def _good_ep(result: object = None) -> _FakeEntryPoint:
    return _FakeEntryPoint(_GROUP, "mod:make", result=result or _StubCollector())


# --- registry surface --------------------------------------------------------------------------


def test_registry_repr_and_type_name_and_factory_guards() -> None:
    registry = CollectorRegistry()
    assert "first_party_types=0" in repr(registry)
    with pytest.raises(RegistryError) as empty:
        registry.register("", fake_factory(("ok",)))
    assert empty.value.code == "MH_RUNTIME_REGISTRY_TYPE"
    with pytest.raises(RegistryError) as not_callable:
        registry.register("site_canary", "not-callable")  # type: ignore[arg-type]
    assert not_callable.value.code == "MH_RUNTIME_REGISTRY_TYPE"


def test_bind_plugin_collector_rejects_wrong_argument_types() -> None:
    registry = CollectorRegistry()
    from milhouse.config._models import PluginsConfig

    with pytest.raises(RegistryError) as bad_entry:
        registry.bind_plugin_collector("nope", plugins=PluginsConfig())  # type: ignore[arg-type]
    assert bad_entry.value.code == "MH_RUNTIME_PLUGIN_INVALID"
    with pytest.raises(RegistryError) as bad_plugins:
        registry.bind_plugin_collector(_ENTRY, plugins="nope")  # type: ignore[arg-type]
    assert bad_plugins.value.code == "MH_RUNTIME_PLUGIN_INVALID"


# --- _load_plugin_object defensive branches ----------------------------------------------------


def test_load_plugin_object_missing_or_ambiguous_distribution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_distributions(monkeypatch, [])
    with pytest.raises(RegistryError) as missing:
        registry_module._load_plugin_object(_ENTRY)
    assert missing.value.code == "MH_RUNTIME_PLUGIN_REJECTED"

    _patch_distributions(
        monkeypatch, [_FakeDistribution("1.0.0", []), _FakeDistribution("1.0.0", [])]
    )
    with pytest.raises(RegistryError) as ambiguous:
        registry_module._load_plugin_object(_ENTRY)
    assert ambiguous.value.code == "MH_RUNTIME_PLUGIN_REJECTED"


def test_load_plugin_object_distribution_read_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    def _raise() -> Any:
        raise RuntimeError("discovery boom")

    _patch_distributions(monkeypatch, _raise)
    with pytest.raises(RegistryError) as caught:
        registry_module._load_plugin_object(_ENTRY)
    assert caught.value.code == "MH_RUNTIME_PLUGIN_REJECTED"


def test_load_plugin_object_version_mismatch_or_unreadable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_distributions(monkeypatch, [_FakeDistribution("2.0.0", [_good_ep()])])
    with pytest.raises(RegistryError) as mismatch:
        registry_module._load_plugin_object(_ENTRY)
    assert mismatch.value.code == "MH_RUNTIME_PLUGIN_REJECTED"

    _patch_distributions(
        monkeypatch, [_FakeDistribution("1.0.0", [_good_ep()], version_raises=True)]
    )
    with pytest.raises(RegistryError) as unreadable:
        registry_module._load_plugin_object(_ENTRY)
    assert unreadable.value.code == "MH_RUNTIME_PLUGIN_REJECTED"


def test_load_plugin_object_entry_points_unreadable_or_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_distributions(monkeypatch, [_FakeDistribution("1.0.0", [], entry_points_raises=True)])
    with pytest.raises(RegistryError) as unreadable:
        registry_module._load_plugin_object(_ENTRY)
    assert unreadable.value.code == "MH_RUNTIME_PLUGIN_REJECTED"

    # Zero matching object references (drifted away) fails closed.
    _patch_distributions(
        monkeypatch, [_FakeDistribution("1.0.0", [_FakeEntryPoint(_GROUP, "mod:other")])]
    )
    with pytest.raises(RegistryError) as absent:
        registry_module._load_plugin_object(_ENTRY)
    assert absent.value.code == "MH_RUNTIME_PLUGIN_REJECTED"

    # More than one matching object reference is ambiguous — fail closed.
    _patch_distributions(monkeypatch, [_FakeDistribution("1.0.0", [_good_ep(), _good_ep()])])
    with pytest.raises(RegistryError) as ambiguous:
        registry_module._load_plugin_object(_ENTRY)
    assert ambiguous.value.code == "MH_RUNTIME_PLUGIN_REJECTED"


def test_load_plugin_object_load_raises_and_success(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_distributions(
        monkeypatch,
        [_FakeDistribution("1.0.0", [_FakeEntryPoint(_GROUP, "mod:make", raises=True)])],
    )
    with pytest.raises(RegistryError) as caught:
        registry_module._load_plugin_object(_ENTRY)
    assert caught.value.code == "MH_RUNTIME_PLUGIN_LOAD"

    stub = _StubCollector()
    _patch_distributions(monkeypatch, [_FakeDistribution("1.0.0", [_good_ep(stub)])])
    assert registry_module._load_plugin_object(_ENTRY) is stub


# --- _bind_plugin_collector branches -----------------------------------------------------------


def test_bind_plugin_collector_accepts_instance_factory_and_rejects_the_rest() -> None:
    stub = _StubCollector()
    assert registry_module._bind_plugin_collector(stub) is stub

    # A class satisfies the runtime_checkable Collector protocol un-instantiated (class-level
    # descriptor + collect), so it must be CONSTRUCTED, never returned as the type object itself.
    constructed_from_class = registry_module._bind_plugin_collector(_StubCollector)
    assert isinstance(constructed_from_class, _StubCollector)
    assert constructed_from_class is not _StubCollector

    def _factory() -> _StubCollector:
        return stub

    assert registry_module._bind_plugin_collector(_factory) is stub

    def _raising_factory() -> object:
        raise RuntimeError("construct boom")

    with pytest.raises(RegistryError) as construct:
        registry_module._bind_plugin_collector(_raising_factory)
    assert construct.value.code == "MH_RUNTIME_PLUGIN_LOAD"

    with pytest.raises(RegistryError) as invalid_result:
        registry_module._bind_plugin_collector(lambda: object())
    assert invalid_result.value.code == "MH_RUNTIME_PLUGIN_INVALID"

    with pytest.raises(RegistryError) as not_a_collector:
        registry_module._bind_plugin_collector(42)
    assert not_a_collector.value.code == "MH_RUNTIME_PLUGIN_INVALID"


# --- pipeline helpers --------------------------------------------------------------------------


def _pipeline(tmp_path: Path) -> Any:
    database, barrier, spool_root = build_control(tmp_path)
    registry = registry_with("site_canary", fake_factory(("ok",)))
    pipeline = make_pipeline(
        mode="spool_only",
        registry=registry,
        control=database,
        barrier=barrier,
        spool_root=spool_root,
        clock=_CLOCK,
    )
    return pipeline, database


def test_retention_days_fails_closed_for_an_ungoverned_record_type(tmp_path: Path) -> None:
    pipeline, database = _pipeline(tmp_path)
    try:
        assert pipeline._retention_days("event") == 30
        with pytest.raises(PipelineError) as caught:
            pipeline._retention_days("incident")
        assert caught.value.code == "MH_RUNTIME_PIPELINE_RETENTION"
    finally:
        database.close()


def test_target_descriptor_absent_and_undeclared() -> None:
    # An installation-scoped collector (no target) yields no descriptor.
    assert _target_descriptor(SimpleNamespace(target=None), {}) is None
    # A target that is not declared fails closed.
    with pytest.raises(PipelineError) as caught:
        _target_descriptor(SimpleNamespace(target="missing"), {})
    assert caught.value.code == "MH_RUNTIME_PIPELINE_TARGET"


def _availability_record(
    status: str, *, category: str = "availability", record_type: str = "event"
):
    # ``_availability_sample`` reads only these attributes, so a stand-in exercises every branch.
    return SimpleNamespace(
        record_type=record_type,
        data=EventDataV1(category=category, status=status),
        record_id=f"rid-{status}-{category}",
    )


def test_availability_sample_maps_health_and_ignores_everything_else() -> None:
    healthy = _availability_record("healthy")
    degraded = _availability_record("degraded")
    assert _availability_sample((healthy,)) == ("success", healthy.record_id)
    assert _availability_sample((degraded,)) == ("failure", degraded.record_id)
    # An availability event with an unexpected status maps to no sample (only healthy/degraded map).
    assert _availability_sample((_availability_record("unknown"),)) is None
    # A non-availability event and a non-event record both contribute no sample.
    assert _availability_sample((_availability_record("healthy", category="latency"),)) is None
    assert _availability_sample((_availability_record("healthy", record_type="metric"),)) is None
    # No records at all yields no sample.
    assert _availability_sample(()) is None


def test_redact_draft_skips_absent_free_text_but_still_stamps_the_policy() -> None:
    from _runtime_harness import make_redactor

    redactor = make_redactor()
    # A draft whose free-text message is absent leaves the loop with nothing to redact; the applied
    # redaction policy version is still stamped.
    values = event_record().model_dump(mode="python", exclude_none=True)
    for envelope_only in ("record_id", "dedupe_key", "content_hash"):
        values.pop(envelope_only, None)
    values["data"].pop("message", None)
    draft = RecordDraftV1.model_validate(values)
    redacted = _redact_draft(draft, redactor=redactor)
    assert redacted.data.message is None
    assert redacted.redaction_version == redactor.version


def test_the_pipeline_commits_nothing_when_a_collector_returns_no_drafts(tmp_path: Path) -> None:
    database, barrier, spool_root = build_control(tmp_path)
    try:
        registry = registry_with("site_canary", fake_factory(()))
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
        assert item.status == "ok"
        assert item.drafts_produced == 0
        assert item.records_committed == 0
        assert item.batch_id is None
    finally:
        database.close()


def test_export_tail_failure_surfaces_a_code_without_losing_the_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from _runtime_harness import clickhouse_exporters
    from _storage_fakes import FakeClickHouseClient

    database, barrier, spool_root = build_control(tmp_path)
    try:
        registry = registry_with("site_canary", fake_factory(("sample",)))
        pipeline = make_pipeline(
            mode="full",
            registry=registry,
            control=database,
            barrier=barrier,
            spool_root=spool_root,
            clock=_CLOCK,
            exporters=clickhouse_exporters(FakeClickHouseClient()),
        )

        import milhouse.runtime.pipeline as pipeline_module

        def _boom(*args: object, **kwargs: object) -> Any:
            raise RuntimeError("replay integrity boom")

        monkeypatch.setattr(pipeline_module, "replay_segments", _boom)
        summary = pipeline.run([canary_config("canary1")], [target_config("t1")])
        # The commit is durable; only the export tail failed and its code is surfaced.
        assert summary.records_committed == 1
        assert summary.records_delivered == 0
        assert summary.export_error_code == "MH_INTERNAL_UNEXPECTED"
    finally:
        database.close()
