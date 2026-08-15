"""Tests for the W06 ``collect`` CLI and ``init`` pseudonym-key provisioning (increment 1).

Network-free: the real ``site_canary`` collector performs a live HTTP GET through a registry factory
with no injection seam, so these tests substitute the module-level collect registry
(:func:`milhouse.cli.root._new_collect_registry`) with one holding a fake, spool-only collector.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest
from _runtime_harness import KNOWN_SECRET, FakeCollector, fake_factory, registry_with
from click.testing import CliRunner

from milhouse.cli import bootstrap, root
from milhouse.cli.root import main
from milhouse.config import RuntimePaths, load_config, resolve_runtime_paths
from milhouse.domain.records import CollectorDescriptorV1
from milhouse.spooling import SpoolError
from milhouse.state import StateError

_REPO_ROOT = Path(__file__).resolve().parents[2]
_EXAMPLE_CONFIG = (_REPO_ROOT / "config" / "example.toml").read_text(encoding="utf-8")
# A second site_canary collector on the already-declared target, so a per-collector isolation run
# has one collector that fails and one that succeeds. Appended text appends to the collectors array.
_SECOND_COLLECTOR = (
    '\n[[collectors]]\nid = "second-canary"\ntype = "site_canary"\n'
    'target = "example-app"\nurl = "https://example.com/health2"\nexpected_statuses = [200]\n'
)


def _config_file(tmp_path: Path, *, extra: str = "", mode: str = "spool_only") -> Path:
    # The example config ships ``runtime.mode = "full"``; collect run rejects full mode (exit 2), so
    # the run-path tests default to a spool_only config. ``mode="full"`` is used to test the reject.
    config_dir = tmp_path / "cfg"
    config_dir.mkdir()
    config_file = config_dir / "config.toml"
    body = _EXAMPLE_CONFIG.replace('mode = "full"', f'mode = "{mode}"')
    config_file.write_text(body + extra, encoding="utf-8")
    return config_file


def _paths(config_file: Path, tmp_path: Path) -> RuntimePaths:
    config, config_path = load_config(config_file, platform_default=config_file)
    return resolve_runtime_paths(
        config, config_path=config_path, platform_data_root=tmp_path / "platform"
    )


def _use_fake_registry(monkeypatch: pytest.MonkeyPatch, factory: object) -> None:
    """Swap the production collect registry for one resolving ``site_canary`` to ``factory``."""

    registry = registry_with("site_canary", factory)
    monkeypatch.setattr(root, "_new_collect_registry", lambda: registry)


def _isolation_factory(fail_id: str) -> object:
    """A factory whose collector raises for ``fail_id`` and otherwise succeeds with one event."""

    def factory(config: object) -> FakeCollector:
        descriptor = CollectorDescriptorV1(
            id=config.id,  # type: ignore[attr-defined]
            type="site.canary",
            implementation_version="1.0.0",
        )
        return FakeCollector(
            descriptor=descriptor,
            messages=("probe ok",),
            raises=(config.id == fail_id),  # type: ignore[attr-defined]
        )

    return factory


_PRIVACY_SAFE_TOP_KEYS = {
    "mode",
    "alerts_fired",
    "alerts_resolved",
    "alerts_error_code",
    "intents_emitted",
    "intents_error_code",
    "export_error_code",
    "records_committed",
    "records_delivered",
    "records_failed",
    "collectors",
}
_PRIVACY_SAFE_COLLECTOR_KEYS = {
    "collector_id",
    "status",
    "error_code",
    "drafts_produced",
    "records_committed",
    "records_delivered",
    "records_failed",
    "batch_id",
}


# --- Part A: init provisions the pseudonym key, idempotently --------------------------------------


def test_init_provisions_the_pseudonym_key_owner_only(tmp_path: Path) -> None:
    config_file = _config_file(tmp_path)
    paths = _paths(config_file, tmp_path)

    result = CliRunner().invoke(main, ["--config", str(config_file), "init"])

    assert result.exit_code == 0
    key_file = paths.pseudonym_key
    assert key_file.is_file()
    assert stat.S_IMODE(os.stat(key_file).st_mode) == 0o600
    assert "pseudonym key created" in result.output


def test_init_is_idempotent_and_never_rotates_the_key(tmp_path: Path) -> None:
    config_file = _config_file(tmp_path)
    paths = _paths(config_file, tmp_path)
    runner = CliRunner()

    first = runner.invoke(main, ["--config", str(config_file), "init", "--json"])
    assert first.exit_code == 0
    key_bytes = paths.pseudonym_key.read_bytes()

    second = runner.invoke(main, ["--config", str(config_file), "init", "--json"])

    assert second.exit_code == 0
    assert json.loads(first.output)["pseudonym_key_created"] is True
    assert json.loads(second.output)["pseudonym_key_created"] is False
    assert json.loads(second.output)["already_initialized"] is True
    # The key bytes are unchanged across the re-run (never rotated/overwritten).
    assert paths.pseudonym_key.read_bytes() == key_bytes


def test_init_never_echoes_key_material(tmp_path: Path) -> None:
    config_file = _config_file(tmp_path)
    paths = _paths(config_file, tmp_path)
    runner = CliRunner()
    runner.invoke(main, ["--config", str(config_file), "init"])
    key_bytes = paths.pseudonym_key.read_bytes()

    text = runner.invoke(main, ["--config", str(config_file), "init"]).output
    as_json = runner.invoke(main, ["--config", str(config_file), "init", "--json"]).output

    # Neither the raw bytes nor their hex ever appear in any rendering.
    assert key_bytes.hex() not in text
    assert key_bytes.hex() not in as_json
    for rendering in (text, as_json):
        assert not any(chunk in rendering for chunk in (key_bytes[:8].hex(), key_bytes[-8:].hex()))


# --- Part B: collect run (spool-only) -------------------------------------------------------------


def test_collect_run_commits_a_segment_and_exits_zero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config_file = _config_file(tmp_path)
    paths = _paths(config_file, tmp_path)
    runner = CliRunner()
    assert runner.invoke(main, ["--config", str(config_file), "init"]).exit_code == 0
    _use_fake_registry(monkeypatch, fake_factory(("probe ok",)))

    result = runner.invoke(main, ["--config", str(config_file), "collect", "run", "--json"])

    assert result.exit_code == 0
    payload = json.loads(result.output.strip().splitlines()[-1])
    assert payload["mode"] == "spool_only"
    assert payload["records_committed"] >= 1
    assert payload["records_delivered"] == 0
    # A durable segment reached the spool.
    assert list((paths.spool / "pending").rglob("*.jsonl"))


def test_collect_run_json_is_stable_and_privacy_safe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config_file = _config_file(tmp_path)
    runner = CliRunner()
    runner.invoke(main, ["--config", str(config_file), "init"])
    _use_fake_registry(monkeypatch, fake_factory(("probe ok",)))

    result = runner.invoke(main, ["--config", str(config_file), "collect", "run", "--json"])

    assert result.exit_code == 0
    json_line = result.output.strip().splitlines()[-1]
    payload = json.loads(json_line)
    # Stable: the emitted line is exactly the sorted-keys serialization of what was parsed.
    assert json_line == json.dumps(payload, sort_keys=True)
    assert set(payload) == _PRIVACY_SAFE_TOP_KEYS
    for collector in payload["collectors"]:
        assert set(collector) == _PRIVACY_SAFE_COLLECTOR_KEYS
    # No target url or host leaks into the summary.
    assert "example.com" not in result.output
    assert "health2" not in result.output


def test_collect_run_exits_one_when_a_collector_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config_file = _config_file(tmp_path)
    runner = CliRunner()
    runner.invoke(main, ["--config", str(config_file), "init"])
    _use_fake_registry(monkeypatch, fake_factory(("boom",), raises=True))

    result = runner.invoke(main, ["--config", str(config_file), "collect", "run", "--json"])

    assert result.exit_code == 1
    payload = json.loads(result.output.strip().splitlines()[-1])
    assert payload["collectors"][0]["status"] == "error"
    assert payload["collectors"][0]["error_code"] is not None
    # The fake's raised exception embeds KNOWN_SECRET; per-collector isolation must reduce it to a
    # fixed code, so the secret in the exception message never surfaces in any rendered output.
    assert KNOWN_SECRET not in result.output


def test_collect_run_isolates_a_failing_collector_from_a_healthy_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config_file = _config_file(tmp_path, extra=_SECOND_COLLECTOR)
    runner = CliRunner()
    runner.invoke(main, ["--config", str(config_file), "init"])
    # "second-canary" raises; "example-canary" succeeds — one failure must not abort the other.
    _use_fake_registry(monkeypatch, _isolation_factory("second-canary"))

    result = runner.invoke(main, ["--config", str(config_file), "collect", "run", "--json"])

    assert result.exit_code == 1  # a failed collector forces exit 1
    payload = json.loads(result.output.strip().splitlines()[-1])
    by_id = {c["collector_id"]: c for c in payload["collectors"]}
    assert by_id["example-canary"]["status"] == "ok"
    assert by_id["example-canary"]["records_committed"] >= 1
    assert by_id["second-canary"]["status"] == "error"
    assert by_id["second-canary"]["error_code"] is not None


def test_collect_run_fails_closed_without_init(tmp_path: Path) -> None:
    config_file = _config_file(tmp_path)
    result = CliRunner().invoke(main, ["--config", str(config_file), "collect", "run"])
    assert result.exit_code == 1
    assert "run milhouse init first" in result.output


def test_collect_run_fails_closed_when_the_pseudonym_key_is_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config_file = _config_file(tmp_path)
    paths = _paths(config_file, tmp_path)
    runner = CliRunner()
    runner.invoke(main, ["--config", str(config_file), "init"])
    # Simulate an install predating key provisioning: identity present, key gone.
    paths.pseudonym_key.unlink()
    assert bootstrap.read_installation_id(paths) is not None
    _use_fake_registry(monkeypatch, fake_factory(("probe ok",)))

    result = runner.invoke(main, ["--config", str(config_file), "collect", "run"])

    assert result.exit_code == 1
    assert "run milhouse init first" in result.output
    # It never reached a collect run.
    assert not list((paths.spool / "pending").rglob("*.jsonl"))


def test_collect_run_unknown_collector_id_is_config_error(tmp_path: Path) -> None:
    config_file = _config_file(tmp_path)
    CliRunner().invoke(main, ["--config", str(config_file), "init"])
    result = CliRunner().invoke(main, ["--config", str(config_file), "collect", "run", "nope"])
    assert result.exit_code == 2


def test_collect_run_unknown_target_is_config_error(tmp_path: Path) -> None:
    config_file = _config_file(tmp_path)
    CliRunner().invoke(main, ["--config", str(config_file), "init"])
    result = CliRunner().invoke(
        main, ["--config", str(config_file), "collect", "run", "--target", "nope"]
    )
    assert result.exit_code == 2


def test_collect_run_filters_to_one_collector(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config_file = _config_file(tmp_path, extra=_SECOND_COLLECTOR)
    runner = CliRunner()
    runner.invoke(main, ["--config", str(config_file), "init"])
    _use_fake_registry(monkeypatch, fake_factory(("probe ok",)))

    result = runner.invoke(
        main, ["--config", str(config_file), "collect", "run", "second-canary", "--json"]
    )

    assert result.exit_code == 0
    payload = json.loads(result.output.strip().splitlines()[-1])
    ids = {c["collector_id"] for c in payload["collectors"]}
    assert ids == {"second-canary"}


def test_collect_run_rejects_full_mode_and_commits_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A full-mode config must be REJECTED (exit 2) before any run: a spool_only run would stamp
    # required_exporters=() and permanently strand the segments from storage export. Nothing spools.
    config_file = _config_file(tmp_path, mode="full")
    paths = _paths(config_file, tmp_path)
    runner = CliRunner()
    runner.invoke(main, ["--config", str(config_file), "init"])
    _use_fake_registry(monkeypatch, fake_factory(("probe ok",)))

    result = runner.invoke(main, ["--config", str(config_file), "collect", "run"])

    assert result.exit_code == 2
    assert "full-mode" in result.output
    assert "runtime.mode = spool_only" in result.output
    # No segment was committed — the reject happens before the pipeline is built.
    assert not list((paths.spool / "pending").rglob("*.jsonl"))


@pytest.mark.parametrize(
    ("error", "code"),
    [
        (SpoolError("MH_SPOOL_TEST", "spool integrity check failed"), "MH_SPOOL_TEST"),
        (StateError("MH_STATE_TEST", "control state check failed"), "MH_STATE_TEST"),
    ],
)
def test_collect_run_maps_a_run_abort_to_the_coded_exit_one_contract(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, error: Exception, code: str
) -> None:
    # A whole-run abort (spool integrity, control state, pipeline ctor) must surface as the coded
    # exit-1 ClickException every other command produces -- never a raw traceback.
    config_file = _config_file(tmp_path)
    runner = CliRunner()
    runner.invoke(main, ["--config", str(config_file), "init"])

    class _AbortingPipeline:
        def run(self, collectors: object, targets: object) -> object:
            raise error

    monkeypatch.setattr(root, "_build_collect_pipeline", lambda *a, **k: _AbortingPipeline())

    result = runner.invoke(main, ["--config", str(config_file), "collect", "run"])

    assert result.exit_code == 1
    # The coded message is rendered by the ClickException handler (an escaped raw error would not
    # reach the captured output), and the recorded exception is the clean SystemExit Click raises
    # for a handled ClickException -- NOT the raw SpoolError/StateError with a traceback.
    assert code in result.output
    assert isinstance(result.exception, SystemExit)
    assert not isinstance(result.exception, (SpoolError, StateError))


# --- collect list ---------------------------------------------------------------------------------


def test_collect_list_reports_configured_collectors(tmp_path: Path) -> None:
    config_file = _config_file(tmp_path)
    result = CliRunner().invoke(main, ["--config", str(config_file), "collect", "list", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert {"id": "example-canary", "type": "site_canary"} in payload["collectors"]
