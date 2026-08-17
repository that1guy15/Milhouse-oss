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
from _storage_fakes import FakeClickHouseClient
from click.testing import CliRunner

from milhouse.cli import bootstrap, root
from milhouse.cli.root import main
from milhouse.config import RuntimePaths, load_config, resolve_runtime_paths
from milhouse.config.loader import validated_config_digest
from milhouse.config.secrets import SecretEnvironment
from milhouse.domain.records import CollectorDescriptorV1
from milhouse.runtime import PipelineError
from milhouse.spooling import SpoolError
from milhouse.state import StateError

_REPO_ROOT = Path(__file__).resolve().parents[2]
_EXAMPLE_CONFIG = (_REPO_ROOT / "config" / "example.toml").read_text(encoding="utf-8")
# A minimal config whose single collector is its LAST block with no job/rule referencing it, so
# truncating at ``[[collectors]]`` yields a valid ZERO-collector config for the empty-list branch.
_LOCAL_ONLY_CONFIG = (_REPO_ROOT / "config" / "examples" / "local-only.toml").read_text(
    encoding="utf-8"
)
# A second site_canary collector on the already-declared target, so a per-collector isolation run
# has one collector that fails and one that succeeds. Appended text appends to the collectors array.
_SECOND_COLLECTOR = (
    '\n[[collectors]]\nid = "second-canary"\ntype = "site_canary"\n'
    'target = "example-app"\nurl = "https://example.com/health2"\nexpected_statuses = [200]\n'
)
# A second declared target that no example collector is bound to.
_SECOND_TARGET = (
    '\n[[targets]]\nid = "other-app"\nname = "Other App"\nkind = "web_service"\n'
    'environment = "production"\n'
)
# A second site_canary collector bound to the second declared target, to prove ``--target`` scoping
# on ``canary`` keeps only the canaries bound to the requested target.
_OTHER_TARGET_CANARY = (
    '\n[[collectors]]\nid = "other-canary"\ntype = "site_canary"\n'
    'target = "other-app"\nurl = "https://other.example/health"\nexpected_statuses = [200]\n'
)
# A NON-canary collector (file_outbox) on the already-declared target, to prove ``canary`` filters
# to the site_canary type and never resolves/runs a non-canary collector.
_NON_CANARY_COLLECTOR = (
    '\n[[collectors]]\nid = "example-outbox"\ntype = "file_outbox"\n'
    'target = "example-app"\npath = "outbox"\n'
)


def _config_file(
    tmp_path: Path, *, extra: str = "", mode: str = "spool_only", clickhouse_enabled: bool = True
) -> Path:
    # The example config ships ``runtime.mode = "full"``; the spool-only run-path tests default to a
    # spool_only config, while ``mode="full"`` exercises the ClickHouse export tail (against a fake
    # client). ``clickhouse_enabled=False`` toggles the storage block off to test the disabled path.
    config_dir = tmp_path / "cfg"
    config_dir.mkdir()
    config_file = config_dir / "config.toml"
    body = _EXAMPLE_CONFIG.replace('mode = "full"', f'mode = "{mode}"')
    if not clickhouse_enabled:
        body = body.replace(
            "[storage.clickhouse]\nenabled = true", "[storage.clickhouse]\nenabled = false"
        )
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

# The example config's example-canary target URL/host; a fake collector emits it inside a draft's
# free-text field so a privacy assertion that it never reaches the summary is meaningful.
_TARGET_URL = "https://example.com/health"
_TARGET_HOST = "example.com"
_URL_BEARING_MESSAGE = f"probe of {_TARGET_URL} failed for host {_TARGET_HOST}"


def _json_payload(output: str) -> dict[str, object]:
    """Parse the ``--json`` summary object from mixed stdout/stderr CLI output.

    ``collect run`` may trail its JSON summary with privacy-safe stderr WARNING/NOTE lines (a failed
    collector, a stage error), which CliRunner mixes into ``output``; the summary is therefore the
    last line that starts with ``{``, not simply the last line.
    """

    json_lines = [line for line in output.splitlines() if line.startswith("{")]
    assert json_lines, output
    return json.loads(json_lines[-1])


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
    # The fake collector emits a draft whose free-text message ACTUALLY carries the target URL/host,
    # so the no-leak assertions below prove the summary is privacy-safe (it never renders draft
    # payloads) rather than being vacuously true against a URL-free draft.
    _use_fake_registry(monkeypatch, fake_factory((_URL_BEARING_MESSAGE,)))

    result = runner.invoke(main, ["--config", str(config_file), "collect", "run", "--json"])

    assert result.exit_code == 0
    json_line = result.output.strip().splitlines()[-1]
    payload = json.loads(json_line)
    # Stable: the emitted line is exactly the sorted-keys serialization of what was parsed.
    assert json_line == json.dumps(payload, sort_keys=True)
    assert set(payload) == _PRIVACY_SAFE_TOP_KEYS
    for collector in payload["collectors"]:
        assert set(collector) == _PRIVACY_SAFE_COLLECTOR_KEYS
    # The draft carried the target URL/host in a free-text field; neither leaks into the summary.
    assert _TARGET_URL not in result.output
    assert _TARGET_HOST not in result.output


def test_collect_run_exits_one_when_a_collector_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config_file = _config_file(tmp_path)
    runner = CliRunner()
    runner.invoke(main, ["--config", str(config_file), "init"])
    _use_fake_registry(monkeypatch, fake_factory(("boom",), raises=True))

    result = runner.invoke(main, ["--config", str(config_file), "collect", "run", "--json"])

    assert result.exit_code == 1
    payload = _json_payload(result.output)
    assert payload["collectors"][0]["status"] == "error"
    assert payload["collectors"][0]["error_code"] is not None
    # The fake's raised exception embeds KNOWN_SECRET; per-collector isolation must reduce it to a
    # fixed code, so the secret in the exception message never surfaces in any rendered output.
    assert KNOWN_SECRET not in result.output
    # A failed/error collector emits a uniform stderr WARNING carrying ONLY the config-declared
    # collector id and its fixed error code (never the secret-bearing exception message).
    assert "WARNING: collector example-canary ended error" in result.output
    assert payload["collectors"][0]["error_code"] in result.output


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
    payload = _json_payload(result.output)
    by_id = {c["collector_id"]: c for c in payload["collectors"]}
    assert by_id["example-canary"]["status"] == "ok"
    assert by_id["example-canary"]["records_committed"] >= 1
    assert by_id["second-canary"]["status"] == "error"
    assert by_id["second-canary"]["error_code"] is not None
    # The uniform per-collector WARNING names only the failing collector, not the healthy one.
    assert "WARNING: collector second-canary ended error" in result.output
    assert "WARNING: collector example-canary" not in result.output


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


def test_collect_run_missing_key_opens_no_control_database(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A2: the pseudonym-key fail-closed guard runs BEFORE any control-DB (or ClickHouse client)
    # handle is opened, so a run whose key is absent leaves no (empty) control DB behind. Simulate a
    # partial state -- identity present, but BOTH the key and the control DB gone -- and prove the
    # DB is not recreated.
    config_file = _config_file(tmp_path)
    paths = _paths(config_file, tmp_path)
    runner = CliRunner()
    assert runner.invoke(main, ["--config", str(config_file), "init"]).exit_code == 0
    paths.pseudonym_key.unlink()
    database = bootstrap.database_path(paths)
    database.unlink()
    assert bootstrap.read_installation_id(paths) is not None  # identity persists (separate file)
    _use_fake_registry(monkeypatch, fake_factory(("probe ok",)))

    result = runner.invoke(main, ["--config", str(config_file), "collect", "run"])

    assert result.exit_code == 1
    assert "run milhouse init first" in result.output
    assert not database.exists()  # the key guard preceded open_control_database


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


def test_collect_run_collector_not_bound_to_target_is_config_error(tmp_path: Path) -> None:
    # example-canary is bound to example-app, not other-app. Naming BOTH a collector and a target it
    # is not bound to is an operator mistake -- a config error (exit 2), not a silent empty run.
    config_file = _config_file(tmp_path, extra=_SECOND_TARGET)
    result = CliRunner().invoke(
        main,
        ["--config", str(config_file), "collect", "run", "example-canary", "--target", "other-app"],
    )
    assert result.exit_code == 2


def test_collect_run_target_only_with_no_bound_collectors_is_an_empty_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # ``--target`` alone (no collector id) over a target that has no bound collectors stays a
    # legitimate empty run (exit 0), NOT a config error -- only the both-given case is an error.
    config_file = _config_file(tmp_path, extra=_SECOND_TARGET)
    runner = CliRunner()
    assert runner.invoke(main, ["--config", str(config_file), "init"]).exit_code == 0
    _use_fake_registry(monkeypatch, fake_factory(("probe ok",)))

    result = runner.invoke(
        main, ["--config", str(config_file), "collect", "run", "--target", "other-app", "--json"]
    )

    assert result.exit_code == 0
    payload = _json_payload(result.output)
    assert payload["collectors"] == []


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


@pytest.mark.parametrize(
    ("error", "code"),
    [
        (SpoolError("MH_SPOOL_TEST", "spool integrity check failed"), "MH_SPOOL_TEST"),
        (StateError("MH_STATE_TEST", "control state check failed"), "MH_STATE_TEST"),
        (PipelineError("MH_PIPELINE_TEST", "pipeline construction failed"), "MH_PIPELINE_TEST"),
    ],
)
def test_collect_run_maps_a_run_abort_to_the_coded_exit_one_contract(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, error: Exception, code: str
) -> None:
    # A whole-run abort (spool integrity, control state, or a pipeline ctor PipelineError) must
    # surface as the coded exit-1 ClickException every other command produces -- never a traceback.
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
    # for a handled ClickException -- NOT the raw SpoolError/StateError/PipelineError with a
    # traceback.
    assert code in result.output
    assert isinstance(result.exception, SystemExit)
    assert not isinstance(result.exception, (SpoolError, StateError, PipelineError))


# --- Part C: collect run (full mode → ClickHouse export via the delivery ledger) ------------------
#
# Full mode wires the SAME exactly-once delivery tail ``storage export`` drives, so these tests
# reuse the offline fake ClickHouse seam: monkeypatch ``build_client`` → a fake and
# ``load_secret_environment`` → an empty env, and run ``storage migrate`` first so ``require_owner``
# passes. The real ClickHouse round-trip is host-gated (live/E06).


class _CloseSpyClient(FakeClickHouseClient):
    """A fake CH client that counts ``close()`` calls, to prove close-on-every-path."""

    def __init__(self) -> None:
        super().__init__()
        self.close_calls = 0

    def close(self) -> None:
        self.close_calls += 1


class _RaisingCloseSpyClient(_CloseSpyClient):
    """A close-spy whose ``insert`` raises, so a delivery is contained as a retryable failure."""

    def insert(self, *args: object, **kwargs: object) -> None:
        raise RuntimeError("clickhouse insert unavailable")


def _stub_clickhouse(monkeypatch: pytest.MonkeyPatch, client: FakeClickHouseClient) -> None:
    """Point the storage client seam at ``client`` with an empty secret environment (no network)."""

    monkeypatch.setattr(
        root, "load_secret_environment", lambda config, paths: SecretEnvironment({}, {})
    )
    monkeypatch.setattr(root.storage, "build_client", lambda config, secrets: client)


def _migrate(config_file: Path) -> None:
    """Claim/verify ownership of the (fake) ClickHouse by applying migrations — the full-mode
    precondition ``require_owner`` enforces."""

    result = CliRunner().invoke(main, ["--config", str(config_file), "storage", "migrate"])
    assert result.exit_code == 0, result.output


def test_collect_run_full_mode_delivers_to_clickhouse(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A migrated (claimed) full-mode destination: the committed segment is delivered through the
    # ClickHouse exporter, so the summary reports a delivery and the fake client received a records
    # insert. The client is closed on the clean-success path.
    config_file = _config_file(tmp_path, mode="full")
    client = _CloseSpyClient()
    _stub_clickhouse(monkeypatch, client)
    runner = CliRunner()
    assert runner.invoke(main, ["--config", str(config_file), "init"]).exit_code == 0
    _migrate(config_file)
    client.close_calls = 0  # isolate collect run's own finally-close from migrate's client close
    _use_fake_registry(monkeypatch, fake_factory(("probe ok",)))

    result = runner.invoke(main, ["--config", str(config_file), "collect", "run", "--json"])

    assert result.exit_code == 0
    payload = json.loads(result.output.strip().splitlines()[-1])
    assert payload["mode"] == "full"
    assert payload["records_committed"] >= 1
    assert payload["records_delivered"] >= 1
    assert payload["records_failed"] == 0
    assert payload["export_error_code"] is None
    # The delivery tail actually wrote the event's record row to ClickHouse (not just migrate DDL).
    assert "records" in [table for _db, table, *_ in client.inserts]
    assert client.close_calls >= 1  # closed on the success path (no leak)


def test_collect_run_full_mode_fails_closed_on_an_unclaimed_destination(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Full mode WITHOUT ``storage migrate`` (the destination is unclaimed): require_owner refuses it
    # with MH_STORAGE_OWNERSHIP and the "run storage migrate first" guidance, BEFORE any commit — so
    # nothing spools and the client is still closed. Click handles it (no traceback).
    config_file = _config_file(tmp_path, mode="full")
    paths = _paths(config_file, tmp_path)
    client = _CloseSpyClient()
    _stub_clickhouse(monkeypatch, client)
    runner = CliRunner()
    assert runner.invoke(main, ["--config", str(config_file), "init"]).exit_code == 0
    _use_fake_registry(monkeypatch, fake_factory(("probe ok",)))

    result = runner.invoke(main, ["--config", str(config_file), "collect", "run"])

    assert result.exit_code == 1
    assert "MH_STORAGE_OWNERSHIP" in result.output
    assert "migrate" in result.output  # "...unclaimed; run storage migrate first"
    assert isinstance(result.exception, SystemExit)  # a handled ClickException, not a raw traceback
    # Nothing was committed (the ownership barrier precedes the pipeline) and the client was closed.
    assert not list((paths.spool / "pending").rglob("*.jsonl"))
    assert client.inserts == []
    assert client.close_calls >= 1


def test_collect_run_full_mode_with_clickhouse_disabled_is_a_config_error(
    tmp_path: Path,
) -> None:
    # A full-mode config that disables ClickHouse cannot export: _storage_client raises
    # MH_STORAGE_CONFIG (exit 1) BEFORE any control handle or client is opened.
    config_file = _config_file(tmp_path, mode="full", clickhouse_enabled=False)
    paths = _paths(config_file, tmp_path)
    runner = CliRunner()
    assert runner.invoke(main, ["--config", str(config_file), "init"]).exit_code == 0

    result = runner.invoke(main, ["--config", str(config_file), "collect", "run"])

    assert result.exit_code == 1
    assert "MH_STORAGE_CONFIG" in result.output
    assert isinstance(result.exception, SystemExit)
    # It failed before the pipeline ran: nothing spooled.
    assert not list((paths.spool / "pending").rglob("*.jsonl"))


def test_collect_run_full_mode_delivery_failure_is_nonfatal_but_exits_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A ClickHouse insert that raises is CONTAINED by the delivery ledger as a retryable failure:
    # the segment is durably committed, records_failed is set, and the run exits 1 (loud, not
    # silent) — but the client is still closed. replay_segments does not raise, so export_error_code
    # stays None.
    config_file = _config_file(tmp_path, mode="full")
    client = _RaisingCloseSpyClient()
    _stub_clickhouse(monkeypatch, client)
    runner = CliRunner()
    assert runner.invoke(main, ["--config", str(config_file), "init"]).exit_code == 0
    _migrate(config_file)  # migrate uses command(), not insert(), so it still claims ownership
    client.close_calls = 0  # isolate collect run's own finally-close from migrate's client close
    _use_fake_registry(monkeypatch, fake_factory(("probe ok",)))

    result = runner.invoke(main, ["--config", str(config_file), "collect", "run", "--json"])

    assert result.exit_code == 1
    payload = json.loads(result.output.strip().splitlines()[-1])
    assert payload["mode"] == "full"
    assert payload["records_committed"] >= 1  # the commit is durable even though delivery failed
    assert payload["records_delivered"] == 0
    assert payload["records_failed"] >= 1  # the contained delivery failure forces exit 1
    assert payload["export_error_code"] is None  # replay_segments did not itself raise
    assert client.inserts == []  # the raising insert recorded nothing
    assert client.close_calls >= 1  # closed on the delivery-failure path (no leak)


def test_collect_run_spool_only_never_opens_a_clickhouse_client(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # spool_only must never touch the storage client seam: point build_client / load_secret_
    # environment at raising stubs and prove the run still succeeds without invoking either.
    config_file = _config_file(tmp_path)  # spool_only
    runner = CliRunner()
    assert runner.invoke(main, ["--config", str(config_file), "init"]).exit_code == 0

    def _boom_secret(config: object, paths: object) -> SecretEnvironment:
        raise AssertionError("spool_only must not load the secret environment")

    def _boom_client(config: object, secrets: object) -> FakeClickHouseClient:
        raise AssertionError("spool_only must not build a ClickHouse client")

    monkeypatch.setattr(root, "load_secret_environment", _boom_secret)
    monkeypatch.setattr(root.storage, "build_client", _boom_client)
    _use_fake_registry(monkeypatch, fake_factory(("probe ok",)))

    result = runner.invoke(main, ["--config", str(config_file), "collect", "run", "--json"])

    assert result.exit_code == 0
    payload = json.loads(result.output.strip().splitlines()[-1])
    assert payload["mode"] == "spool_only"
    assert payload["records_delivered"] == 0


# --- collect list ---------------------------------------------------------------------------------


def test_collect_list_reports_configured_collectors(tmp_path: Path) -> None:
    config_file = _config_file(tmp_path)
    result = CliRunner().invoke(main, ["--config", str(config_file), "collect", "list", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert {"id": "example-canary", "type": "site_canary"} in payload["collectors"]


# --- human-mode (non --json) render paths ---------------------------------------------------------


def test_collect_run_human_mode_renders_summary_and_per_collector_lines(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config_file = _config_file(tmp_path)  # spool_only
    runner = CliRunner()
    assert runner.invoke(main, ["--config", str(config_file), "init"]).exit_code == 0
    _use_fake_registry(monkeypatch, fake_factory(("probe ok",)))

    result = runner.invoke(main, ["--config", str(config_file), "collect", "run"])  # no --json

    assert result.exit_code == 0
    # The human-mode summary line and the per-collector line for the configured, healthy collector.
    assert "collect: mode=spool_only committed=" in result.output
    assert "delivered=0" in result.output
    assert "example-canary: status=ok" in result.output
    # Human mode emits no JSON object.
    assert "{" not in result.output


def test_collect_list_human_mode_renders_configured_collectors(tmp_path: Path) -> None:
    config_file = _config_file(tmp_path)
    result = CliRunner().invoke(
        main, ["--config", str(config_file), "collect", "list"]
    )  # no --json
    assert result.exit_code == 0
    assert "example-canary  type=site_canary" in result.output


def test_collect_list_human_mode_reports_no_configured_collectors(tmp_path: Path) -> None:
    body = _LOCAL_ONLY_CONFIG[: _LOCAL_ONLY_CONFIG.index("[[collectors]]")]
    config_dir = tmp_path / "cfg"
    config_dir.mkdir()
    config_file = config_dir / "config.toml"
    config_file.write_text(body, encoding="utf-8")

    result = CliRunner().invoke(main, ["--config", str(config_file), "collect", "list"])

    assert result.exit_code == 0
    assert "no configured collectors" in result.output


# --- config_generation digest reuse (locks B4 byte-identity) --------------------------------------


def test_config_selection_digest_is_the_validated_config_digest(tmp_path: Path) -> None:
    # ``_build_collect_pipeline`` reuses ``paths.config_selection.config_digest`` as the pipeline's
    # ``config_generation`` INSTEAD of recomputing ``validated_config_digest(config)``; the loader
    # binds them equal and ``verify_config_generation`` enforces it, so lock byte-identity here.
    config_file = _config_file(tmp_path)
    config, config_path = load_config(config_file, platform_default=config_file)
    paths = resolve_runtime_paths(
        config, config_path=config_path, platform_data_root=tmp_path / "platform"
    )
    assert paths.config_selection.config_digest == validated_config_digest(config)


# --- Part D: the ``canary`` shorthand -------------------------------------------------------------
#
# ``canary`` scopes a single runtime run to the configured ``site_canary`` collectors and reuses the
# SAME shared ``_run_collect`` body ``collect run`` drives, so these tests reuse the fake registry
# and fake-ClickHouse seams and assert the same privacy-safe summary shape and exit-code contract.


def test_canary_runs_the_site_canary_collectors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config_file = _config_file(tmp_path)
    paths = _paths(config_file, tmp_path)
    runner = CliRunner()
    assert runner.invoke(main, ["--config", str(config_file), "init"]).exit_code == 0
    _use_fake_registry(monkeypatch, fake_factory(("probe ok",)))

    result = runner.invoke(main, ["--config", str(config_file), "canary", "--json"])

    assert result.exit_code == 0
    payload = json.loads(result.output.strip().splitlines()[-1])
    assert payload["mode"] == "spool_only"
    assert payload["records_committed"] >= 1
    # The summary is the SAME privacy-safe shape ``collect run`` emits (shared helper).
    assert set(payload) == _PRIVACY_SAFE_TOP_KEYS
    for collector in payload["collectors"]:
        assert set(collector) == _PRIVACY_SAFE_COLLECTOR_KEYS
    # Only the configured site_canary collector ran, and a durable segment reached the spool.
    assert {c["collector_id"] for c in payload["collectors"]} == {"example-canary"}
    assert list((paths.spool / "pending").rglob("*.jsonl"))


def test_canary_excludes_non_site_canary_collectors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A file_outbox collector shares the config; ``canary`` must filter to the site_canary type
    # only, so the non-canary collector is never resolved/run (the fake registry has only canary).
    config_file = _config_file(tmp_path, extra=_NON_CANARY_COLLECTOR)
    runner = CliRunner()
    assert runner.invoke(main, ["--config", str(config_file), "init"]).exit_code == 0
    _use_fake_registry(monkeypatch, fake_factory(("probe ok",)))

    result = runner.invoke(main, ["--config", str(config_file), "canary", "--json"])

    assert result.exit_code == 0
    payload = json.loads(result.output.strip().splitlines()[-1])
    assert {c["collector_id"] for c in payload["collectors"]} == {"example-canary"}


def test_canary_target_filters_to_bound_canaries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Two canaries on two targets: ``--target example-app`` keeps only the canary bound to it.
    config_file = _config_file(tmp_path, extra=_SECOND_TARGET + _OTHER_TARGET_CANARY)
    runner = CliRunner()
    assert runner.invoke(main, ["--config", str(config_file), "init"]).exit_code == 0
    _use_fake_registry(monkeypatch, fake_factory(("probe ok",)))

    result = runner.invoke(
        main, ["--config", str(config_file), "canary", "--target", "example-app", "--json"]
    )

    assert result.exit_code == 0
    payload = json.loads(result.output.strip().splitlines()[-1])
    assert {c["collector_id"] for c in payload["collectors"]} == {"example-canary"}


def test_canary_target_with_no_bound_canaries_reports_and_exits_zero(tmp_path: Path) -> None:
    # other-app has no bound canary: ``canary`` reports the target-scoped message and exits 0
    # without running anything -- so no init is required and no handle is opened.
    config_file = _config_file(tmp_path, extra=_SECOND_TARGET)
    result = CliRunner().invoke(
        main, ["--config", str(config_file), "canary", "--target", "other-app"]
    )
    assert result.exit_code == 0
    assert "no site_canary collectors bound to target other-app" in result.output


def test_canary_unknown_target_is_config_error(tmp_path: Path) -> None:
    config_file = _config_file(tmp_path)
    CliRunner().invoke(main, ["--config", str(config_file), "init"])
    result = CliRunner().invoke(main, ["--config", str(config_file), "canary", "--target", "nope"])
    assert result.exit_code == 2


def test_canary_with_no_site_canary_collectors_reports_and_opens_no_handles(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A config that HAS a collector but NO site_canary one: ``canary`` reports the message and exits
    # 0 WITHOUT loading the key or opening any control/ClickHouse handle -- there is nothing to run.
    body = _LOCAL_ONLY_CONFIG[: _LOCAL_ONLY_CONFIG.index("[[collectors]]")]
    body += (
        '[[collectors]]\nid = "local-outbox"\ntype = "file_outbox"\n'
        'target = "local-tool"\npath = "outbox"\n'
    )
    config_dir = tmp_path / "cfg"
    config_dir.mkdir()
    config_file = config_dir / "config.toml"
    config_file.write_text(body, encoding="utf-8")
    paths = _paths(config_file, tmp_path)

    def _boom_control(path: object) -> object:
        raise AssertionError("the empty canary run must not open a control database")

    monkeypatch.setattr(root, "open_control_database", _boom_control)

    result = CliRunner().invoke(main, ["--config", str(config_file), "canary"])

    assert result.exit_code == 0
    assert "no site_canary collectors configured" in result.output
    # Nothing was opened or spooled (the empty-run guard precedes every handle).
    assert not bootstrap.database_path(paths).exists()
    assert not list((paths.spool / "pending").rglob("*.jsonl"))


def test_canary_json_on_an_empty_run_emits_parseable_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # --json must ALWAYS emit parseable JSON, even when nothing runs: an empty ``collectors``
    # signals nothing ran, and (as with the plain path) no handle is opened.
    body = _LOCAL_ONLY_CONFIG[: _LOCAL_ONLY_CONFIG.index("[[collectors]]")]
    body += (
        '[[collectors]]\nid = "local-outbox"\ntype = "file_outbox"\n'
        'target = "local-tool"\npath = "outbox"\n'
    )
    config_dir = tmp_path / "cfg"
    config_dir.mkdir()
    config_file = config_dir / "config.toml"
    config_file.write_text(body, encoding="utf-8")

    def _boom_control(path: object) -> object:
        raise AssertionError("the empty canary run must not open a control database")

    monkeypatch.setattr(root, "open_control_database", _boom_control)

    result = CliRunner().invoke(main, ["--config", str(config_file), "canary", "--json"])

    assert result.exit_code == 0
    payload = json.loads(result.output.strip().splitlines()[-1])
    assert payload["collectors"] == []
    assert "message" in payload


def test_canary_full_mode_delivers_to_clickhouse(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Full-mode ``canary`` reaches the SAME delivery tail: on a migrated (claimed) destination the
    # committed canary segment is delivered through the ClickHouse exporter and the client closes.
    config_file = _config_file(tmp_path, mode="full")
    client = _CloseSpyClient()
    _stub_clickhouse(monkeypatch, client)
    runner = CliRunner()
    assert runner.invoke(main, ["--config", str(config_file), "init"]).exit_code == 0
    _migrate(config_file)
    client.close_calls = 0  # isolate the canary run's own finally-close from migrate's client close
    _use_fake_registry(monkeypatch, fake_factory(("probe ok",)))

    result = runner.invoke(main, ["--config", str(config_file), "canary", "--json"])

    assert result.exit_code == 0
    payload = json.loads(result.output.strip().splitlines()[-1])
    assert payload["mode"] == "full"
    assert payload["records_committed"] >= 1
    assert payload["records_delivered"] >= 1
    assert payload["records_failed"] == 0
    assert payload["export_error_code"] is None
    # The delivery tail actually wrote the event's record row to ClickHouse (not just migrate DDL).
    assert "records" in [table for _db, table, *_ in client.inserts]
    assert client.close_calls >= 1  # closed on the success path (no leak)


def test_canary_json_is_privacy_safe(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config_file = _config_file(tmp_path)
    runner = CliRunner()
    runner.invoke(main, ["--config", str(config_file), "init"])
    # The fake canary emits a draft whose free-text message ACTUALLY carries the target URL/host, so
    # the no-leak assertions prove the summary is privacy-safe rather than vacuously true.
    _use_fake_registry(monkeypatch, fake_factory((_URL_BEARING_MESSAGE,)))

    result = runner.invoke(main, ["--config", str(config_file), "canary", "--json"])

    assert result.exit_code == 0
    json_line = result.output.strip().splitlines()[-1]
    payload = json.loads(json_line)
    assert json_line == json.dumps(payload, sort_keys=True)
    assert set(payload) == _PRIVACY_SAFE_TOP_KEYS
    assert _TARGET_URL not in result.output
    assert _TARGET_HOST not in result.output
