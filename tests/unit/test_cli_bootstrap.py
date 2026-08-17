"""Tests for the config-driven ``init``/``health`` bootstrap (first product slice)."""

from __future__ import annotations

import os
import stat
from datetime import UTC, datetime
from pathlib import Path

import pytest
from click.testing import CliRunner
from pydantic import TypeAdapter

from milhouse.cli import bootstrap
from milhouse.cli.root import main
from milhouse.config import RuntimePaths, load_config, resolve_runtime_paths
from milhouse.domain.identity import InstallationIdV1

_NOW = datetime(2026, 8, 3, 12, 0, 0, tzinfo=UTC)
_REPO_ROOT = Path(__file__).resolve().parents[2]
_EXAMPLE_CONFIG = (_REPO_ROOT / "config" / "example.toml").read_text(encoding="utf-8")
_INSTALLATION_ID = TypeAdapter(InstallationIdV1)


def _config_file(tmp_path: Path) -> Path:
    config_dir = tmp_path / "cfg"
    config_dir.mkdir()
    config_file = config_dir / "config.toml"
    config_file.write_text(_EXAMPLE_CONFIG, encoding="utf-8")
    return config_file


def _paths(tmp_path: Path) -> RuntimePaths:
    config_file = _config_file(tmp_path)
    config, config_path = load_config(config_file, platform_default=config_file)
    return resolve_runtime_paths(
        config, config_path=config_path, platform_data_root=tmp_path / "platform"
    )


def _init_with_key(tmp_path: Path) -> RuntimePaths:
    """Initialize an install WITH the pseudonym key (a full config-aware init)."""

    config_file = _config_file(tmp_path)
    config, config_path = load_config(config_file, platform_default=config_file)
    paths = resolve_runtime_paths(
        config, config_path=config_path, platform_data_root=tmp_path / "platform"
    )
    bootstrap.initialize(paths, now=_NOW, config=config)
    return paths


def test_initialize_creates_the_full_layout_schema_and_identity(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    report = bootstrap.initialize(paths, now=_NOW)

    assert set(report.created_directories) == {
        "state_root",
        "control",
        "spool",
        "reports",
        "logs",
        "backups",
    }
    assert report.schema_version == bootstrap.EXPECTED_SCHEMA_VERSION == 11
    assert report.installation_id_created is True
    assert report.already_initialized is False
    for _label, directory in bootstrap._managed_directories(paths):
        assert directory.is_dir()
        assert stat.S_IMODE(os.stat(directory).st_mode) == 0o700
    assert bootstrap.database_path(paths).is_file()


def test_initialize_is_idempotent(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    first = bootstrap.initialize(paths, now=_NOW)
    first_id = bootstrap.read_installation_id(paths)

    second = bootstrap.initialize(paths, now=_NOW)

    assert first.installation_id_created is True
    assert second.created_directories == ()
    assert second.installation_id_created is False
    assert second.already_initialized is True
    assert bootstrap.read_installation_id(paths) == first_id  # identity is stable across runs


def test_installation_id_is_a_valid_domain_identity_stored_owner_only(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    bootstrap.initialize(paths, now=_NOW)

    identity = bootstrap.read_installation_id(paths)
    assert identity is not None
    _INSTALLATION_ID.validate_python(identity)  # the domain record-identity type accepts it
    id_file = paths.state_root / "control" / "installation.id"
    assert stat.S_IMODE(os.stat(id_file).st_mode) == 0o600


def test_read_installation_id_is_none_before_init(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    (paths.state_root / "control").mkdir(parents=True)
    assert bootstrap.read_installation_id(paths) is None


def test_read_installation_id_rejects_a_malformed_file(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    control = paths.state_root / "control"
    control.mkdir(parents=True)
    (control / "installation.id").write_text("not-a-valid-id", encoding="utf-8")
    assert bootstrap.read_installation_id(paths) is None


def test_read_installation_id_rejects_an_oversized_file(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    control = paths.state_root / "control"
    control.mkdir(parents=True)
    (control / "installation.id").write_bytes(b"a" * 200)
    assert bootstrap.read_installation_id(paths) is None


def test_read_installation_id_rejects_non_ascii(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    control = paths.state_root / "control"
    control.mkdir(parents=True)
    (control / "installation.id").write_bytes(b"\xff\xfe\xfd\xfc")
    assert bootstrap.read_installation_id(paths) is None


def test_initialize_fails_closed_when_a_directory_cannot_be_created(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    # Put a regular file where the state root must be a directory, so mkdir fails closed.
    paths.state_root.parent.mkdir(parents=True, exist_ok=True)
    paths.state_root.write_bytes(b"not a directory")
    with pytest.raises(bootstrap.BootstrapError) as captured:
        bootstrap.initialize(paths, now=_NOW)
    assert captured.value.code == "MH_INIT_DIR"


def test_health_is_healthy_after_init(tmp_path: Path) -> None:
    # A full config-aware init provisions the pseudonym key, so the install is fully healthy.
    paths = _init_with_key(tmp_path)

    report = bootstrap.health(paths, now=_NOW)

    assert report.healthy is True
    assert report.status == "healthy"
    assert {check.name for check in report.checks} >= {
        "control_database",
        "installation_identity",
        "directory:spool",
        "pseudonym_key",
    }


def test_health_flags_a_missing_pseudonym_key(tmp_path: Path) -> None:
    config_file = _config_file(tmp_path)
    config, config_path = load_config(config_file, platform_default=config_file)
    paths = resolve_runtime_paths(
        config, config_path=config_path, platform_data_root=tmp_path / "platform"
    )
    # Keyless init: directories + schema + identity, but NO pseudonym key (collect run needs it).
    bootstrap.initialize(paths, now=_NOW)

    report = bootstrap.health(paths, now=_NOW)

    key_check = next(check for check in report.checks if check.name == "pseudonym_key")
    assert key_check.ok is False
    assert report.healthy is False  # a keyless install is not usable

    # A full init (with config) provisions the key; the install becomes healthy again.
    bootstrap.initialize(paths, now=_NOW, config=config)
    healed = bootstrap.health(paths, now=_NOW)
    assert next(check for check in healed.checks if check.name == "pseudonym_key").ok is True
    assert healed.healthy is True


def test_health_is_unhealthy_before_init(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    report = bootstrap.health(paths, now=_NOW)
    assert report.healthy is False
    assert report.status == "unhealthy"
    names = {check.name for check in report.checks if not check.ok}
    assert "control_database" in names
    assert "installation_identity" in names


def test_health_flags_a_wrong_schema_version(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _paths(tmp_path)
    bootstrap.initialize(paths, now=_NOW)
    monkeypatch.setattr(bootstrap, "EXPECTED_SCHEMA_VERSION", 999)

    report = bootstrap.health(paths, now=_NOW)

    database_check = next(c for c in report.checks if c.name == "control_database")
    assert database_check.ok is False
    assert "expected 999" in database_check.detail


def test_health_flags_a_corrupt_pseudonym_key(tmp_path: Path) -> None:
    # A present-but-invalid key (here: mode loosened from owner-only 0600 to 0644) must read NOT-ok
    # and unhealthy -- matching how ``collect``'s load_pseudonym_key rejects it -- rather than being
    # called "healthy" by a bare presence probe.
    paths = _init_with_key(tmp_path)
    os.chmod(paths.pseudonym_key, 0o644)

    report = bootstrap.health(paths, now=_NOW)

    key_check = next(check for check in report.checks if check.name == "pseudonym_key")
    assert key_check.ok is False
    assert key_check.detail == "present but invalid (run milhouse init)"
    assert report.healthy is False


def test_initialize_without_config_never_provisions_the_pseudonym_key(tmp_path: Path) -> None:
    # Credential-free callers (the spool-only demo) init WITHOUT a config: the pseudonym key file
    # must stay ABSENT and ``pseudonym_key_created`` False -- the privacy invariant that a keyless
    # init never provisions key material.
    config_file = _config_file(tmp_path)
    config, config_path = load_config(config_file, platform_default=config_file)
    paths = resolve_runtime_paths(
        config, config_path=config_path, platform_data_root=tmp_path / "platform"
    )

    report = bootstrap.initialize(paths, now=_NOW)  # no config

    assert report.pseudonym_key_created is False
    assert not paths.pseudonym_key.exists()


def test_initialize_creates_a_nested_pseudonym_key_parent(tmp_path: Path) -> None:
    # A non-default nested ``identity.pseudonym_key_path`` must have its owner-only parent chain
    # created, or key provisioning would fail with an opaque parent-missing error.
    config_dir = tmp_path / "cfg"
    config_dir.mkdir()
    config_file = config_dir / "config.toml"
    body = _EXAMPLE_CONFIG.replace(
        'pseudonym_key_path = "control/pseudonym.key"',
        'pseudonym_key_path = "control/keys/nested/pseudonym.key"',
    )
    config_file.write_text(body, encoding="utf-8")
    config, config_path = load_config(config_file, platform_default=config_file)
    paths = resolve_runtime_paths(
        config, config_path=config_path, platform_data_root=tmp_path / "platform"
    )
    assert not paths.pseudonym_key.parent.exists()

    report = bootstrap.initialize(paths, now=_NOW, config=config)

    assert report.pseudonym_key_created is True
    assert paths.pseudonym_key.is_file()
    assert stat.S_IMODE(os.stat(paths.pseudonym_key).st_mode) == 0o600
    # Every ancestor directory created down to the key's parent is owner-only (0700), including the
    # intermediate levels ``mkdir(parents=True)`` would otherwise leave at the umask default.
    parent = paths.pseudonym_key.parent
    for level in (parent, parent.parent):  # control/keys/nested, control/keys
        assert stat.S_IMODE(os.stat(level).st_mode) == 0o700


# --- CLI surface (exit codes + stable JSON) -------------------------------------------------------


def test_cli_init_then_health_json(tmp_path: Path) -> None:
    config_file = _config_file(tmp_path)
    runner = CliRunner()

    init_result = runner.invoke(main, ["--config", str(config_file), "init"])
    assert init_result.exit_code == 0
    assert "initialized" in init_result.output

    health_result = runner.invoke(main, ["--config", str(config_file), "health", "--json"])
    assert health_result.exit_code == 0
    assert '"status": "healthy"' in health_result.output


def test_cli_health_exits_nonzero_when_unhealthy(tmp_path: Path) -> None:
    config_file = _config_file(tmp_path)
    runner = CliRunner()
    result = runner.invoke(main, ["--config", str(config_file), "health"])
    assert result.exit_code == 1
    assert "status: unhealthy" in result.output


def test_cli_init_json_is_stable(tmp_path: Path) -> None:
    config_file = _config_file(tmp_path)
    runner = CliRunner()
    result = runner.invoke(main, ["--config", str(config_file), "init", "--json"])
    assert result.exit_code == 0
    assert '"schema_version": 11' in result.output
    assert '"installation_id_created": true' in result.output


def test_cli_init_reports_config_error_with_exit_code_two(tmp_path: Path) -> None:
    missing = tmp_path / "does-not-exist.toml"
    runner = CliRunner()
    result = runner.invoke(main, ["--config", str(missing), "init"])
    assert result.exit_code == 2
