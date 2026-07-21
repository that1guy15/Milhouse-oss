from __future__ import annotations

import os
import traceback
from pathlib import Path

import pytest
from click.testing import CliRunner

from milhouse.cli import main
from milhouse.config import ConfigError, load_config_file
from milhouse.config.filesystem import inspect_regular_file_no_follow
from milhouse.config.loader import ConfigFileSelection, validated_config_digest
from milhouse.config.paths import resolve_runtime_paths
from milhouse.config.secrets import load_secret_environment

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
LOCAL_CONFIG = REPOSITORY_ROOT / "config/examples/local-only.toml"


def _runtime(tmp_path: Path, *, env_files: list[str] | None = None):
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    config_path = config_dir / "milhouse.toml"
    config_path.write_text("config_version = 1\n", encoding="utf-8")
    base = load_config_file(LOCAL_CONFIG)
    paths_config = base.paths.model_copy(update={"home": "state"})
    secrets_config = base.secrets.model_copy(update={"env_files": env_files or []})
    config = base.model_copy(update={"paths": paths_config, "secrets": secrets_config})
    selected = inspect_regular_file_no_follow(config_path)
    selection = ConfigFileSelection(
        path=selected.path,
        parent_identity=selected.parent_identity,
        snapshot=selected.snapshot,
        config_digest=validated_config_digest(config),
    )
    paths = resolve_runtime_paths(
        config,
        config_path=selection,
        platform_data_root=tmp_path / "platform",
        env={},
    )
    return config, paths


def test_secret_values_are_absent_from_container_source_and_missing_value_traceback(
    tmp_path: Path,
) -> None:
    config, paths = _runtime(tmp_path)
    private_value = "runtime-private-observation-0123456789"
    loaded = load_secret_environment(
        config,
        paths,
        process_env={"MILHOUSE_CLICKHOUSE_PASSWORD": private_value},
    )

    with pytest.raises(ConfigError) as excinfo:
        loaded.require("MILHOUSE_CLICKHOUSE_URL")

    rendered = "\n".join(
        (
            repr(loaded),
            str(loaded),
            repr(loaded.source("MILHOUSE_CLICKHOUSE_PASSWORD")),
            "".join(traceback.format_exception(excinfo.value)),
        )
    )
    assert private_value not in rendered
    assert os.fspath(tmp_path) not in rendered


def test_malformed_selected_file_never_echoes_its_private_content_or_path(tmp_path: Path) -> None:
    config, paths = _runtime(tmp_path, env_files=["runtime.env"])
    private_value = "runtime-private-observation-9876543210"
    env_path = paths.config_dir / "runtime.env"
    env_path.write_text(
        f"MILHOUSE_CLICKHOUSE_PASSWORD={private_value}\ninvalid statement !\n",
        encoding="utf-8",
    )

    with pytest.raises(ConfigError) as excinfo:
        load_secret_environment(config, paths, process_env={})

    rendered = "".join(traceback.format_exception(excinfo.value))
    assert excinfo.value.code == "secrets.file.syntax"
    assert private_value not in rendered
    assert os.fspath(env_path) not in rendered


def test_config_validate_is_offline_and_does_not_open_any_env_file(tmp_path: Path) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text(LOCAL_CONFIG.read_text(encoding="utf-8"), encoding="utf-8")
    missing_explicit = tmp_path / "missing-explicit.env"

    result = CliRunner().invoke(
        main,
        [
            "--config",
            os.fspath(config_path),
            "--env-file",
            os.fspath(missing_explicit),
            "config",
            "validate",
        ],
        env={},
    )

    assert result.exit_code == 0
    assert result.output == "configuration is valid\n"
    assert not missing_explicit.exists()


def test_config_validate_refuses_runtime_escape_with_exit_two_and_value_safe_output(
    tmp_path: Path,
) -> None:
    private_path = tmp_path / "private-runtime-fragment-0123456789"
    document = LOCAL_CONFIG.read_text(encoding="utf-8").replace(
        'spool = "spool"', f'spool = "{private_path}"', 1
    )
    config_path = tmp_path / "config.toml"
    config_path.write_text(document, encoding="utf-8")

    result = CliRunner().invoke(
        main,
        ["--config", os.fspath(config_path), "config", "validate"],
        env={},
    )

    assert result.exit_code == 2
    assert "config.path.escape" in result.stderr
    assert os.fspath(private_path) not in result.output
    assert os.fspath(private_path) not in result.stderr


def test_configured_env_symlink_refusal_never_echoes_target_path(tmp_path: Path) -> None:
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    config_path = config_dir / "milhouse.toml"
    config_path.write_text("config_version = 1\n", encoding="utf-8")
    target = tmp_path / "private-target-fragment-0123456789.env"
    target.write_text("MILHOUSE_CLICKHOUSE_URL=value\n", encoding="utf-8")
    (config_dir / "runtime.env").symlink_to(target)
    base = load_config_file(LOCAL_CONFIG)
    config = base.model_copy(
        update={
            "paths": base.paths.model_copy(update={"home": "state"}),
            "secrets": base.secrets.model_copy(update={"env_files": ["runtime.env"]}),
        }
    )

    with pytest.raises(ConfigError) as excinfo:
        selected = inspect_regular_file_no_follow(config_path)
        selection = ConfigFileSelection(
            path=selected.path,
            parent_identity=selected.parent_identity,
            snapshot=selected.snapshot,
            config_digest=validated_config_digest(config),
        )
        resolve_runtime_paths(
            config,
            config_path=selection,
            platform_data_root=tmp_path / "platform",
            env={},
        )

    rendered = "".join(traceback.format_exception(excinfo.value))
    assert excinfo.value.code == "config.path.symlink"
    assert os.fspath(target) not in rendered


def test_cli_validate_refuses_a_symlinked_config_parent_before_parsing_target(
    tmp_path: Path,
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    target = outside / "config.toml"
    private_content = "private-malformed-config-fragment-0123456789 !\n"
    target.write_text(private_content, encoding="utf-8")
    linked_parent = tmp_path / "linked"
    linked_parent.symlink_to(outside, target_is_directory=True)

    result = CliRunner().invoke(
        main,
        ["--config", os.fspath(linked_parent / "config.toml"), "config", "validate"],
        env={},
    )

    assert result.exit_code == 2
    assert "config.file.not_regular" in result.stderr
    assert "config.toml.syntax" not in result.stderr
    assert private_content.strip() not in result.output
    assert os.fspath(target) not in result.output


def test_secret_loading_refuses_a_replaced_config_directory_before_reading_new_source(
    tmp_path: Path,
) -> None:
    config, paths = _runtime(tmp_path, env_files=["runtime.env"])
    original_dir = tmp_path / "original-config"
    paths.config_dir.rename(original_dir)
    paths.config_dir.mkdir()
    (paths.config_dir / "milhouse.toml").write_text("config_version = 1\n", encoding="utf-8")
    private_value = "private-replacement-fragment-0123456789"
    (paths.config_dir / "runtime.env").write_text(
        f"MILHOUSE_CLICKHOUSE_URL={private_value}\n", encoding="utf-8"
    )

    with pytest.raises(ConfigError) as excinfo:
        load_secret_environment(config, paths, process_env={})

    rendered = "".join(traceback.format_exception(excinfo.value))
    assert excinfo.value.code == "config.file.changed"
    assert private_value not in rendered
    assert os.fspath(paths.config_dir) not in rendered
