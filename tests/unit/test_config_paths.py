from __future__ import annotations

import os
from pathlib import Path

import pytest

import milhouse.config.paths as config_paths
from milhouse.config import ConfigError, load_config_file
from milhouse.config._models import MilhouseConfig
from milhouse.config.filesystem import inspect_regular_file_no_follow
from milhouse.config.loader import ConfigFileSelection, validated_config_digest
from milhouse.config.paths import (
    MILHOUSE_HOME_ENV_VAR,
    RuntimePaths,
    resolve_config_source_path,
)
from milhouse.config.paths import (
    resolve_runtime_paths as _resolve_runtime_paths,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
BASE_CONFIG = load_config_file(REPOSITORY_ROOT / "config/examples/local-only.toml")


def _config(
    *,
    home: str = "state",
    spool: str = "spool",
    reports: str = "reports",
    logs: str = "logs",
    backups: str = "backups",
    pseudonym_key_path: str = "control/pseudonym.key",
    env_files: list[str] | None = None,
):
    paths = BASE_CONFIG.paths.model_copy(
        update={
            "home": home,
            "spool": spool,
            "reports": reports,
            "logs": logs,
            "backups": backups,
        }
    )
    identity = BASE_CONFIG.identity.model_copy(update={"pseudonym_key_path": pseudonym_key_path})
    secrets = BASE_CONFIG.secrets.model_copy(update={"env_files": env_files or []})
    return BASE_CONFIG.model_copy(update={"paths": paths, "identity": identity, "secrets": secrets})


def _config_file(tmp_path: Path) -> Path:
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    path = config_dir / "milhouse.toml"
    path.write_text("config_version = 1\n", encoding="utf-8")
    return path


def _bound_selection(config: MilhouseConfig, path: Path) -> ConfigFileSelection:
    selected = inspect_regular_file_no_follow(path)
    return ConfigFileSelection(
        path=selected.path,
        parent_identity=selected.parent_identity,
        snapshot=selected.snapshot,
        config_digest=validated_config_digest(config),
    )


def resolve_runtime_paths(
    config: MilhouseConfig,
    *,
    config_path: str | Path | ConfigFileSelection,
    platform_data_root: str | Path,
    env: dict[str, str] | None = None,
) -> RuntimePaths:
    selection = (
        config_path
        if isinstance(config_path, ConfigFileSelection)
        else _bound_selection(config, Path(config_path))
    )
    return _resolve_runtime_paths(
        config,
        config_path=selection,
        platform_data_root=platform_data_root,
        env=env,
    )


def test_runtime_paths_resolve_every_relative_class_without_using_cwd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config_file = _config_file(tmp_path)
    decoy = tmp_path / "decoy"
    decoy.mkdir()
    monkeypatch.chdir(decoy)

    resolved = resolve_runtime_paths(
        _config(env_files=["../secrets/runtime.env"]),
        config_path=config_file,
        platform_data_root=tmp_path / "platform",
        env={},
    )

    state_root = tmp_path / "config/state"
    assert resolved.config_file == config_file
    assert resolved.config_dir == config_file.parent
    assert resolved.state_root == state_root
    assert resolved.spool == state_root / "spool"
    assert resolved.reports == state_root / "reports"
    assert resolved.logs == state_root / "logs"
    assert resolved.backups == state_root / "backups"
    assert resolved.pseudonym_key == state_root / "control/pseudonym.key"
    assert resolved.configured_env_files == (tmp_path / "secrets/runtime.env",)
    assert decoy not in resolved.state_root.parents


def test_milhouse_home_precedes_configured_and_platform_homes(tmp_path: Path) -> None:
    config_file = _config_file(tmp_path)
    override = tmp_path / "override"

    resolved = resolve_runtime_paths(
        _config(home="configured"),
        config_path=config_file,
        platform_data_root=tmp_path / "platform",
        env={MILHOUSE_HOME_ENV_VAR: os.fspath(override)},
    )

    assert resolved.state_root == override


def test_empty_milhouse_home_does_not_override_configured_home(tmp_path: Path) -> None:
    config_file = _config_file(tmp_path)

    resolved = resolve_runtime_paths(
        _config(home="configured"),
        config_path=config_file,
        platform_data_root=tmp_path / "platform",
        env={MILHOUSE_HOME_ENV_VAR: ""},
    )

    assert resolved.state_root == config_file.parent / "configured"


def test_filesystem_root_cannot_be_used_as_state_root(tmp_path: Path) -> None:
    config_file = _config_file(tmp_path)
    filesystem_root = Path(config_file.anchor)

    with pytest.raises(ConfigError) as excinfo:
        resolve_runtime_paths(
            _config(),
            config_path=config_file,
            platform_data_root=tmp_path / "platform",
            env={MILHOUSE_HOME_ENV_VAR: os.fspath(filesystem_root)},
        )

    assert excinfo.value.code == "config.path.unsafe_root"


def test_configured_filesystem_root_cannot_be_used_as_state_root(tmp_path: Path) -> None:
    config_file = _config_file(tmp_path)

    with pytest.raises(ConfigError) as excinfo:
        resolve_runtime_paths(
            _config(home=os.fspath(Path(config_file.anchor))),
            config_path=config_file,
            platform_data_root=tmp_path / "platform",
            env={},
        )

    assert excinfo.value.code == "config.path.unsafe_root"


def test_relative_milhouse_home_is_rejected_without_using_cwd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config_file = _config_file(tmp_path)
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    monkeypatch.chdir(cwd)

    with pytest.raises(ConfigError) as excinfo:
        resolve_runtime_paths(
            _config(home="configured"),
            config_path=config_file,
            platform_data_root=tmp_path / "platform",
            env={MILHOUSE_HOME_ENV_VAR: "runtime-override"},
        )

    assert excinfo.value.code == "config.path.not_absolute"
    assert os.fspath(cwd) not in str(excinfo.value)


def test_absolute_runtime_children_inside_state_root_are_accepted(tmp_path: Path) -> None:
    config_file = _config_file(tmp_path)
    state_root = config_file.parent / "state"

    resolved = resolve_runtime_paths(
        _config(
            spool=os.fspath(state_root / "custom-spool"),
            pseudonym_key_path=os.fspath(state_root / "keys/install.key"),
        ),
        config_path=config_file,
        platform_data_root=tmp_path / "platform",
        env={},
    )

    assert resolved.spool == state_root / "custom-spool"
    assert resolved.pseudonym_key == state_root / "keys/install.key"


@pytest.mark.parametrize("field", ["spool", "reports", "logs", "backups"])
def test_absolute_runtime_directory_outside_state_root_is_rejected(
    tmp_path: Path, field: str
) -> None:
    config_file = _config_file(tmp_path)
    overrides = {field: os.fspath(tmp_path / "outside" / field)}

    with pytest.raises(ConfigError) as excinfo:
        resolve_runtime_paths(
            _config(**overrides),  # type: ignore[arg-type]
            config_path=config_file,
            platform_data_root=tmp_path / "platform",
            env={},
        )

    assert excinfo.value.code == "config.path.escape"
    assert os.fspath(tmp_path) not in str(excinfo.value)


def test_pseudonym_key_outside_state_root_is_rejected(tmp_path: Path) -> None:
    config_file = _config_file(tmp_path)

    with pytest.raises(ConfigError) as excinfo:
        resolve_runtime_paths(
            _config(pseudonym_key_path=os.fspath(tmp_path / "outside.key")),
            config_path=config_file,
            platform_data_root=tmp_path / "platform",
            env={},
        )

    assert excinfo.value.code == "config.path.escape"


@pytest.mark.parametrize("field", ["spool", "reports", "logs", "backups"])
def test_runtime_directory_equal_to_state_root_is_rejected(tmp_path: Path, field: str) -> None:
    config_file = _config_file(tmp_path)
    state_root = config_file.parent / "state"

    with pytest.raises(ConfigError) as excinfo:
        resolve_runtime_paths(
            _config(**{field: os.fspath(state_root)}),  # type: ignore[arg-type]
            config_path=config_file,
            platform_data_root=tmp_path / "platform",
            env={},
        )

    assert excinfo.value.code == "config.path.escape"


def test_existing_symlink_component_beneath_state_root_is_rejected(tmp_path: Path) -> None:
    config_file = _config_file(tmp_path)
    state_root = config_file.parent / "state"
    state_root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (state_root / "redirect").symlink_to(outside, target_is_directory=True)

    with pytest.raises(ConfigError) as excinfo:
        resolve_runtime_paths(
            _config(spool="redirect/spool"),
            config_path=config_file,
            platform_data_root=tmp_path / "platform",
            env={},
        )

    assert excinfo.value.code == "config.path.symlink"
    assert os.fspath(outside) not in str(excinfo.value)


def test_existing_runtime_directory_must_be_a_directory(tmp_path: Path) -> None:
    config_file = _config_file(tmp_path)
    state_root = config_file.parent / "state"
    state_root.mkdir()
    (state_root / "spool").write_text("not a directory", encoding="utf-8")

    with pytest.raises(ConfigError) as excinfo:
        resolve_runtime_paths(
            _config(),
            config_path=config_file,
            platform_data_root=tmp_path / "platform",
            env={},
        )

    assert excinfo.value.code == "config.path.not_directory"


def test_runtime_child_rejects_a_non_directory_intermediate_component(tmp_path: Path) -> None:
    config_file = _config_file(tmp_path)
    state_root = config_file.parent / "state"
    state_root.mkdir()
    (state_root / "blocked").write_text("not a directory", encoding="utf-8")

    with pytest.raises(ConfigError) as excinfo:
        resolve_runtime_paths(
            _config(spool="blocked/spool"),
            config_path=config_file,
            platform_data_root=tmp_path / "platform",
            env={},
        )

    assert excinfo.value.code == "config.path.not_directory"


def test_existing_pseudonym_key_must_be_a_regular_file(tmp_path: Path) -> None:
    config_file = _config_file(tmp_path)
    key_dir = config_file.parent / "state/control/pseudonym.key"
    key_dir.mkdir(parents=True)

    with pytest.raises(ConfigError) as excinfo:
        resolve_runtime_paths(
            _config(),
            config_path=config_file,
            platform_data_root=tmp_path / "platform",
            env={},
        )

    assert excinfo.value.code == "config.path.not_file"


def test_config_source_allows_parent_relative_paths_without_cwd_lookup(tmp_path: Path) -> None:
    config_dir = tmp_path / "nested/config"
    config_dir.mkdir(parents=True)

    resolved = resolve_config_source_path("../../shared/runtime.env", config_dir=config_dir)

    assert resolved == tmp_path / "shared/runtime.env"


def test_config_source_rejects_a_symlinked_file(tmp_path: Path) -> None:
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    target = tmp_path / "runtime.env"
    target.write_text("NAME=value\n", encoding="utf-8")
    link = config_dir / "runtime.env"
    link.symlink_to(target)

    with pytest.raises(ConfigError) as excinfo:
        resolve_config_source_path("runtime.env", config_dir=config_dir)

    assert excinfo.value.code == "config.path.symlink"


def test_config_source_rejects_a_preexisting_parent_symlink(tmp_path: Path) -> None:
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "runtime.env").write_text("NAME=private\n", encoding="utf-8")
    (config_dir / "selected").symlink_to(outside, target_is_directory=True)

    with pytest.raises(ConfigError) as excinfo:
        resolve_config_source_path("selected/runtime.env", config_dir=config_dir)

    assert excinfo.value.code == "config.path.symlink"
    assert os.fspath(outside) not in str(excinfo.value)


def test_absolute_config_source_rejects_a_preexisting_parent_symlink(tmp_path: Path) -> None:
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "runtime.env").write_text("NAME=private\n", encoding="utf-8")
    linked_parent = tmp_path / "linked-parent"
    linked_parent.symlink_to(outside, target_is_directory=True)

    with pytest.raises(ConfigError) as excinfo:
        resolve_config_source_path(linked_parent / "runtime.env", config_dir=config_dir)

    assert excinfo.value.code == "config.path.symlink"
    assert os.fspath(outside) not in str(excinfo.value)


def test_config_source_leaf_swap_is_never_canonicalized_to_the_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    source = config_dir / "runtime.env"
    source.write_text("NAME=original\n", encoding="utf-8")
    target = tmp_path / "target.env"
    target.write_text("NAME=private\n", encoding="utf-8")
    original_check = config_paths._require_symlink_free_source_path

    def swap_after_check(path: Path) -> Path:
        result = original_check(path)
        if result == source:
            source.unlink()
            source.symlink_to(target)
        return result

    monkeypatch.setattr(config_paths, "_require_symlink_free_source_path", swap_after_check)

    resolved = resolve_config_source_path("runtime.env", config_dir=config_dir)

    assert resolved == source
    assert resolved != target


def test_selected_config_leaf_swap_is_rejected_after_selection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config_file = _config_file(tmp_path)
    target = tmp_path / "target.toml"
    target.write_text("config_version = 1\n", encoding="utf-8")
    original_verify = config_paths.verify_config_generation
    calls = 0

    def swap_after_selection(config: MilhouseConfig, selection: ConfigFileSelection):
        nonlocal calls
        result = original_verify(config, selection)
        calls += 1
        if calls == 1:
            config_file.unlink()
            config_file.symlink_to(target)
        return result

    monkeypatch.setattr(config_paths, "verify_config_generation", swap_after_selection)

    with pytest.raises(ConfigError) as excinfo:
        resolve_runtime_paths(
            _config(),
            config_path=config_file,
            platform_data_root=tmp_path / "platform",
            env={},
        )

    assert excinfo.value.code == "config.file.changed"
    assert os.fspath(target) not in str(excinfo.value)


def test_runtime_paths_require_a_bound_config_generation(tmp_path: Path) -> None:
    config_file = _config_file(tmp_path)

    with pytest.raises(ConfigError) as excinfo:
        _resolve_runtime_paths(
            _config(),
            config_path=config_file,  # type: ignore[arg-type]
            platform_data_root=tmp_path / "platform",
            env={},
        )

    assert excinfo.value.code == "config.selection.required"


def test_runtime_paths_reject_a_selection_bound_to_another_config(tmp_path: Path) -> None:
    config_file = _config_file(tmp_path)
    first = _config(home="first-state")
    second = _config(home="second-state")
    second_selection = _bound_selection(second, config_file)

    with pytest.raises(ConfigError) as excinfo:
        _resolve_runtime_paths(
            first,
            config_path=second_selection,
            platform_data_root=tmp_path / "platform",
            env={},
        )

    assert excinfo.value.code == "config.selection.mismatch"


def test_runtime_paths_reject_a_model_changed_after_selection(tmp_path: Path) -> None:
    config_file = _config_file(tmp_path)
    original = _config(home="original-state")
    selection = _bound_selection(original, config_file)
    changed = original.model_copy(
        update={"paths": original.paths.model_copy(update={"home": "changed-state"})}
    )

    with pytest.raises(ConfigError) as excinfo:
        _resolve_runtime_paths(
            changed,
            config_path=selection,
            platform_data_root=tmp_path / "platform",
            env={},
        )

    assert excinfo.value.code == "config.selection.mismatch"


def test_selected_config_rejects_a_symlinked_parent(tmp_path: Path) -> None:
    real_config_dir = tmp_path / "real-config"
    real_config_dir.mkdir()
    config_file = real_config_dir / "milhouse.toml"
    config_file.write_text("config_version = 1\n", encoding="utf-8")
    linked_config_dir = tmp_path / "linked-config"
    linked_config_dir.symlink_to(real_config_dir, target_is_directory=True)

    with pytest.raises(ConfigError) as excinfo:
        load_config_file(linked_config_dir / "milhouse.toml")

    assert excinfo.value.code == "config.file.not_regular"
    assert os.fspath(real_config_dir) not in str(excinfo.value)


def test_relative_home_refuses_a_config_parent_swapped_after_path_selection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config_file = _config_file(tmp_path)
    config_dir = config_file.parent
    original_dir = tmp_path / "original-config"
    outside = tmp_path / "outside"
    (outside / "state").mkdir(parents=True)
    original_check = config_paths._require_symlink_free_source_path
    swapped = False

    def swap_after_home_check(path: Path) -> Path:
        nonlocal swapped
        result = original_check(path)
        if not swapped and result == config_dir / "state":
            config_dir.rename(original_dir)
            config_dir.symlink_to(outside, target_is_directory=True)
            swapped = True
        return result

    monkeypatch.setattr(config_paths, "_require_symlink_free_source_path", swap_after_home_check)

    with pytest.raises(ConfigError) as excinfo:
        resolve_runtime_paths(
            _config(home="state"),
            config_path=config_file,
            platform_data_root=tmp_path / "platform",
            env={},
        )

    assert swapped
    assert excinfo.value.code == "config.file.changed"
    assert os.fspath(outside) not in str(excinfo.value)


def test_runtime_paths_repr_never_contains_local_paths(tmp_path: Path) -> None:
    config_file = _config_file(tmp_path)
    resolved = resolve_runtime_paths(
        _config(),
        config_path=config_file,
        platform_data_root=tmp_path / "platform",
        env={},
    )

    rendered = repr(resolved)

    assert rendered == "RuntimePaths(resolved=True, configured_env_files=0)"
    assert os.fspath(tmp_path) not in rendered
    assert str(resolved) == rendered
    assert isinstance(resolved, RuntimePaths)


def test_runtime_paths_are_immutable(tmp_path: Path) -> None:
    config_file = _config_file(tmp_path)
    resolved = resolve_runtime_paths(
        _config(),
        config_path=config_file,
        platform_data_root=tmp_path / "platform",
        env={},
    )

    with pytest.raises((AttributeError, TypeError)):
        resolved.state_root = tmp_path / "replacement"  # type: ignore[misc]


def test_relative_selected_config_path_is_canonicalized_from_an_explicit_input(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config_file = _config_file(tmp_path)
    monkeypatch.chdir(tmp_path)

    resolved = resolve_runtime_paths(
        _config(),
        config_path=config_file.relative_to(tmp_path),
        platform_data_root=tmp_path / "platform",
        env={},
    )

    assert resolved.config_file == config_file


def test_missing_selected_config_file_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ConfigError) as excinfo:
        load_config_file(tmp_path / "missing.toml")

    assert excinfo.value.code == "config.file.not_found"


def test_selected_config_path_must_be_a_regular_file(tmp_path: Path) -> None:
    config_dir = tmp_path / "config"
    config_dir.mkdir()

    with pytest.raises(ConfigError) as excinfo:
        load_config_file(config_dir)

    assert excinfo.value.code == "config.file.not_regular"


def test_absolute_configured_home_is_accepted(tmp_path: Path) -> None:
    config_file = _config_file(tmp_path)
    absolute_home = tmp_path / "absolute-state"

    resolved = resolve_runtime_paths(
        _config(home=os.fspath(absolute_home)),
        config_path=config_file,
        platform_data_root=tmp_path / "platform",
        env={},
    )

    assert resolved.state_root == absolute_home


def test_platform_data_fallback_is_absolute_and_cwd_independent(tmp_path: Path) -> None:
    config_file = _config_file(tmp_path)
    config = _config().model_copy(update={"paths": _config().paths.model_copy(update={"home": ""})})

    resolved = resolve_runtime_paths(
        config,
        config_path=config_file,
        platform_data_root=tmp_path / "platform",
        env={},
    )

    assert resolved.state_root == tmp_path / "platform"


def test_relative_platform_data_fallback_is_rejected(tmp_path: Path) -> None:
    config_file = _config_file(tmp_path)
    config = _config().model_copy(update={"paths": _config().paths.model_copy(update={"home": ""})})

    with pytest.raises(ConfigError) as excinfo:
        resolve_runtime_paths(
            config,
            config_path=config_file,
            platform_data_root="relative-platform",
            env={},
        )

    assert excinfo.value.code == "config.path.not_absolute"


def test_process_environment_is_used_when_no_mapping_is_injected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config_file = _config_file(tmp_path)
    state_root = tmp_path / "process-state"
    monkeypatch.setenv(MILHOUSE_HOME_ENV_VAR, os.fspath(state_root))

    resolved = resolve_runtime_paths(
        _config(),
        config_path=config_file,
        platform_data_root=tmp_path / "platform",
    )

    assert resolved.state_root == state_root


def test_existing_regular_pseudonym_key_is_accepted(tmp_path: Path) -> None:
    config_file = _config_file(tmp_path)
    key = config_file.parent / "state/control/pseudonym.key"
    key.parent.mkdir(parents=True)
    key.write_bytes(b"x" * 32)

    resolved = resolve_runtime_paths(
        _config(),
        config_path=config_file,
        platform_data_root=tmp_path / "platform",
        env={},
    )

    assert resolved.pseudonym_key == key


def test_non_directory_parent_is_rejected_before_a_leaf_is_resolved(tmp_path: Path) -> None:
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    (config_dir / "blocked").write_text("file", encoding="utf-8")

    with pytest.raises(ConfigError) as excinfo:
        resolve_config_source_path("blocked/source.env", config_dir=config_dir)

    assert excinfo.value.code == "config.path.not_directory"


def test_relative_config_directory_argument_is_rejected() -> None:
    with pytest.raises(ConfigError) as excinfo:
        resolve_config_source_path("source.env", config_dir=Path("relative-config"))

    assert excinfo.value.code == "config.path.not_absolute"


def test_path_normalization_failure_is_value_safe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    private_fragment = "private-path-fragment-0123456789"

    def fail_normalization(_value: str) -> str:
        raise ValueError(private_fragment)

    monkeypatch.setattr(config_paths.os.path, "normpath", fail_normalization)

    with pytest.raises(ConfigError) as excinfo:
        resolve_config_source_path(tmp_path / "source.env", config_dir=tmp_path)

    assert excinfo.value.code == "config.path.invalid"
    assert private_fragment not in str(excinfo.value)


def test_path_inspection_oserror_is_value_safe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    private_fragment = "private-path-fragment-0123456789"

    def fail_lstat(_value: str | os.PathLike[str]) -> os.stat_result:
        raise OSError(private_fragment)

    monkeypatch.setattr(config_paths.os, "lstat", fail_lstat)

    with pytest.raises(ConfigError) as excinfo:
        resolve_config_source_path(tmp_path / "source.env", config_dir=tmp_path)

    assert excinfo.value.code == "config.path.unreadable"
    assert private_fragment not in str(excinfo.value)
