from __future__ import annotations

import errno
import os
import stat
import traceback
from dataclasses import replace
from pathlib import Path

import pytest

import milhouse.config.filesystem as config_filesystem
import milhouse.config.secrets as config_secrets
from milhouse.config import ConfigError, load_config_file
from milhouse.config.filesystem import inspect_regular_file_no_follow
from milhouse.config.loader import ConfigFileSelection, validated_config_digest
from milhouse.config.paths import resolve_runtime_paths as _resolve_runtime_paths
from milhouse.config.secrets import (
    MAX_ENV_FILE_BYTES,
    MAX_ENV_FILE_ENTRIES,
    MAX_SECRET_VALUE_CHARS,
    SecretEnvironment,
    SecretSourceKind,
    collect_secret_references,
    load_secret_environment,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
BASE_CONFIG = load_config_file(REPOSITORY_ROOT / "config/examples/local-only.toml")
REFERENCES = {
    "MILHOUSE_CLICKHOUSE_PASSWORD",
    "MILHOUSE_CLICKHOUSE_URL",
    "MILHOUSE_CLICKHOUSE_USER",
}


def _runtime(tmp_path: Path, *, env_files: list[str] | None = None):
    config_dir = tmp_path / "config"
    config_dir.mkdir(exist_ok=True)
    config_file = config_dir / "milhouse.toml"
    config_file.write_text("config_version = 1\n", encoding="utf-8")
    paths = BASE_CONFIG.paths.model_copy(update={"home": "state"})
    secrets = BASE_CONFIG.secrets.model_copy(update={"env_files": env_files or []})
    config = BASE_CONFIG.model_copy(update={"paths": paths, "secrets": secrets})
    selected = inspect_regular_file_no_follow(config_file)
    selection = ConfigFileSelection(
        path=selected.path,
        parent_identity=selected.parent_identity,
        snapshot=selected.snapshot,
        config_digest=validated_config_digest(config),
    )
    resolved = _resolve_runtime_paths(
        config,
        config_path=selection,
        platform_data_root=tmp_path / "platform",
        env={},
    )
    return config, resolved


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def test_collect_secret_references_finds_nested_config_references_only() -> None:
    assert collect_secret_references(BASE_CONFIG) == frozenset(REFERENCES)


def test_process_environment_has_highest_precedence(tmp_path: Path) -> None:
    config, paths = _runtime(tmp_path, env_files=["configured.env"])
    explicit = _write(paths.config_dir / "explicit.env", "MILHOUSE_CLICKHOUSE_URL=cli\n")
    _write(paths.config_dir / "configured.env", "MILHOUSE_CLICKHOUSE_URL=configured\n")

    loaded = load_secret_environment(
        config,
        paths,
        process_env={"MILHOUSE_CLICKHOUSE_URL": "process"},
        explicit_env_file=explicit,
    )

    assert loaded.get("MILHOUSE_CLICKHOUSE_URL") == "process"
    assert loaded.source("MILHOUSE_CLICKHOUSE_URL").kind is SecretSourceKind.PROCESS


def test_explicit_env_file_precedes_configured_files(tmp_path: Path) -> None:
    config, paths = _runtime(tmp_path, env_files=["first.env", "second.env"])
    _write(paths.config_dir / "first.env", "MILHOUSE_CLICKHOUSE_URL=first\n")
    _write(paths.config_dir / "second.env", "MILHOUSE_CLICKHOUSE_URL=second\n")
    _write(paths.config_dir / "explicit.env", "MILHOUSE_CLICKHOUSE_URL=explicit\n")

    loaded = load_secret_environment(
        config,
        paths,
        process_env={},
        explicit_env_file="explicit.env",
    )

    assert loaded.get("MILHOUSE_CLICKHOUSE_URL") == "explicit"
    assert loaded.source("MILHOUSE_CLICKHOUSE_URL").kind is SecretSourceKind.CLI_ENV_FILE


def test_earliest_configured_env_file_wins(tmp_path: Path) -> None:
    config, paths = _runtime(tmp_path, env_files=["first.env", "second.env"])
    _write(paths.config_dir / "first.env", "MILHOUSE_CLICKHOUSE_URL=first\n")
    _write(paths.config_dir / "second.env", "MILHOUSE_CLICKHOUSE_URL=second\n")

    loaded = load_secret_environment(config, paths, process_env={})

    assert loaded.get("MILHOUSE_CLICKHOUSE_URL") == "first"
    source = loaded.source("MILHOUSE_CLICKHOUSE_URL")
    assert source.kind is SecretSourceKind.CONFIG_ENV_FILE
    assert source.ordinal == 1


def test_loader_retains_only_config_referenced_names(tmp_path: Path) -> None:
    config, paths = _runtime(tmp_path, env_files=["runtime.env"])
    _write(
        paths.config_dir / "runtime.env",
        "MILHOUSE_CLICKHOUSE_URL=selected\nUNRELATED_PRIVATE_VALUE=discarded\n",
    )

    loaded = load_secret_environment(config, paths, process_env={})

    assert loaded.get("MILHOUSE_CLICKHOUSE_URL") == "selected"
    assert loaded.get("UNRELATED_PRIVATE_VALUE") is None
    assert loaded.source("UNRELATED_PRIVATE_VALUE") is None
    assert len(loaded) == 1


def test_explicit_empty_value_is_present_and_not_overwritten(tmp_path: Path) -> None:
    config, paths = _runtime(tmp_path, env_files=["configured.env"])
    explicit = _write(paths.config_dir / "explicit.env", "MILHOUSE_CLICKHOUSE_URL=\n")
    _write(paths.config_dir / "configured.env", "MILHOUSE_CLICKHOUSE_URL=configured\n")

    loaded = load_secret_environment(config, paths, process_env={}, explicit_env_file=explicit)

    assert loaded.get("MILHOUSE_CLICKHOUSE_URL") == ""
    assert loaded.source("MILHOUSE_CLICKHOUSE_URL").kind is SecretSourceKind.CLI_ENV_FILE


def test_missing_value_uses_a_stable_value_free_error(tmp_path: Path) -> None:
    config, paths = _runtime(tmp_path)
    loaded = load_secret_environment(config, paths, process_env={})

    with pytest.raises(ConfigError) as excinfo:
        loaded.require("MILHOUSE_CLICKHOUSE_PASSWORD")

    assert excinfo.value.code == "secrets.value.missing"
    assert "MILHOUSE_CLICKHOUSE_PASSWORD" not in str(excinfo.value)


def test_secret_environment_repr_and_str_never_include_names_values_or_paths(
    tmp_path: Path,
) -> None:
    config, paths = _runtime(tmp_path)
    private_value = "runtime-private-value-0123456789"
    loaded = load_secret_environment(
        config,
        paths,
        process_env={"MILHOUSE_CLICKHOUSE_PASSWORD": private_value},
    )

    assert repr(loaded) == "SecretEnvironment(resolved=1)"
    assert str(loaded) == "SecretEnvironment(resolved=1)"
    assert private_value not in repr(loaded)
    assert "MILHOUSE_CLICKHOUSE_PASSWORD" not in repr(loaded)
    assert os.fspath(tmp_path) not in repr(loaded)
    assert isinstance(loaded, SecretEnvironment)


def test_secret_source_repr_contains_only_category_and_ordinal(tmp_path: Path) -> None:
    config, paths = _runtime(tmp_path, env_files=["runtime.env"])
    _write(paths.config_dir / "runtime.env", "MILHOUSE_CLICKHOUSE_URL=private\n")

    loaded = load_secret_environment(config, paths, process_env={})

    assert repr(loaded.source("MILHOUSE_CLICKHOUSE_URL")) == (
        "SecretSource(kind='config_env_file', ordinal=1)"
    )


def test_loading_never_mutates_process_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config, paths = _runtime(tmp_path, env_files=["runtime.env"])
    _write(paths.config_dir / "runtime.env", "MILHOUSE_CLICKHOUSE_URL=file-value\n")
    monkeypatch.delenv("MILHOUSE_CLICKHOUSE_URL", raising=False)

    loaded = load_secret_environment(config, paths, process_env={})

    assert loaded.get("MILHOUSE_CLICKHOUSE_URL") == "file-value"
    assert "MILHOUSE_CLICKHOUSE_URL" not in os.environ


def test_unselected_dotenv_is_never_discovered(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config, paths = _runtime(tmp_path)
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    _write(cwd / ".env", "MILHOUSE_CLICKHOUSE_URL=decoy\n")
    monkeypatch.chdir(cwd)

    loaded = load_secret_environment(config, paths, process_env={})

    assert loaded.get("MILHOUSE_CLICKHOUSE_URL") is None


def test_dotenv_interpolation_is_disabled(tmp_path: Path) -> None:
    config, paths = _runtime(tmp_path, env_files=["runtime.env"])
    _write(paths.config_dir / "runtime.env", "MILHOUSE_CLICKHOUSE_URL=${OTHER_VALUE}\n")

    loaded = load_secret_environment(config, paths, process_env={"OTHER_VALUE": "must-not-expand"})

    assert loaded.get("MILHOUSE_CLICKHOUSE_URL") == "${OTHER_VALUE}"


def test_export_and_quoted_multiline_values_use_explicit_dotenv_parsing(tmp_path: Path) -> None:
    config, paths = _runtime(tmp_path, env_files=["runtime.env"])
    _write(
        paths.config_dir / "runtime.env",
        'export MILHOUSE_CLICKHOUSE_URL="line-one\\nline-two"\n',
    )

    loaded = load_secret_environment(config, paths, process_env={})

    assert loaded.get("MILHOUSE_CLICKHOUSE_URL") == "line-one\nline-two"


@pytest.mark.parametrize(
    ("contents", "code"),
    [
        ("not valid !\n", "secrets.file.syntax"),
        ("MILHOUSE_CLICKHOUSE_URL\n", "secrets.file.syntax"),
        (
            "MILHOUSE_CLICKHOUSE_URL=one\nMILHOUSE_CLICKHOUSE_URL=two\n",
            "secrets.file.duplicate",
        ),
        ("INVALID-NAME=value\n", "secrets.file.name_invalid"),
    ],
)
def test_invalid_env_documents_fail_closed_without_echoing_content(
    tmp_path: Path, contents: str, code: str
) -> None:
    config, paths = _runtime(tmp_path, env_files=["runtime.env"])
    private_value = "private-fragment-0123456789"
    path = _write(paths.config_dir / "runtime.env", contents + f"# {private_value}\n")

    with pytest.raises(ConfigError) as excinfo:
        load_secret_environment(config, paths, process_env={})

    rendered = "".join(traceback.format_exception(excinfo.value))
    assert excinfo.value.code == code
    assert private_value not in rendered
    assert os.fspath(path) not in rendered
    assert excinfo.value.__cause__ is None
    assert excinfo.value.__context__ is None


def test_missing_selected_env_file_is_a_stable_error(tmp_path: Path) -> None:
    config, paths = _runtime(tmp_path, env_files=["missing.env"])

    with pytest.raises(ConfigError) as excinfo:
        load_secret_environment(config, paths, process_env={})

    assert excinfo.value.code == "secrets.file.not_found"
    assert os.fspath(tmp_path) not in str(excinfo.value)


def test_selected_env_file_must_be_regular(tmp_path: Path) -> None:
    config, paths = _runtime(tmp_path, env_files=["directory.env"])
    (paths.config_dir / "directory.env").mkdir()

    with pytest.raises(ConfigError) as excinfo:
        load_secret_environment(config, paths, process_env={})

    assert excinfo.value.code == "secrets.file.not_regular"


def test_selected_env_file_must_be_utf8(tmp_path: Path) -> None:
    config, paths = _runtime(tmp_path, env_files=["runtime.env"])
    (paths.config_dir / "runtime.env").write_bytes(b"MILHOUSE_CLICKHOUSE_URL=\xff\xfe")

    with pytest.raises(ConfigError) as excinfo:
        load_secret_environment(config, paths, process_env={})

    assert excinfo.value.code == "secrets.file.unreadable"


def test_selected_env_file_is_bounded(tmp_path: Path) -> None:
    config, paths = _runtime(tmp_path, env_files=["runtime.env"])
    (paths.config_dir / "runtime.env").write_bytes(b"#" * (MAX_ENV_FILE_BYTES + 1))

    with pytest.raises(ConfigError) as excinfo:
        load_secret_environment(config, paths, process_env={})

    assert excinfo.value.code == "secrets.file.too_large"


def test_higher_priority_values_avoid_opening_unneeded_lower_priority_files(
    tmp_path: Path,
) -> None:
    config, paths = _runtime(tmp_path, env_files=["missing.env"])

    loaded = load_secret_environment(
        config,
        paths,
        process_env={name: f"process-{index}" for index, name in enumerate(REFERENCES)},
    )

    assert len(loaded) == len(REFERENCES)


def test_secret_environment_is_not_serializable_as_a_plain_mapping(tmp_path: Path) -> None:
    config, paths = _runtime(tmp_path)
    loaded = load_secret_environment(
        config,
        paths,
        process_env={"MILHOUSE_CLICKHOUSE_PASSWORD": "private"},
    )

    with pytest.raises(TypeError):
        dict(loaded)  # type: ignore[arg-type]

    with pytest.raises((AttributeError, TypeError)):
        loaded._values = {}  # type: ignore[misc]


def test_require_returns_a_present_secret_value(tmp_path: Path) -> None:
    config, paths = _runtime(tmp_path)
    loaded = load_secret_environment(
        config,
        paths,
        process_env={"MILHOUSE_CLICKHOUSE_PASSWORD": "private"},
    )

    assert loaded.require("MILHOUSE_CLICKHOUSE_PASSWORD") == "private"


def test_process_secret_source_repr_is_path_and_value_free(tmp_path: Path) -> None:
    config, paths = _runtime(tmp_path)
    loaded = load_secret_environment(
        config,
        paths,
        process_env={"MILHOUSE_CLICKHOUSE_PASSWORD": "private"},
    )

    assert repr(loaded.source("MILHOUSE_CLICKHOUSE_PASSWORD")) == (
        "SecretSource(kind='process', ordinal=None)"
    )


def test_collect_secret_references_walks_nonempty_mapping_fields() -> None:
    config = load_config_file(REPOSITORY_ROOT / "config/examples/ai-agent-workflows.toml")

    references = collect_secret_references(config)

    assert REFERENCES <= references


def test_valid_comments_and_empty_selected_file_are_accepted(tmp_path: Path) -> None:
    config, paths = _runtime(tmp_path, env_files=["runtime.env"])
    _write(paths.config_dir / "runtime.env", "# selected explicitly\n\n")

    loaded = load_secret_environment(config, paths, process_env={})

    assert len(loaded) == 0


def test_selected_env_file_entry_count_is_bounded(tmp_path: Path) -> None:
    config, paths = _runtime(tmp_path, env_files=["runtime.env"])
    rows = "".join(f"SAFE_NAME_{index}=value\n" for index in range(MAX_ENV_FILE_ENTRIES + 1))
    _write(paths.config_dir / "runtime.env", rows)

    with pytest.raises(ConfigError) as excinfo:
        load_secret_environment(config, paths, process_env={})

    assert excinfo.value.code == "secrets.file.too_many"


def test_resolved_paths_must_match_configured_env_file_count(tmp_path: Path) -> None:
    config, paths = _runtime(tmp_path)
    changed_paths = replace(
        paths,
        configured_env_files=(paths.config_dir / "added.env",),
    )

    with pytest.raises(ConfigError) as excinfo:
        load_secret_environment(config, changed_paths, process_env={})

    assert excinfo.value.code == "secrets.paths.mismatch"


def test_resolved_paths_must_match_the_exact_configured_env_file(tmp_path: Path) -> None:
    config, paths = _runtime(tmp_path, env_files=["first.env"])
    changed_paths = replace(
        paths,
        configured_env_files=(paths.config_dir / "second.env",),
    )

    with pytest.raises(ConfigError) as excinfo:
        load_secret_environment(config, changed_paths, process_env={})

    assert excinfo.value.code == "secrets.paths.mismatch"


def test_resolved_paths_must_match_configured_env_file_order(tmp_path: Path) -> None:
    config, paths = _runtime(tmp_path, env_files=["first.env", "second.env"])
    changed_paths = replace(paths, configured_env_files=tuple(reversed(paths.configured_env_files)))

    with pytest.raises(ConfigError) as excinfo:
        load_secret_environment(config, changed_paths, process_env={})

    assert excinfo.value.code == "secrets.paths.mismatch"


def test_non_text_process_value_is_rejected_without_rendering_it(tmp_path: Path) -> None:
    config, paths = _runtime(tmp_path)

    with pytest.raises(ConfigError) as excinfo:
        load_secret_environment(
            config,
            paths,
            process_env={"MILHOUSE_CLICKHOUSE_PASSWORD": object()},  # type: ignore[dict-item]
        )

    assert excinfo.value.code == "secrets.value.invalid"


def test_process_secret_value_is_bounded_without_rendering_it(tmp_path: Path) -> None:
    config, paths = _runtime(tmp_path)
    oversized = "x" * (MAX_SECRET_VALUE_CHARS + 1)

    with pytest.raises(ConfigError) as excinfo:
        load_secret_environment(
            config,
            paths,
            process_env={"MILHOUSE_CLICKHOUSE_PASSWORD": oversized},
        )

    assert excinfo.value.code == "secrets.value.too_large"
    assert oversized not in str(excinfo.value)


def test_env_file_secret_value_is_bounded_without_rendering_it(tmp_path: Path) -> None:
    config, paths = _runtime(tmp_path, env_files=["runtime.env"])
    oversized = "x" * (MAX_SECRET_VALUE_CHARS + 1)
    _write(paths.config_dir / "runtime.env", f"MILHOUSE_CLICKHOUSE_URL={oversized}\n")

    with pytest.raises(ConfigError) as excinfo:
        load_secret_environment(config, paths, process_env={})

    assert excinfo.value.code == "secrets.file.value_too_large"
    assert oversized not in str(excinfo.value)


def test_process_environment_is_used_when_no_mapping_is_injected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config, paths = _runtime(tmp_path)
    monkeypatch.setenv("MILHOUSE_CLICKHOUSE_URL", "process-private")

    loaded = load_secret_environment(config, paths)

    assert loaded.get("MILHOUSE_CLICKHOUSE_URL") == "process-private"


def test_first_configured_file_can_satisfy_every_reference_without_opening_later_file(
    tmp_path: Path,
) -> None:
    config, paths = _runtime(tmp_path, env_files=["complete.env", "missing.env"])
    _write(
        paths.config_dir / "complete.env",
        "\n".join(f"{name}=value-{index}" for index, name in enumerate(sorted(REFERENCES))) + "\n",
    )

    loaded = load_secret_environment(config, paths, process_env={})

    assert len(loaded) == len(REFERENCES)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFOs are unavailable")
def test_selected_env_file_rejects_a_fifo_without_blocking(tmp_path: Path) -> None:
    config, paths = _runtime(tmp_path, env_files=["runtime.env"])
    os.mkfifo(paths.config_dir / "runtime.env")

    with pytest.raises(ConfigError) as excinfo:
        load_secret_environment(config, paths, process_env={})

    assert excinfo.value.code == "secrets.file.not_regular"


def test_selected_env_file_rejects_a_symlink_created_after_path_resolution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config, paths = _runtime(tmp_path, env_files=["runtime.env"])
    target = _write(tmp_path / "target.env", "MILHOUSE_CLICKHOUSE_URL=private\n")
    source = paths.config_dir / "runtime.env"
    real_resolve = config_secrets.resolve_config_source_path

    def swap_after_resolution(value: str | Path, *, config_dir: Path) -> Path:
        result = real_resolve(value, config_dir=config_dir)
        source.symlink_to(target)
        return result

    monkeypatch.setattr(config_secrets, "resolve_config_source_path", swap_after_resolution)

    with pytest.raises(ConfigError) as excinfo:
        load_secret_environment(config, paths, process_env={})

    assert excinfo.value.code == "secrets.file.not_regular"


def test_selected_env_file_rejects_a_parent_symlink_created_after_resolution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config, paths = _runtime(tmp_path, env_files=["selected/runtime.env"])
    outside = tmp_path / "outside"
    outside.mkdir()
    _write(outside / "runtime.env", "MILHOUSE_CLICKHOUSE_URL=private\n")
    selected_parent = paths.config_dir / "selected"
    real_resolve = config_secrets.resolve_config_source_path

    def swap_after_resolution(value: str | Path, *, config_dir: Path) -> Path:
        result = real_resolve(value, config_dir=config_dir)
        selected_parent.symlink_to(outside, target_is_directory=True)
        return result

    monkeypatch.setattr(config_secrets, "resolve_config_source_path", swap_after_resolution)

    with pytest.raises(ConfigError) as excinfo:
        load_secret_environment(config, paths, process_env={})

    assert excinfo.value.code == "secrets.file.not_regular"
    assert os.fspath(outside) not in str(excinfo.value)


def test_selected_env_file_fails_closed_when_nofollow_is_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config, paths = _runtime(tmp_path, env_files=["runtime.env"])
    _write(paths.config_dir / "runtime.env", "MILHOUSE_CLICKHOUSE_URL=one\n")

    def unsupported(_path: str | Path):
        raise config_filesystem.SecureFileError(
            config_filesystem.SecureFileErrorKind.SECURITY_UNSUPPORTED
        )

    monkeypatch.setattr(config_secrets, "open_regular_file_no_follow", unsupported)

    with pytest.raises(ConfigError) as excinfo:
        load_secret_environment(config, paths, process_env={})

    assert excinfo.value.code == "secrets.file.security_unsupported"


def test_selected_env_file_detects_an_in_place_read_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _config, paths = _runtime(tmp_path, env_files=["runtime.env"])
    path = _write(paths.config_dir / "runtime.env", "MILHOUSE_CLICKHOUSE_URL=one\n")
    real_fstat = os.fstat
    initial = path.stat()
    regular_file_calls = 0

    def changed_after_read(descriptor: int) -> os.stat_result:
        nonlocal regular_file_calls
        metadata = real_fstat(descriptor)
        if stat.S_ISREG(metadata.st_mode):
            regular_file_calls += 1
        if regular_file_calls == 2:
            os.utime(path, ns=(initial.st_atime_ns, initial.st_mtime_ns + 1_000_000_000))
        return real_fstat(descriptor)

    monkeypatch.setattr(config_secrets.os, "fstat", changed_after_read)

    with pytest.raises(ConfigError) as excinfo:
        config_secrets._read_env_text(path)

    assert excinfo.value.code == "secrets.file.changed"


def test_selected_env_file_enforces_read_bound_after_fstat(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _config, paths = _runtime(tmp_path, env_files=["runtime.env"])
    path = paths.config_dir / "runtime.env"
    path.write_bytes(b"#" * (MAX_ENV_FILE_BYTES + 1))
    real_fstat = os.fstat

    def hidden_size(descriptor: int) -> os.stat_result:
        values = list(real_fstat(descriptor))
        values[6] = MAX_ENV_FILE_BYTES
        return os.stat_result(values)

    monkeypatch.setattr(config_secrets.os, "fstat", hidden_size)

    with pytest.raises(ConfigError) as excinfo:
        config_secrets._read_env_text(path)

    assert excinfo.value.code == "secrets.file.too_large"


def test_noncanonical_relative_resolved_env_path_fails_closed(tmp_path: Path) -> None:
    config, paths = _runtime(tmp_path, env_files=["runtime.env"])
    invalid_paths = replace(paths, configured_env_files=(Path("relative.env"),))

    with pytest.raises(ConfigError) as excinfo:
        load_secret_environment(config, invalid_paths, process_env={})

    assert excinfo.value.code == "secrets.paths.mismatch"


def test_directory_walk_rejects_a_non_directory_component_without_o_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    blocked = tmp_path / "blocked"
    blocked.write_text("not a directory", encoding="utf-8")
    monkeypatch.setattr(config_secrets.os, "O_DIRECTORY", 0, raising=False)

    with pytest.raises(ConfigError) as excinfo:
        config_secrets._read_env_text(blocked / "runtime.env")

    assert excinfo.value.code == "secrets.file.not_regular"


def test_no_nofollow_support_refuses_a_final_symlink_without_opening_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _config, paths = _runtime(tmp_path, env_files=["runtime.env"])
    target = _write(tmp_path / "target.env", "MILHOUSE_CLICKHOUSE_URL=private\n")
    selected = paths.config_dir / "runtime.env"
    selected.symlink_to(target)
    monkeypatch.setattr(config_filesystem.os, "O_NOFOLLOW", 0, raising=False)

    with pytest.raises(ConfigError) as excinfo:
        config_secrets._read_env_text(selected)

    assert excinfo.value.code == "secrets.file.security_unsupported"


def test_no_nofollow_support_refuses_a_parent_symlink_without_opening_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _config, paths = _runtime(tmp_path, env_files=["selected/runtime.env"])
    outside = tmp_path / "outside"
    outside.mkdir()
    target = _write(outside / "runtime.env", "MILHOUSE_CLICKHOUSE_URL=private\n")
    (paths.config_dir / "selected").symlink_to(outside, target_is_directory=True)
    monkeypatch.setattr(config_filesystem.os, "O_NOFOLLOW", 0, raising=False)

    with pytest.raises(ConfigError) as excinfo:
        config_secrets._read_env_text(paths.config_dir / "selected/runtime.env")

    assert excinfo.value.code == "secrets.file.security_unsupported"
    assert os.fspath(outside) not in str(excinfo.value)
    assert target.read_text(encoding="utf-8").endswith("private\n")


def test_no_nofollow_support_refuses_a_parent_swapped_after_resolution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _config, paths = _runtime(tmp_path, env_files=["selected/runtime.env"])
    outside = tmp_path / "outside"
    outside.mkdir()
    target = _write(outside / "runtime.env", "MILHOUSE_CLICKHOUSE_URL=private\n")
    selected_parent = paths.config_dir / "selected"
    selected = selected_parent / "runtime.env"
    selected_parent.symlink_to(outside, target_is_directory=True)
    monkeypatch.setattr(config_filesystem.os, "O_NOFOLLOW", 0, raising=False)

    with pytest.raises(ConfigError) as excinfo:
        config_secrets._read_env_text(selected)

    assert excinfo.value.code == "secrets.file.security_unsupported"
    assert os.fspath(outside) not in str(excinfo.value)
    assert target.read_text(encoding="utf-8").endswith("private\n")


def test_generic_env_open_failure_is_value_safe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _config, paths = _runtime(tmp_path, env_files=["runtime.env"])
    path = _write(paths.config_dir / "runtime.env", "MILHOUSE_CLICKHOUSE_URL=private\n")
    private_fragment = "private-open-fragment-0123456789"

    def fail_open(*_args: object, **_kwargs: object) -> int:
        raise OSError(errno.EACCES, private_fragment)

    monkeypatch.setattr(config_filesystem.os, "open", fail_open)

    with pytest.raises(ConfigError) as excinfo:
        config_secrets._read_env_text(path)

    assert excinfo.value.code == "secrets.file.unreadable"
    assert private_fragment not in str(excinfo.value)
