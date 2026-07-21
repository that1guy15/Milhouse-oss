import os
import stat
import traceback
from dataclasses import replace
from pathlib import Path

import pytest

import milhouse.config.filesystem as config_filesystem
import milhouse.config.loader as config_loader
from milhouse.config.loader import (
    CONFIG_PATH_ENV_VAR,
    MAX_CONFIG_BYTES,
    ConfigError,
    load_config,
    load_config_file,
    resolve_config_path,
)

_MINIMAL_CONFIG = """
config_version = 1

[project]
name = "team"
default_target = "app"
timezone = "UTC"

[paths]
home = "../data"
spool = "spool"
reports = "reports"
logs = "logs"
backups = "backups"

[secrets]
env_files = []

[identity]
pseudonym_key_path = "control/pseudonym.key"

[plugins]
allow_third_party = false

[runtime]
mode = "full"
log_level = "INFO"
max_batch_records = 500
max_batch_bytes = 5242880

[storage.clickhouse]
enabled = true
url_env = "MILHOUSE_CLICKHOUSE_URL"
username_env = "MILHOUSE_CLICKHOUSE_USER"
password_env = "MILHOUSE_CLICKHOUSE_PASSWORD"
database = "milhouse"
connect_timeout_seconds = 5

[privacy]
strict = true
agent_summaries_enabled = false
agent_trace_events_enabled = false
trace_excerpts_enabled = false
hash_local_paths = true

[retention]
events_days = 30
metrics_days = 90
runs_days = 180
alerts_days = 365
feedback_days = 365
agent_summaries_days = 30
trace_events_days = 14
reports_days = 90
logs_days = 14

[scheduler]
enabled = true
jitter_seconds = 5
shutdown_timeout_seconds = 30

[reports.daily]
enabled = true

[reports.weekly]
enabled = true

[mcp]
enabled = true
transport = "stdio"
allow_writes = false
default_limit = 100
maximum_limit = 500
maximum_window_days = 30

[postmortem]
auto_on_doh_marker = true
default_window_hours = 24
scan_project_docs = true

[receiver]
enabled = false
bind = "127.0.0.1"
port = 8787
allow_remote = false
max_body_bytes = 262144
requests_per_minute = 60
clock_skew_seconds = 300

[[targets]]
id = "app"
name = "App"
kind = "web_service"
environment = "production"
"""


def _write(path: Path, text: str = _MINIMAL_CONFIG) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


def test_load_config_file_accepts_a_valid_document(tmp_path: Path) -> None:
    config_path = _write(tmp_path / "milhouse.toml")

    config = load_config_file(config_path)

    assert config.project.name == "team"


def test_resolve_config_path_prefers_cli_over_env_and_default(tmp_path: Path) -> None:
    cli_path = tmp_path / "cli.toml"
    env_path = tmp_path / "env.toml"
    default_path = tmp_path / "default.toml"

    resolved = resolve_config_path(
        str(cli_path),
        platform_default=default_path,
        env={CONFIG_PATH_ENV_VAR: str(env_path)},
    )

    assert resolved == cli_path


def test_resolve_config_path_prefers_env_over_default(tmp_path: Path) -> None:
    env_path = tmp_path / "env.toml"
    default_path = tmp_path / "default.toml"

    resolved = resolve_config_path(
        None, platform_default=default_path, env={CONFIG_PATH_ENV_VAR: str(env_path)}
    )

    assert resolved == env_path


def test_resolve_config_path_falls_back_to_platform_default(tmp_path: Path) -> None:
    default_path = tmp_path / "default.toml"

    resolved = resolve_config_path(None, platform_default=default_path, env={})

    assert resolved == default_path


def test_resolve_config_path_ignores_empty_env_value(tmp_path: Path) -> None:
    default_path = tmp_path / "default.toml"

    resolved = resolve_config_path(
        None, platform_default=default_path, env={CONFIG_PATH_ENV_VAR: ""}
    )

    assert resolved == default_path


def test_resolve_config_path_rejects_empty_cli_value(tmp_path: Path) -> None:
    with pytest.raises(ConfigError) as excinfo:
        resolve_config_path("", platform_default=tmp_path / "default.toml", env={})

    assert excinfo.value.code == "config.path.invalid"


def test_resolve_config_path_never_searches_the_current_working_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    decoy_cwd = tmp_path / "cwd"
    decoy_cwd.mkdir()
    _write(decoy_cwd / "milhouse.toml")
    monkeypatch.chdir(decoy_cwd)

    default_path = tmp_path / "elsewhere" / "default.toml"
    resolved = resolve_config_path(None, platform_default=default_path, env={})

    assert resolved == default_path
    assert resolved != Path("milhouse.toml").resolve()


def test_resolve_config_path_uses_process_environment_by_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env_path = _write(tmp_path / "env.toml")
    monkeypatch.setenv(CONFIG_PATH_ENV_VAR, str(env_path))

    resolved = resolve_config_path(None, platform_default=tmp_path / "default.toml")

    assert resolved == env_path


def test_load_config_end_to_end_returns_config_and_resolved_path(tmp_path: Path) -> None:
    config_path = _write(tmp_path / "milhouse.toml")

    config, selection = load_config(
        str(config_path), platform_default=tmp_path / "default.toml", env={}
    )

    assert selection.path == config_path
    assert repr(selection) == "ConfigFileSelection(selected=True)"
    assert os.fspath(selection) == os.fspath(config_path)
    assert os.fspath(config_path) not in repr(selection)
    assert config.project.name == "team"


def test_config_open_unreadable_category_maps_to_a_stable_error() -> None:
    error = config_loader._config_open_error(
        config_filesystem.SecureFileError(config_filesystem.SecureFileErrorKind.UNREADABLE)
    )

    assert error.code == "config.file.unreadable"


def test_validated_config_digest_serialization_failure_is_value_safe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    private_fragment = "private-serialization-fragment-0123456789"
    config = load_config_file(_write(tmp_path / "config.toml"))

    def fail_dump(*_args: object, **_kwargs: object) -> dict[str, object]:
        raise TypeError(private_fragment)

    monkeypatch.setattr(type(config), "model_dump", fail_dump)

    with pytest.raises(ConfigError) as excinfo:
        config_loader.validated_config_digest(config)

    assert excinfo.value.code == "config.selection.mismatch"
    assert private_fragment not in str(excinfo.value)


def test_load_config_file_missing_is_a_stable_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigError) as excinfo:
        load_config_file(tmp_path / "missing.toml")

    assert excinfo.value.code == "config.file.not_found"


def test_load_config_file_rejects_symlinks(tmp_path: Path) -> None:
    target = _write(tmp_path / "real.toml")
    link = tmp_path / "link.toml"
    link.symlink_to(target)

    with pytest.raises(ConfigError) as excinfo:
        load_config_file(link)

    assert excinfo.value.code == "config.file.not_regular"


def test_load_config_file_rejects_symlinks_without_o_nofollow(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = _write(tmp_path / "real.toml")
    link = tmp_path / "link.toml"
    link.symlink_to(target)
    monkeypatch.setattr(config_filesystem.os, "O_NOFOLLOW", 0, raising=False)

    with pytest.raises(ConfigError) as excinfo:
        load_config_file(link)

    assert excinfo.value.code == "config.file.security_unsupported"


def test_load_config_file_fails_closed_without_nofollow_before_opening(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _write(tmp_path / "milhouse.toml")
    monkeypatch.setattr(config_filesystem.os, "O_NOFOLLOW", 0, raising=False)

    def fail_open(*_args: object, **_kwargs: object) -> int:
        raise AssertionError("config path must not be opened")

    monkeypatch.setattr(config_filesystem.os, "open", fail_open)

    with pytest.raises(ConfigError) as excinfo:
        load_config_file(path)

    assert excinfo.value.code == "config.file.security_unsupported"


def test_load_config_file_rejects_a_preexisting_parent_symlink_before_parsing(
    tmp_path: Path,
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    target = _write(outside / "milhouse.toml", "malformed target content !\n")
    linked_parent = tmp_path / "linked"
    linked_parent.symlink_to(outside, target_is_directory=True)

    with pytest.raises(ConfigError) as excinfo:
        load_config_file(linked_parent / "milhouse.toml")

    assert excinfo.value.code == "config.file.not_regular"
    assert os.fspath(target) not in str(excinfo.value)
    assert "malformed" not in str(excinfo.value)


def test_load_config_file_rejects_a_parent_swapped_during_selection_before_parsing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    selected_parent = tmp_path / "selected"
    selected_parent.mkdir()
    original = _write(selected_parent / "milhouse.toml")
    outside = tmp_path / "outside"
    outside.mkdir()
    target = _write(outside / "milhouse.toml", "malformed target content !\n")
    real_open = os.open
    swapped = False

    def swap_parent(
        candidate: str | bytes | os.PathLike[str],
        flags: int,
        *args: object,
        **kwargs: object,
    ) -> int:
        nonlocal swapped
        if not swapped and candidate == selected_parent.name:
            selected_parent.rename(tmp_path / "original-parent")
            selected_parent.symlink_to(outside, target_is_directory=True)
            swapped = True
        return real_open(candidate, flags, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(config_filesystem.os, "open", swap_parent)

    with pytest.raises(ConfigError) as excinfo:
        load_config_file(original)

    assert swapped
    assert excinfo.value.code == "config.file.not_regular"
    assert os.fspath(target) not in str(excinfo.value)
    assert "malformed" not in str(excinfo.value)


def test_load_config_file_rejects_a_parent_swapped_after_directory_open_before_parsing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    selected_parent = tmp_path / "selected"
    selected_parent.mkdir()
    original = _write(selected_parent / "milhouse.toml")
    outside = tmp_path / "outside"
    outside.mkdir()
    target = _write(outside / "milhouse.toml", "malformed target content !\n")
    real_open = os.open
    swapped = False

    def swap_after_parent_open(
        candidate: str | bytes | os.PathLike[str],
        flags: int,
        *args: object,
        **kwargs: object,
    ) -> int:
        nonlocal swapped
        if not swapped and candidate == original.name and kwargs.get("dir_fd") is not None:
            selected_parent.rename(tmp_path / "original-parent")
            selected_parent.symlink_to(outside, target_is_directory=True)
            swapped = True
        return real_open(candidate, flags, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(config_filesystem.os, "open", swap_after_parent_open)

    with pytest.raises(ConfigError) as excinfo:
        load_config_file(original)

    assert swapped
    assert excinfo.value.code == "config.file.changed"
    assert os.fspath(target) not in str(excinfo.value)
    assert "malformed" not in str(excinfo.value)


def test_load_config_file_rejects_directories(tmp_path: Path) -> None:
    directory = tmp_path / "a-directory.toml"
    directory.mkdir()

    with pytest.raises(ConfigError) as excinfo:
        load_config_file(directory)

    assert excinfo.value.code == "config.file.not_regular"


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFOs are unavailable")
def test_load_config_file_rejects_a_fifo_without_blocking(tmp_path: Path) -> None:
    fifo = tmp_path / "config.fifo"
    os.mkfifo(fifo)

    with pytest.raises(ConfigError) as excinfo:
        load_config_file(fifo)

    assert excinfo.value.code == "config.file.not_regular"


def test_load_config_file_rejects_an_invalid_path_without_echoing_it() -> None:
    with pytest.raises(ConfigError) as excinfo:
        load_config_file("invalid\x00path")

    assert excinfo.value.code == "config.path.invalid"
    assert "invalid\x00path" not in str(excinfo.value)


def test_load_config_file_rejects_empty_files(tmp_path: Path) -> None:
    empty = _write(tmp_path / "empty.toml", "")

    with pytest.raises(ConfigError) as excinfo:
        load_config_file(empty)

    assert excinfo.value.code == "config.file.empty"


def test_load_config_file_rejects_oversized_files(tmp_path: Path) -> None:
    oversized = tmp_path / "big.toml"
    oversized.write_text("# " + ("x" * (MAX_CONFIG_BYTES + 1)), encoding="utf-8")

    with pytest.raises(ConfigError) as excinfo:
        load_config_file(oversized)

    assert excinfo.value.code == "config.file.too_large"


def test_load_config_file_enforces_the_read_bound_after_fstat(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    oversized = tmp_path / "growing.toml"
    oversized.write_bytes(b"#" * (MAX_CONFIG_BYTES + 1))
    real_fstat = os.fstat

    def hidden_size(descriptor: int) -> os.stat_result:
        values = list(real_fstat(descriptor))
        values[6] = MAX_CONFIG_BYTES
        return os.stat_result(values)

    monkeypatch.setattr(config_loader.os, "fstat", hidden_size)

    with pytest.raises(ConfigError) as excinfo:
        load_config_file(oversized)

    assert excinfo.value.code == "config.file.too_large"


def test_load_config_file_translates_fdopen_failure_and_closes_descriptor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _write(tmp_path / "milhouse.toml")
    private_fragment = "private-fdopen-fragment-0123456789"
    real_close = os.close
    closed: list[int] = []

    def fail_fdopen(*_args: object, **_kwargs: object) -> object:
        raise OSError(private_fragment)

    def record_close(descriptor: int) -> None:
        closed.append(descriptor)
        real_close(descriptor)

    monkeypatch.setattr(config_loader.os, "fdopen", fail_fdopen)
    monkeypatch.setattr(config_loader.os, "close", record_close)

    with pytest.raises(ConfigError) as excinfo:
        load_config_file(path)

    assert excinfo.value.code == "config.file.unreadable"
    assert private_fragment not in str(excinfo.value)
    assert closed


def test_load_config_file_translates_read_metadata_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _write(tmp_path / "milhouse.toml")
    real_fstat = os.fstat
    regular_file_calls = 0

    def fail_after_read(descriptor: int) -> os.stat_result:
        nonlocal regular_file_calls
        metadata = real_fstat(descriptor)
        if stat.S_ISREG(metadata.st_mode):
            regular_file_calls += 1
        if regular_file_calls == 2:
            raise OSError("private-read-fragment-0123456789")
        return metadata

    monkeypatch.setattr(config_loader.os, "fstat", fail_after_read)

    with pytest.raises(ConfigError) as excinfo:
        load_config_file(path)

    assert excinfo.value.code == "config.file.unreadable"
    assert "private-read-fragment" not in str(excinfo.value)


def test_load_config_file_rejects_reinspection_snapshot_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _write(tmp_path / "milhouse.toml")
    real_inspect = config_loader.inspect_regular_file_no_follow

    def changed_snapshot(selected_path: str | Path):
        current = real_inspect(selected_path)
        return replace(current, snapshot=replace(current.snapshot, size=current.snapshot.size + 1))

    monkeypatch.setattr(config_loader, "inspect_regular_file_no_follow", changed_snapshot)

    with pytest.raises(ConfigError) as excinfo:
        load_config_file(path)

    assert excinfo.value.code == "config.file.changed"


def test_load_config_file_detects_an_in_place_read_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _write(tmp_path / "milhouse.toml")
    real_fstat = os.fstat
    initial = path.stat()
    regular_file_calls = 0

    def changed_after_read(descriptor: int) -> os.stat_result:
        nonlocal regular_file_calls
        metadata = real_fstat(descriptor)
        if stat.S_ISREG(metadata.st_mode):
            regular_file_calls += 1
        if regular_file_calls == 2:
            os.utime(
                path,
                ns=(initial.st_atime_ns, initial.st_mtime_ns + 1_000_000_000),
            )
        return real_fstat(descriptor)

    monkeypatch.setattr(config_loader.os, "fstat", changed_after_read)

    with pytest.raises(ConfigError) as excinfo:
        load_config_file(path)

    assert excinfo.value.code == "config.file.changed"


def test_load_config_file_rejects_non_utf8_bytes(tmp_path: Path) -> None:
    non_utf8 = tmp_path / "non-utf8.toml"
    non_utf8.write_bytes(b"config_version = 1\nname = \xff\xfe")

    with pytest.raises(ConfigError) as excinfo:
        load_config_file(non_utf8)

    assert excinfo.value.code == "config.file.unreadable"


def test_load_config_file_rejects_malformed_toml(tmp_path: Path) -> None:
    malformed = _write(tmp_path / "malformed.toml", "not valid = = toml")

    with pytest.raises(ConfigError) as excinfo:
        load_config_file(malformed)

    assert excinfo.value.code == "config.toml.syntax"
    assert "line" in excinfo.value.message


def test_toml_location_extraction_and_location_free_syntax_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert config_loader._extract_toml_location("no source coordinate") is None
    monkeypatch.setattr(config_loader, "_extract_toml_location", lambda _message: None)

    with pytest.raises(ConfigError) as excinfo:
        config_loader._parse_toml("not valid = = toml")

    assert excinfo.value.code == "config.toml.syntax"
    assert "line" not in excinfo.value.message


@pytest.mark.parametrize(
    "version_line",
    ["config_version = 2", 'config_version = "1"', "config_version = 1.0"],
)
def test_load_config_file_rejects_unsupported_versions(tmp_path: Path, version_line: str) -> None:
    document = _MINIMAL_CONFIG.replace("config_version = 1", version_line, 1)
    path = _write(tmp_path / "version.toml", document)

    with pytest.raises(ConfigError) as excinfo:
        load_config_file(path)

    assert excinfo.value.code == "config.version.unsupported"


def test_load_config_file_schema_errors_never_echo_raw_field_values(tmp_path: Path) -> None:
    secret_looking_value = "sk-not-a-real-secret-0123456789"
    document = _MINIMAL_CONFIG.replace(
        "max_batch_records = 500", f'max_batch_records = "{secret_looking_value}"'
    )
    path = _write(tmp_path / "coercion.toml", document)

    with pytest.raises(ConfigError) as excinfo:
        load_config_file(path)

    assert excinfo.value.code == "config.schema.invalid"
    assert secret_looking_value not in excinfo.value.message
    assert secret_looking_value not in str(excinfo.value)
    assert excinfo.value.__cause__ is None
    assert excinfo.value.__suppress_context__ is True
    assert secret_looking_value not in "".join(traceback.format_exception(excinfo.value))


def test_load_config_file_cross_reference_errors_never_echo_raw_ids(tmp_path: Path) -> None:
    secret_looking_id = "secret_token_0123456789abcdef"
    document = _MINIMAL_CONFIG.replace(
        'default_target = "app"', f'default_target = "{secret_looking_id}"'
    )
    path = _write(tmp_path / "reference.toml", document)

    with pytest.raises(ConfigError) as excinfo:
        load_config_file(path)

    assert excinfo.value.code == "config.schema.invalid"
    assert secret_looking_id not in str(excinfo.value)


def test_load_config_file_reports_unknown_keys(tmp_path: Path) -> None:
    document = _MINIMAL_CONFIG.replace("[project]", "[project]\nbogus_field = 1")
    path = _write(tmp_path / "unknown.toml", document)

    with pytest.raises(ConfigError) as excinfo:
        load_config_file(path)

    assert excinfo.value.code == "config.schema.invalid"
    assert "project.bogus_field" in excinfo.value.message


def test_config_error_string_includes_code_and_message() -> None:
    error = ConfigError("config.file.not_found", "config file was not found")

    assert str(error) == "config.file.not_found: config file was not found"
