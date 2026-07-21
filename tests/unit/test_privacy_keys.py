from __future__ import annotations

import os
import stat
import traceback
from dataclasses import replace
from pathlib import Path

import pytest

import milhouse.config.filesystem as secure_filesystem
import milhouse.privacy.keys as privacy_keys
from milhouse.config import ConfigError, load_config, resolve_runtime_paths
from milhouse.config.filesystem import (
    OpenedRegularFile,
    SecureFileError,
    SecureFileErrorKind,
    inspect_regular_file_no_follow,
)
from milhouse.config.loader import ConfigFileSelection, validated_config_digest
from milhouse.config.models import MilhouseConfig
from milhouse.config.paths import RuntimePaths
from milhouse.privacy import (
    PSEUDONYM_KEY_BYTES,
    PSEUDONYM_KEY_MODE,
    PrivacyError,
    PseudonymKeyCommitUncertain,
    create_pseudonym_key,
    load_pseudonym_key,
    recover_pseudonym_key_creation,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
EXAMPLE_CONFIG = REPOSITORY_ROOT / "config/examples/local-only.toml"


def _runtime(tmp_path: Path) -> tuple[MilhouseConfig, RuntimePaths]:
    config_dir = tmp_path / "config"
    config_dir.mkdir(parents=True)
    config_file = config_dir / "milhouse.toml"
    config_file.write_text(
        EXAMPLE_CONFIG.read_text(encoding="utf-8").replace(
            'home = "../../data/local-only"',
            'home = "../state"',
        ),
        encoding="utf-8",
    )
    config, selection = load_config(
        config_file,
        platform_default=config_file,
        env={},
    )
    paths = resolve_runtime_paths(
        config,
        config_path=selection,
        platform_data_root=tmp_path / "platform",
        env={},
    )
    paths.pseudonym_key.parent.mkdir(parents=True, mode=0o700)
    return config, paths


def _write_key(paths: RuntimePaths, value: bytes, *, mode: int = PSEUDONYM_KEY_MODE) -> None:
    paths.pseudonym_key.write_bytes(value)
    paths.pseudonym_key.chmod(mode)


def test_create_and_load_key_round_trip_with_restrictive_mode(tmp_path: Path) -> None:
    config, paths = _runtime(tmp_path)
    key = bytes(range(PSEUDONYM_KEY_BYTES))

    created = create_pseudonym_key(config, paths, epoch=3, random_bytes=lambda size: key)
    loaded = load_pseudonym_key(
        config,
        paths,
        epoch=3,
        expected_key_id=created.key_id,
    )

    metadata = paths.pseudonym_key.stat()
    assert metadata.st_size == PSEUDONYM_KEY_BYTES
    assert stat.S_IMODE(metadata.st_mode) == PSEUDONYM_KEY_MODE
    assert metadata.st_nlink == 1
    assert paths.pseudonym_key.read_bytes() == key
    assert created.key_id == loaded.key_id
    assert created.pseudonymize("email", "synthetic@example.test") == loaded.pseudonymize(
        "email", "synthetic@example.test"
    )
    assert repr(created) == "Pseudonymizer(epoch=3)"
    assert os.fspath(paths.pseudonym_key) not in repr(created)
    assert key.hex() not in repr(created)


def test_create_never_overwrites_an_existing_key(tmp_path: Path) -> None:
    config, paths = _runtime(tmp_path)
    original = b"A" * PSEUDONYM_KEY_BYTES
    replacement = b"B" * PSEUDONYM_KEY_BYTES
    create_pseudonym_key(config, paths, random_bytes=lambda size: original)

    with pytest.raises(PrivacyError) as captured:
        create_pseudonym_key(config, paths, random_bytes=lambda size: replacement)

    assert captured.value.code == "MH_PRIVACY_KEY_EXISTS"
    assert paths.pseudonym_key.read_bytes() == original


@pytest.mark.parametrize(
    ("value", "mode", "code"),
    [
        (b"S" * (PSEUDONYM_KEY_BYTES - 1), PSEUDONYM_KEY_MODE, "MH_PRIVACY_KEY_SIZE"),
        (b"L" * (PSEUDONYM_KEY_BYTES + 1), PSEUDONYM_KEY_MODE, "MH_PRIVACY_KEY_SIZE"),
        (b"M" * PSEUDONYM_KEY_BYTES, 0o644, "MH_PRIVACY_KEY_MODE"),
        (b"R" * PSEUDONYM_KEY_BYTES, 0o400, "MH_PRIVACY_KEY_MODE"),
    ],
)
def test_load_rejects_wrong_size_or_mode_without_rendering_material(
    tmp_path: Path,
    value: bytes,
    mode: int,
    code: str,
) -> None:
    config, paths = _runtime(tmp_path)
    _write_key(paths, value, mode=mode)

    with pytest.raises(PrivacyError) as captured:
        load_pseudonym_key(config, paths)

    assert captured.value.code == code
    assert value.hex() not in str(captured.value)
    assert os.fspath(paths.pseudonym_key) not in str(captured.value)


def test_load_rejects_missing_key_and_missing_create_parent(tmp_path: Path) -> None:
    config, paths = _runtime(tmp_path)

    with pytest.raises(PrivacyError) as missing:
        load_pseudonym_key(config, paths)
    assert missing.value.code == "MH_PRIVACY_KEY_NOT_FOUND"

    paths.pseudonym_key.parent.rmdir()
    with pytest.raises(PrivacyError) as missing_parent:
        create_pseudonym_key(config, paths)
    assert missing_parent.value.code == "MH_PRIVACY_KEY_PARENT_MISSING"


@pytest.mark.parametrize("operation", ["create", "load"])
def test_key_operations_reject_non_private_parent(
    tmp_path: Path,
    operation: str,
) -> None:
    config, paths = _runtime(tmp_path)
    if operation == "load":
        _write_key(paths, b"P" * PSEUDONYM_KEY_BYTES)
    paths.pseudonym_key.parent.chmod(0o750)

    with pytest.raises(PrivacyError) as captured:
        if operation == "create":
            create_pseudonym_key(config, paths)
        else:
            load_pseudonym_key(config, paths)

    assert captured.value.code == "MH_PRIVACY_KEY_PARENT_UNSAFE"


def test_load_rejects_wrong_owner_and_hard_links(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config, paths = _runtime(tmp_path)
    _write_key(paths, b"O" * PSEUDONYM_KEY_BYTES)
    current_user = os.geteuid()
    monkeypatch.setattr(privacy_keys.os, "geteuid", lambda: current_user + 1)

    with pytest.raises(PrivacyError) as wrong_owner:
        privacy_keys._validate_key_metadata(paths.pseudonym_key.stat())
    assert wrong_owner.value.code == "MH_PRIVACY_KEY_OWNER"

    monkeypatch.setattr(privacy_keys.os, "geteuid", lambda: current_user)
    os.link(paths.pseudonym_key, paths.pseudonym_key.with_suffix(".linked"))
    with pytest.raises(PrivacyError) as linked:
        load_pseudonym_key(config, paths)
    assert linked.value.code == "MH_PRIVACY_KEY_LINKS"


def test_expected_key_id_is_validated_and_compared_without_key_material(tmp_path: Path) -> None:
    config, paths = _runtime(tmp_path)
    key = b"I" * PSEUDONYM_KEY_BYTES
    created = create_pseudonym_key(config, paths, random_bytes=lambda size: key)

    with pytest.raises(PrivacyError) as malformed:
        load_pseudonym_key(config, paths, expected_key_id="not-a-key-id")
    assert malformed.value.code == "MH_PRIVACY_KEY_ID"

    different_id = "mh_pk1_0000000000000000"
    assert different_id != created.key_id
    with pytest.raises(PrivacyError) as mismatch:
        load_pseudonym_key(config, paths, expected_key_id=different_id)
    assert mismatch.value.code == "MH_PRIVACY_KEY_ID_MISMATCH"
    assert key.hex() not in str(mismatch.value)


@pytest.mark.parametrize("leaf_kind", ["symlink", "directory", "fifo"])
def test_key_leaf_must_be_a_regular_non_symlink_file(tmp_path: Path, leaf_kind: str) -> None:
    config, paths = _runtime(tmp_path)
    if leaf_kind == "symlink":
        target = tmp_path / "synthetic-target"
        target.write_bytes(b"T" * PSEUDONYM_KEY_BYTES)
        target.chmod(PSEUDONYM_KEY_MODE)
        paths.pseudonym_key.symlink_to(target)
    elif leaf_kind == "directory":
        paths.pseudonym_key.mkdir()
    else:
        os.mkfifo(paths.pseudonym_key, PSEUDONYM_KEY_MODE)

    with pytest.raises(PrivacyError) as captured:
        load_pseudonym_key(config, paths)

    assert captured.value.code == "MH_PRIVACY_KEY_TYPE"


def test_key_parent_symlink_is_refused(tmp_path: Path) -> None:
    config, paths = _runtime(tmp_path)
    real_parent = paths.pseudonym_key.parent.with_name("real-control")
    paths.pseudonym_key.parent.rename(real_parent)
    paths.pseudonym_key.parent.symlink_to(real_parent, target_is_directory=True)
    _write_key(replace(paths, pseudonym_key=real_parent / paths.pseudonym_key.name), b"P" * 32)

    with pytest.raises(PrivacyError) as captured:
        load_pseudonym_key(config, paths)

    assert captured.value.code == "MH_PRIVACY_KEY_TYPE"


def test_runtime_key_path_must_match_config_and_remain_beneath_state_root(tmp_path: Path) -> None:
    config, paths = _runtime(tmp_path)
    outside = replace(paths, pseudonym_key=tmp_path / "outside.key")
    alternate = replace(paths, pseudonym_key=paths.state_root / "other.key")

    with pytest.raises(PrivacyError) as escaped:
        create_pseudonym_key(config, outside)
    assert escaped.value.code == "MH_PRIVACY_KEY_ESCAPE"

    with pytest.raises(PrivacyError) as mismatched:
        create_pseudonym_key(config, alternate)
    assert mismatched.value.code == "MH_PRIVACY_KEY_BINDING"
    assert not outside.pseudonym_key.exists()
    assert not alternate.pseudonym_key.exists()


def test_self_consistent_forged_absolute_root_fails_runtime_generation_binding(
    tmp_path: Path,
) -> None:
    config, paths = _runtime(tmp_path)
    forged_root = tmp_path / "forged-state"
    forged_key = forged_root / config.identity.pseudonym_key_path
    forged_key.parent.mkdir(parents=True, mode=0o700)
    forged_paths = replace(
        paths,
        state_root=forged_root,
        pseudonym_key=forged_key,
    )

    with pytest.raises(PrivacyError) as captured:
        create_pseudonym_key(config, forged_paths)

    assert captured.value.code == "MH_PRIVACY_KEY_BINDING"
    assert not forged_key.exists()
    assert not paths.pseudonym_key.exists()


def test_key_operations_are_independent_of_current_working_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, paths = _runtime(tmp_path)
    decoy = tmp_path / "decoy"
    decoy.mkdir()
    monkeypatch.chdir(decoy)

    created = create_pseudonym_key(
        config,
        paths,
        random_bytes=lambda size: b"C" * size,
    )
    loaded = load_pseudonym_key(config, paths, expected_key_id=created.key_id)

    assert created.key_id == loaded.key_id
    assert not (decoy / "control/pseudonym.key").exists()


def test_missing_nofollow_support_fails_closed_before_creation_or_loading(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, paths = _runtime(tmp_path)
    monkeypatch.setattr(secure_filesystem.os, "O_NOFOLLOW", 0)

    with pytest.raises(PrivacyError) as create_error:
        create_pseudonym_key(config, paths)
    assert create_error.value.code == "MH_PRIVACY_KEY_SECURITY_UNSUPPORTED"
    assert not paths.pseudonym_key.exists()

    paths.pseudonym_key.write_bytes(b"N" * PSEUDONYM_KEY_BYTES)
    paths.pseudonym_key.chmod(PSEUDONYM_KEY_MODE)
    with pytest.raises(PrivacyError) as load_error:
        load_pseudonym_key(config, paths)
    assert load_error.value.code == "MH_PRIVACY_KEY_SECURITY_UNSUPPORTED"


@pytest.mark.parametrize("result", [b"short", b"X" * 33, bytearray(b"X" * 32), "text"])
def test_entropy_source_must_return_exact_bytes(tmp_path: Path, result: object) -> None:
    config, paths = _runtime(tmp_path)

    with pytest.raises(PrivacyError) as captured:
        create_pseudonym_key(config, paths, random_bytes=lambda size: result)  # type: ignore[arg-type,return-value]

    assert captured.value.code == "MH_PRIVACY_KEY_RANDOM"
    assert not paths.pseudonym_key.exists()


def test_entropy_source_failure_is_value_safe(tmp_path: Path) -> None:
    config, paths = _runtime(tmp_path)

    def fail_entropy(size: int) -> bytes:
        raise RuntimeError("synthetic-private-random-detail")

    with pytest.raises(PrivacyError) as captured:
        create_pseudonym_key(config, paths, random_bytes=fail_entropy)

    assert captured.value.code == "MH_PRIVACY_KEY_RANDOM"
    assert "synthetic-private-random-detail" not in str(captured.value)
    assert not paths.pseudonym_key.exists()


def test_staging_name_entropy_failure_is_value_safe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, paths = _runtime(tmp_path)

    def fail_stage_name(size: int) -> str:
        raise RuntimeError("synthetic-private-stage-name-detail")

    monkeypatch.setattr(secure_filesystem.secrets, "token_hex", fail_stage_name)
    with pytest.raises(PrivacyError) as captured:
        create_pseudonym_key(config, paths, random_bytes=lambda size: b"S" * size)

    rendered = "".join(traceback.format_exception(captured.value))
    assert captured.value.code == "MH_PRIVACY_KEY_WRITE"
    assert "synthetic-private-stage-name-detail" not in rendered
    assert os.fspath(paths.pseudonym_key) not in rendered
    assert not paths.pseudonym_key.exists()


@pytest.mark.parametrize("token", [object(), "../outside-stage", "g" * 32, "a" * 31])
def test_staging_name_entropy_must_be_exact_lowercase_hex(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    token: object,
) -> None:
    config, paths = _runtime(tmp_path)
    monkeypatch.setattr(secure_filesystem.secrets, "token_hex", lambda size: token)

    with pytest.raises(PrivacyError) as captured:
        create_pseudonym_key(config, paths)

    assert captured.value.code == "MH_PRIVACY_KEY_WRITE"
    assert not paths.pseudonym_key.exists()
    assert not (tmp_path / "outside-stage").exists()


def test_partial_write_failure_removes_only_the_new_key(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, paths = _runtime(tmp_path)
    real_write = secure_filesystem.os.write
    calls = 0

    def fail_after_short_write(descriptor: int, value: bytes) -> int:
        nonlocal calls
        calls += 1
        if calls == 1:
            return real_write(descriptor, value[:7])
        raise OSError("synthetic-private-write-detail")

    monkeypatch.setattr(secure_filesystem.os, "write", fail_after_short_write)
    with pytest.raises(PrivacyError) as captured:
        create_pseudonym_key(config, paths, random_bytes=lambda size: b"W" * size)

    assert captured.value.code == "MH_PRIVACY_KEY_WRITE"
    assert "synthetic-private-write-detail" not in str(captured.value)
    assert not paths.pseudonym_key.exists()


def test_permission_failure_cleans_up_new_key(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, paths = _runtime(tmp_path)

    def fail_chmod(descriptor: int, mode: int) -> None:
        raise OSError("synthetic-private-chmod-detail")

    monkeypatch.setattr(secure_filesystem.os, "fchmod", fail_chmod)
    with pytest.raises(PrivacyError) as captured:
        create_pseudonym_key(config, paths)

    assert captured.value.code == "MH_PRIVACY_KEY_PERMISSION"
    assert not paths.pseudonym_key.exists()


def test_file_sync_failure_sanitizes_stage_without_publishing_key(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, paths = _runtime(tmp_path)
    real_fsync = secure_filesystem.os.fsync
    calls = 0

    def fail_selected_sync(descriptor: int) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError("synthetic-private-sync-detail")
        real_fsync(descriptor)

    monkeypatch.setattr(secure_filesystem.os, "fsync", fail_selected_sync)
    with pytest.raises(PrivacyError) as captured:
        create_pseudonym_key(config, paths)

    assert captured.value.code == "MH_PRIVACY_KEY_SYNC"
    assert not paths.pseudonym_key.exists()


def test_parent_sync_failure_returns_identity_checked_recovery_handle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, paths = _runtime(tmp_path)
    real_fsync = secure_filesystem.os.fsync
    calls = 0

    def fail_parent_sync_once(descriptor: int) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("synthetic-private-sync-detail")
        real_fsync(descriptor)

    monkeypatch.setattr(secure_filesystem.os, "fsync", fail_parent_sync_once)
    with pytest.raises(PseudonymKeyCommitUncertain) as captured:
        create_pseudonym_key(config, paths, random_bytes=lambda size: b"D" * size)

    assert captured.value.code == "MH_PRIVACY_KEY_COMMIT_UNCERTAIN"
    assert repr(captured.value) == "PseudonymKeyCommitUncertain(recovery_required=True)"
    assert paths.pseudonym_key.read_bytes() == b"D" * PSEUDONYM_KEY_BYTES

    monkeypatch.undo()
    recovered = recover_pseudonym_key_creation(
        config,
        paths,
        expected_key_id=captured.value.key_id,
    )
    assert recovered.key_id == captured.value.key_id


def test_cleanup_failure_is_explicit_and_does_not_render_material(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, paths = _runtime(tmp_path)
    key = b"Q" * PSEUDONYM_KEY_BYTES

    def fail_write(descriptor: int, value: bytes) -> int:
        raise OSError("synthetic-private-write-detail")

    def fail_truncate(descriptor: int, length: int) -> None:
        raise OSError("synthetic-private-cleanup-detail")

    monkeypatch.setattr(secure_filesystem.os, "write", fail_write)
    monkeypatch.setattr(secure_filesystem.os, "ftruncate", fail_truncate)
    with pytest.raises(PrivacyError) as captured:
        create_pseudonym_key(config, paths, random_bytes=lambda size: key)

    assert captured.value.code == "MH_PRIVACY_KEY_CLEANUP"
    rendered = "".join(traceback.format_exception(captured.value))
    assert key.hex() not in rendered
    assert os.fspath(paths.pseudonym_key) not in rendered
    assert "synthetic-private" not in rendered


def test_load_detects_leaf_replacement_after_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, paths = _runtime(tmp_path)
    _write_key(paths, b"A" * PSEUDONYM_KEY_BYTES)
    replacement = tmp_path / "replacement.key"
    replacement.write_bytes(b"B" * PSEUDONYM_KEY_BYTES)
    replacement.chmod(PSEUDONYM_KEY_MODE)
    real_inspect = privacy_keys.inspect_regular_file_no_follow

    def replace_then_inspect(path: str | Path, **kwargs: object):
        paths.pseudonym_key.unlink()
        replacement.rename(paths.pseudonym_key)
        return real_inspect(path, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(privacy_keys, "inspect_regular_file_no_follow", replace_then_inspect)
    with pytest.raises(PrivacyError) as captured:
        load_pseudonym_key(config, paths)

    assert captured.value.code == "MH_PRIVACY_KEY_CHANGED"


def test_load_detects_parent_replacement_after_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, paths = _runtime(tmp_path)
    _write_key(paths, b"A" * PSEUDONYM_KEY_BYTES)
    original_parent = paths.pseudonym_key.parent
    moved_parent = original_parent.with_name("old-control")
    real_inspect = privacy_keys.inspect_regular_file_no_follow

    def replace_parent_then_inspect(path: str | Path, **kwargs: object):
        original_parent.rename(moved_parent)
        original_parent.mkdir(mode=0o700)
        _write_key(
            replace(paths, pseudonym_key=original_parent / paths.pseudonym_key.name), b"A" * 32
        )
        return real_inspect(path, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(
        privacy_keys,
        "inspect_regular_file_no_follow",
        replace_parent_then_inspect,
    )
    with pytest.raises(PrivacyError) as captured:
        load_pseudonym_key(config, paths)

    assert captured.value.code == "MH_PRIVACY_KEY_CHANGED"


def test_create_reports_commit_uncertain_without_deleting_moved_key(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, paths = _runtime(tmp_path)
    original_parent = paths.pseudonym_key.parent
    moved_parent = original_parent.with_name("old-control")
    real_inspect = secure_filesystem.inspect_regular_file_no_follow

    def replace_parent_then_inspect(path: str | Path, **kwargs: object):
        original_parent.rename(moved_parent)
        original_parent.mkdir(mode=0o700)
        return real_inspect(path, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(
        secure_filesystem,
        "inspect_regular_file_no_follow",
        replace_parent_then_inspect,
    )
    with pytest.raises(PrivacyError) as captured:
        create_pseudonym_key(config, paths)

    assert captured.value.code == "MH_PRIVACY_KEY_COMMIT_UNCERTAIN"
    assert (moved_parent / paths.pseudonym_key.name).stat().st_size == PSEUDONYM_KEY_BYTES
    assert not paths.pseudonym_key.exists()


@pytest.mark.parametrize("invalid", [object(), None, "runtime-paths"])
def test_key_operations_require_validated_config_and_runtime_types(
    tmp_path: Path,
    invalid: object,
) -> None:
    config, paths = _runtime(tmp_path)

    with pytest.raises(PrivacyError) as invalid_config:
        create_pseudonym_key(invalid, paths)  # type: ignore[arg-type]
    with pytest.raises(PrivacyError) as invalid_paths:
        create_pseudonym_key(config, invalid)  # type: ignore[arg-type]

    assert invalid_config.value.code == "MH_PRIVACY_KEY_BINDING"
    assert invalid_paths.value.code == "MH_PRIVACY_KEY_BINDING"


def test_key_operations_reject_changed_config_generation(tmp_path: Path) -> None:
    config, paths = _runtime(tmp_path)
    paths.config_file.write_text(
        paths.config_file.read_text(encoding="utf-8") + "\n",
        encoding="utf-8",
    )

    with pytest.raises(PrivacyError) as captured:
        create_pseudonym_key(config, paths)

    assert captured.value.code == "MH_PRIVACY_KEY_CONFIG"
    assert not paths.pseudonym_key.exists()


def test_key_operations_reject_malformed_runtime_path_values(tmp_path: Path) -> None:
    config, paths = _runtime(tmp_path)
    malformed = replace(paths, state_root=object())  # type: ignore[arg-type]

    with pytest.raises(PrivacyError) as captured:
        create_pseudonym_key(config, malformed)

    assert captured.value.code == "MH_PRIVACY_KEY_BINDING"


@pytest.mark.parametrize(
    "forged",
    [
        {"state_root": Path("relative-state")},
        {"config_file": Path("relative-config.toml")},
        {"config_dir": Path("relative-config")},
    ],
)
def test_key_operations_reject_internally_inconsistent_runtime_paths(
    tmp_path: Path,
    forged: dict[str, Path],
) -> None:
    config, paths = _runtime(tmp_path)

    with pytest.raises(PrivacyError) as captured:
        create_pseudonym_key(config, replace(paths, **forged))  # type: ignore[arg-type]

    assert captured.value.code == "MH_PRIVACY_KEY_BINDING"


def test_state_root_itself_cannot_be_the_key_path(tmp_path: Path) -> None:
    config, paths = _runtime(tmp_path)

    with pytest.raises(PrivacyError) as captured:
        create_pseudonym_key(config, replace(paths, pseudonym_key=paths.state_root))

    assert captured.value.code == "MH_PRIVACY_KEY_ESCAPE"


def test_forged_configured_key_escape_is_rejected(tmp_path: Path) -> None:
    config, paths = _runtime(tmp_path)
    forged_identity = config.identity.model_copy(update={"pseudonym_key_path": "../outside.key"})
    forged_config = config.model_copy(update={"identity": forged_identity})
    selected = inspect_regular_file_no_follow(paths.config_file)
    forged_selection = ConfigFileSelection(
        path=selected.path,
        parent_identity=selected.parent_identity,
        snapshot=selected.snapshot,
        config_digest=validated_config_digest(forged_config),
    )
    forged_paths = replace(
        paths,
        config_selection=forged_selection,
        pseudonym_key=paths.state_root / "safe.key",
    )

    with pytest.raises(PrivacyError) as captured:
        create_pseudonym_key(forged_config, forged_paths)

    assert captured.value.code == "MH_PRIVACY_KEY_ESCAPE"


def test_runtime_binding_rechecks_generation_before_return(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, paths = _runtime(tmp_path)
    calls = 0
    real_verify = privacy_keys.verify_config_generation

    def fail_second_verify(config_value: MilhouseConfig, selection: ConfigFileSelection):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise ConfigError("config.file.changed", "synthetic safe failure")
        return real_verify(config_value, selection)

    monkeypatch.setattr(privacy_keys, "verify_config_generation", fail_second_verify)
    with pytest.raises(PrivacyError) as captured:
        create_pseudonym_key(config, paths)

    assert captured.value.code == "MH_PRIVACY_KEY_CONFIG"
    assert not paths.pseudonym_key.exists()


@pytest.mark.parametrize(
    ("kind", "code"),
    [
        (SecureFileErrorKind.SECURITY_UNSUPPORTED, "MH_PRIVACY_KEY_SECURITY_UNSUPPORTED"),
        (SecureFileErrorKind.CHANGED, "MH_PRIVACY_KEY_CHANGED"),
        (SecureFileErrorKind.INVALID, "MH_PRIVACY_KEY_CREATE"),
    ],
)
def test_create_translates_remaining_secure_file_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    kind: SecureFileErrorKind,
    code: str,
) -> None:
    config, paths = _runtime(tmp_path)

    def fail_create(path: Path, content: bytes, **kwargs: object):
        raise SecureFileError(kind)

    monkeypatch.setattr(privacy_keys, "create_regular_file_no_follow", fail_create)
    with pytest.raises(PrivacyError) as captured:
        create_pseudonym_key(config, paths)

    assert captured.value.code == code


@pytest.mark.parametrize("operation", ["create", "load", "recover"])
def test_key_boundaries_translate_unexpected_runtime_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
) -> None:
    config, paths = _runtime(tmp_path)
    created = create_pseudonym_key(config, paths) if operation == "recover" else None

    def fail_unexpected(*args: object, **kwargs: object) -> None:
        raise RuntimeError("synthetic-private-unexpected-detail")

    if operation == "create":
        monkeypatch.setattr(privacy_keys, "create_regular_file_no_follow", fail_unexpected)
        expected_code = "MH_PRIVACY_KEY_CREATE"
    elif operation == "load":
        monkeypatch.setattr(privacy_keys, "_read_key_material", fail_unexpected)
        expected_code = "MH_PRIVACY_KEY_READ"
    else:
        assert created is not None
        monkeypatch.setattr(privacy_keys, "sync_parent_directory_no_follow", fail_unexpected)
        expected_code = "MH_PRIVACY_KEY_RECOVERY"

    with pytest.raises(PrivacyError) as captured:
        if operation == "create":
            create_pseudonym_key(config, paths)
        elif operation == "load":
            load_pseudonym_key(config, paths)
        else:
            assert created is not None
            recover_pseudonym_key_creation(
                config,
                paths,
                expected_key_id=created.key_id,
            )

    rendered = "".join(traceback.format_exception(captured.value))
    assert captured.value.code == expected_code
    assert "synthetic-private-unexpected-detail" not in rendered
    assert os.fspath(paths.pseudonym_key) not in rendered


@pytest.mark.parametrize(
    ("kind", "code"),
    [
        (SecureFileErrorKind.SECURITY_UNSUPPORTED, "MH_PRIVACY_KEY_SECURITY_UNSUPPORTED"),
        (SecureFileErrorKind.UNREADABLE, "MH_PRIVACY_KEY_READ"),
    ],
)
def test_load_translates_remaining_secure_file_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    kind: SecureFileErrorKind,
    code: str,
) -> None:
    config, paths = _runtime(tmp_path)

    def fail_open(path: Path, **kwargs: object):
        raise SecureFileError(kind)

    monkeypatch.setattr(privacy_keys, "open_regular_file_no_follow", fail_open)
    with pytest.raises(PrivacyError) as captured:
        load_pseudonym_key(config, paths)

    assert captured.value.code == code


def test_metadata_validator_rejects_nonregular_metadata(tmp_path: Path) -> None:
    with pytest.raises(PrivacyError) as captured:
        privacy_keys._validate_key_metadata(tmp_path.stat())

    assert captured.value.code == "MH_PRIVACY_KEY_TYPE"


def test_load_fails_when_owner_checks_are_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, paths = _runtime(tmp_path)
    _write_key(paths, b"U" * PSEUDONYM_KEY_BYTES)
    monkeypatch.setattr(privacy_keys.os, "geteuid", None)

    with pytest.raises(PrivacyError) as captured:
        load_pseudonym_key(config, paths)

    assert captured.value.code == "MH_PRIVACY_KEY_SECURITY_UNSUPPORTED"

    with pytest.raises(PrivacyError) as metadata_error:
        privacy_keys._validate_key_metadata(paths.pseudonym_key.stat())
    assert metadata_error.value.code == "MH_PRIVACY_KEY_SECURITY_UNSUPPORTED"


@pytest.mark.parametrize(
    ("kind", "code"),
    [
        (SecureFileErrorKind.PARENT_UNSAFE, "MH_PRIVACY_KEY_PARENT_UNSAFE"),
        (SecureFileErrorKind.SYNC_FAILED, "MH_PRIVACY_KEY_RECOVERY"),
    ],
)
def test_commit_recovery_translates_parent_sync_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    kind: SecureFileErrorKind,
    code: str,
) -> None:
    config, paths = _runtime(tmp_path)
    created = create_pseudonym_key(config, paths)

    def fail_sync(path: Path, **kwargs: object) -> None:
        raise SecureFileError(kind)

    monkeypatch.setattr(privacy_keys, "sync_parent_directory_no_follow", fail_sync)
    with pytest.raises(PrivacyError) as captured:
        recover_pseudonym_key_creation(
            config,
            paths,
            expected_key_id=created.key_id,
        )

    assert captured.value.code == code


def test_load_rejects_more_bytes_than_the_validated_file_size(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, paths = _runtime(tmp_path)
    _write_key(paths, b"B" * PSEUDONYM_KEY_BYTES)
    calls = 0

    def oversized_read(descriptor: int, size: int) -> bytes:
        nonlocal calls
        calls += 1
        return b"Z" * (PSEUDONYM_KEY_BYTES + 1) if calls == 1 else b""

    monkeypatch.setattr(privacy_keys.os, "read", oversized_read)
    with pytest.raises(PrivacyError) as captured:
        load_pseudonym_key(config, paths)

    assert captured.value.code == "MH_PRIVACY_KEY_SIZE"


def test_load_detects_metadata_change_during_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, paths = _runtime(tmp_path)
    _write_key(paths, b"D" * PSEUDONYM_KEY_BYTES)
    real_coordinates = privacy_keys._metadata_coordinates
    calls = 0

    def changed_coordinates(metadata: os.stat_result) -> tuple[int, ...]:
        nonlocal calls
        calls += 1
        coordinates = real_coordinates(metadata)
        return coordinates if calls == 1 else (*coordinates, 1)

    monkeypatch.setattr(privacy_keys, "_metadata_coordinates", changed_coordinates)
    with pytest.raises(PrivacyError) as captured:
        load_pseudonym_key(config, paths)

    assert captured.value.code == "MH_PRIVACY_KEY_CHANGED"


def test_load_translates_read_and_close_failures_without_os_details(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, paths = _runtime(tmp_path)
    _write_key(paths, b"E" * PSEUDONYM_KEY_BYTES)

    def fail_read(descriptor: int, size: int) -> bytes:
        raise OSError("synthetic-private-read-detail")

    monkeypatch.setattr(privacy_keys.os, "read", fail_read)
    with pytest.raises(PrivacyError) as read_error:
        load_pseudonym_key(config, paths)
    assert read_error.value.code == "MH_PRIVACY_KEY_READ"
    assert "synthetic-private" not in str(read_error.value)

    monkeypatch.undo()
    config, paths = _runtime(tmp_path / "close-case")
    _write_key(paths, b"E" * PSEUDONYM_KEY_BYTES)
    selected = inspect_regular_file_no_follow(paths.pseudonym_key)
    descriptor = os.open(paths.pseudonym_key, os.O_RDONLY)
    opened = OpenedRegularFile(descriptor=descriptor, selection=selected)
    real_close = privacy_keys.os.close

    def fail_selected_close(value: int) -> None:
        real_close(value)
        if value == descriptor:
            raise OSError("synthetic-private-close-detail")

    monkeypatch.setattr(
        privacy_keys,
        "open_regular_file_no_follow",
        lambda path, **kwargs: opened,
    )
    monkeypatch.setattr(privacy_keys.os, "close", fail_selected_close)
    with pytest.raises(PrivacyError) as close_error:
        load_pseudonym_key(config, paths)
    assert close_error.value.code == "MH_PRIVACY_KEY_READ"
    assert "synthetic-private" not in str(close_error.value)


def test_real_open_parent_close_failure_is_stable_and_closes_key_descriptor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, paths = _runtime(tmp_path)
    key = b"J" * PSEUDONYM_KEY_BYTES
    _write_key(paths, key)
    real_chain = secure_filesystem._open_directory_chain
    real_open = secure_filesystem.os.open
    real_close = secure_filesystem.os.close
    key_parent_descriptor: int | None = None
    key_descriptor: int | None = None

    def capture_key_parent(path: Path, *, nofollow: int) -> tuple[int, str]:
        nonlocal key_parent_descriptor
        descriptor, leaf = real_chain(path, nofollow=nofollow)
        if path == paths.pseudonym_key:
            key_parent_descriptor = descriptor
        return descriptor, leaf

    def capture_key_open(
        selected_path: str,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal key_descriptor
        descriptor = real_open(selected_path, flags, mode, dir_fd=dir_fd)
        if dir_fd == key_parent_descriptor and selected_path == paths.pseudonym_key.name:
            key_descriptor = descriptor
        return descriptor

    def fail_key_parent_close(descriptor: int) -> None:
        real_close(descriptor)
        if descriptor == key_parent_descriptor:
            raise OSError("synthetic-private-parent-close-detail")

    monkeypatch.setattr(secure_filesystem, "_open_directory_chain", capture_key_parent)
    monkeypatch.setattr(secure_filesystem.os, "open", capture_key_open)
    monkeypatch.setattr(secure_filesystem.os, "close", fail_key_parent_close)
    with pytest.raises(PrivacyError) as captured:
        load_pseudonym_key(config, paths)

    rendered = "".join(traceback.format_exception(captured.value))
    assert captured.value.code == "MH_PRIVACY_KEY_READ"
    assert os.fspath(paths.pseudonym_key) not in rendered
    assert key.hex() not in rendered
    assert "synthetic-private-parent-close-detail" not in rendered
    assert key_descriptor is not None
    with pytest.raises(OSError):
        os.fstat(key_descriptor)


def test_load_reports_path_disappearance_after_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, paths = _runtime(tmp_path)
    _write_key(paths, b"G" * PSEUDONYM_KEY_BYTES)

    def remove_then_fail(path: Path, **kwargs: object):
        paths.pseudonym_key.unlink()
        raise SecureFileError(SecureFileErrorKind.NOT_FOUND)

    monkeypatch.setattr(privacy_keys, "inspect_regular_file_no_follow", remove_then_fail)
    with pytest.raises(PrivacyError) as captured:
        load_pseudonym_key(config, paths)

    assert captured.value.code == "MH_PRIVACY_KEY_CHANGED"


@pytest.mark.parametrize("operation", ["create", "load"])
def test_key_operations_recheck_generation_after_file_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
) -> None:
    config, paths = _runtime(tmp_path)
    if operation == "load":
        _write_key(paths, b"V" * PSEUDONYM_KEY_BYTES)
    calls = 0
    real_verify = privacy_keys.verify_config_generation

    def fail_third_verify(config_value: MilhouseConfig, selection: ConfigFileSelection):
        nonlocal calls
        calls += 1
        if calls == 3:
            raise ConfigError("config.file.changed", "synthetic safe failure")
        return real_verify(config_value, selection)

    monkeypatch.setattr(privacy_keys, "verify_config_generation", fail_third_verify)
    with pytest.raises(PrivacyError) as captured:
        if operation == "create":
            create_pseudonym_key(config, paths)
        else:
            load_pseudonym_key(config, paths)

    assert captured.value.code == "MH_PRIVACY_KEY_CONFIG"
    if operation == "create":
        assert not paths.pseudonym_key.exists()


@pytest.mark.parametrize("invalid", [b"not-text", 42, object()])
def test_expected_key_id_must_be_text(tmp_path: Path, invalid: object) -> None:
    config, paths = _runtime(tmp_path)

    with pytest.raises(PrivacyError) as captured:
        load_pseudonym_key(config, paths, expected_key_id=invalid)  # type: ignore[arg-type]

    assert captured.value.code == "MH_PRIVACY_KEY_ID"


@pytest.mark.parametrize("operation", ["create", "load"])
def test_key_operations_reject_invalid_epochs(tmp_path: Path, operation: str) -> None:
    config, paths = _runtime(tmp_path)

    with pytest.raises(PrivacyError) as captured:
        if operation == "create":
            create_pseudonym_key(config, paths, epoch=0)
        else:
            load_pseudonym_key(config, paths, epoch=0)

    assert captured.value.code == "MH_PRIVACY_EPOCH"
    assert not paths.pseudonym_key.exists()
