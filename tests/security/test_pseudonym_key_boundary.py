from __future__ import annotations

import ctypes
import errno
import os
import stat
import subprocess
import sys
import threading
import traceback
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

import milhouse.config.filesystem as secure_filesystem
import milhouse.privacy.keys as privacy_keys
from milhouse.config import load_config, resolve_runtime_paths
from milhouse.config._models import MilhouseConfig
from milhouse.config.paths import RuntimePaths
from milhouse.privacy import (
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
    config, selection = load_config(config_file, platform_default=config_file, env={})
    paths = resolve_runtime_paths(
        config,
        config_path=selection,
        platform_data_root=tmp_path / "platform",
        env={},
    )
    paths.pseudonym_key.parent.mkdir(parents=True, mode=0o700)
    return config, paths


def test_concurrent_exclusive_creation_has_one_winner_and_never_overwrites(
    tmp_path: Path,
) -> None:
    config, paths = _runtime(tmp_path)
    barrier = threading.Barrier(2)
    candidates = (b"A" * 32, b"B" * 32)

    def attempt(candidate: bytes) -> tuple[str, str]:
        def synchronized_entropy(size: int) -> bytes:
            barrier.wait(timeout=5)
            return candidate

        try:
            created = create_pseudonym_key(
                config,
                paths,
                random_bytes=synchronized_entropy,
            )
        except PrivacyError as error:
            return "error", error.code
        return "created", created.key_id

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = tuple(executor.map(attempt, candidates))

    created = [value for outcome, value in results if outcome == "created"]
    failures = [value for outcome, value in results if outcome == "error"]
    assert len(created) == 1
    assert failures == ["MH_PRIVACY_KEY_EXISTS"]
    assert paths.pseudonym_key.read_bytes() in candidates
    assert load_pseudonym_key(config, paths, expected_key_id=created[0]).key_id == created[0]


def test_key_failures_suppress_secret_path_and_nested_os_details(
    tmp_path: Path,
) -> None:
    config, paths = _runtime(tmp_path)
    synthetic_key = os.urandom(32)
    private_path_text = os.fspath(paths.pseudonym_key)
    nested_detail = f"{private_path_text}:{synthetic_key.hex()}:synthetic-os-detail"

    def fail_entropy(size: int) -> bytes:
        raise OSError(nested_detail)

    with pytest.raises(PrivacyError) as captured:
        create_pseudonym_key(config, paths, random_bytes=fail_entropy)

    rendered = "".join(traceback.format_exception(captured.value))
    assert captured.value.code == "MH_PRIVACY_KEY_RANDOM"
    assert captured.value.__cause__ is None
    assert captured.value.__suppress_context__ is True
    assert private_path_text not in rendered
    assert synthetic_key.hex() not in rendered
    assert "synthetic-os-detail" not in rendered


def test_symlinked_key_never_reads_the_target_material(tmp_path: Path) -> None:
    config, paths = _runtime(tmp_path)
    target_key = os.urandom(32)
    target = tmp_path / "synthetic-target.key"
    target.write_bytes(target_key)
    target.chmod(0o600)
    paths.pseudonym_key.symlink_to(target)

    with pytest.raises(PrivacyError) as captured:
        load_pseudonym_key(config, paths)

    rendered = "".join(traceback.format_exception(captured.value))
    assert captured.value.code == "MH_PRIVACY_KEY_TYPE"
    assert target_key.hex() not in rendered
    assert os.fspath(target) not in rendered
    assert os.fspath(paths.pseudonym_key) not in rendered


def test_wrong_key_continuity_check_discloses_only_a_stable_code(tmp_path: Path) -> None:
    config, paths = _runtime(tmp_path)
    synthetic_key = os.urandom(32)
    create_pseudonym_key(config, paths, random_bytes=lambda size: synthetic_key)

    with pytest.raises(PrivacyError) as captured:
        load_pseudonym_key(
            config,
            paths,
            expected_key_id="mh_pk1_0000000000000000",
        )

    rendered = "".join(traceback.format_exception(captured.value))
    assert captured.value.code == "MH_PRIVACY_KEY_ID_MISMATCH"
    assert synthetic_key.hex() not in rendered
    assert os.fspath(paths.pseudonym_key) not in rendered


@pytest.mark.skipif(sys.platform != "darwin", reason="macOS extended ACL regression")
def test_macos_extended_acl_cannot_bypass_owner_only_mode_bits(tmp_path: Path) -> None:
    config, paths = _runtime(tmp_path)
    parent = paths.pseudonym_key.parent
    subprocess.run(
        [
            "chmod",
            "+a",
            "everyone allow read,execute,file_inherit",
            os.fspath(parent),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    assert stat.S_IMODE(parent.stat().st_mode) == 0o700

    with pytest.raises(PrivacyError) as unsafe_parent:
        create_pseudonym_key(config, paths)
    assert unsafe_parent.value.code == "MH_PRIVACY_KEY_PARENT_UNSAFE"
    assert not paths.pseudonym_key.exists()

    paths.pseudonym_key.write_bytes(b"A" * 32)
    paths.pseudonym_key.chmod(0o600)
    subprocess.run(
        ["chmod", "-N", os.fspath(parent)],
        check=True,
        capture_output=True,
        text=True,
    )
    acl_listing = subprocess.run(
        ["ls", "-le", os.fspath(paths.pseudonym_key)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    assert stat.S_IMODE(parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(paths.pseudonym_key.stat().st_mode) == 0o600
    assert "everyone" in acl_listing

    with pytest.raises(PrivacyError) as unsafe_key:
        load_pseudonym_key(config, paths)
    assert unsafe_key.value.code == "MH_PRIVACY_KEY_ACL"


def test_post_publish_same_inode_overwrite_cannot_report_false_key_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, paths = _runtime(tmp_path)
    created_key = b"A" * 32
    replacement_key = b"B" * 32
    real_rename = secure_filesystem._rename_no_replace

    def rename_then_overwrite(
        directory_descriptor: int,
        staged_leaf: str,
        final_leaf: str,
        *,
        primitive: object,
        flag: int,
    ) -> None:
        real_rename(
            directory_descriptor,
            staged_leaf,
            final_leaf,
            primitive=primitive,
            flag=flag,
        )
        descriptor = os.open(final_leaf, os.O_WRONLY, dir_fd=directory_descriptor)
        try:
            assert os.pwrite(descriptor, replacement_key, 0) == len(replacement_key)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    monkeypatch.setattr(secure_filesystem, "_rename_no_replace", rename_then_overwrite)
    with pytest.raises(PseudonymKeyCommitUncertain) as captured:
        create_pseudonym_key(
            config,
            paths,
            random_bytes=lambda size: created_key,
        )

    loaded = load_pseudonym_key(config, paths)
    assert captured.value.key_id != loaded.key_id
    assert paths.pseudonym_key.read_bytes() == replacement_key


def test_rename_eio_after_namespace_change_preserves_recoverable_key(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, paths = _runtime(tmp_path)
    key = b"E" * 32

    def rename_then_report_eio(
        source_directory: int,
        source: bytes,
        destination_directory: int,
        destination: bytes,
        _flag: int,
    ) -> int:
        os.rename(
            source,
            destination,
            src_dir_fd=source_directory,
            dst_dir_fd=destination_directory,
        )
        ctypes.set_errno(errno.EIO)
        return -1

    monkeypatch.setattr(
        secure_filesystem,
        "_exclusive_rename_primitive",
        lambda: (rename_then_report_eio, 1),
    )
    with pytest.raises(PseudonymKeyCommitUncertain) as captured:
        create_pseudonym_key(config, paths, random_bytes=lambda size: key)

    assert paths.pseudonym_key.read_bytes() == key
    recovered = recover_pseudonym_key_creation(
        config,
        paths,
        expected_key_id=captured.value.key_id,
    )
    assert recovered.key_id == captured.value.key_id


def test_publication_cancellation_cannot_sanitize_an_already_renamed_key(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, paths = _runtime(tmp_path)
    key = b"K" * 32

    def rename_then_cancel(
        source_directory: int,
        source: bytes,
        destination_directory: int,
        destination: bytes,
        _flag: int,
    ) -> int:
        os.rename(
            source,
            destination,
            src_dir_fd=source_directory,
            dst_dir_fd=destination_directory,
        )
        raise KeyboardInterrupt

    monkeypatch.setattr(
        secure_filesystem,
        "_exclusive_rename_primitive",
        lambda: (rename_then_cancel, 1),
    )
    with pytest.raises(KeyboardInterrupt):
        create_pseudonym_key(config, paths, random_bytes=lambda size: key)

    assert paths.pseudonym_key.read_bytes() == key
    assert load_pseudonym_key(config, paths).key_id


def test_process_exit_before_atomic_publication_never_leaves_a_partial_final_key(
    tmp_path: Path,
) -> None:
    config, paths = _runtime(tmp_path)
    interrupted_key = b"I" * 32
    replacement_key = b"R" * 32
    child = os.fork()
    if child == 0:  # pragma: no branch - child exits at the injected boundary
        real_bound = privacy_keys._bound_key_path
        calls = 0

        def exit_during_prepublication(config_value, paths_value):
            nonlocal calls
            result = real_bound(config_value, paths_value)
            calls += 1
            if calls == 2:
                os._exit(23)
            return result

        privacy_keys._bound_key_path = exit_during_prepublication
        create_pseudonym_key(
            config,
            paths,
            random_bytes=lambda size: interrupted_key,
        )
        os._exit(99)

    waited, status = os.waitpid(child, 0)
    assert waited == child
    assert os.waitstatus_to_exitcode(status) == 23
    assert not paths.pseudonym_key.exists()

    created = create_pseudonym_key(
        config,
        paths,
        random_bytes=lambda size: replacement_key,
    )
    assert paths.pseudonym_key.read_bytes() == replacement_key
    assert created.key_id == load_pseudonym_key(config, paths).key_id
