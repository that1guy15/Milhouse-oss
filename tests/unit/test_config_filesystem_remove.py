"""Tests for the secure descriptor-relative file removal primitive (W03 slice 5b part 2).

``remove_regular_file_no_follow`` unlinks one owner-only, single-link regular file relative to its
no-follow-opened private parent and fsyncs the parent, refusing a symlink, directory, hard-linked,
or identity-mismatched leaf, a non-private or symlinked-ancestor parent, and normalizing every fault
to a fixed :class:`SecureFileError`.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

import milhouse.config.filesystem as config_filesystem
from milhouse.config.filesystem import (
    FileIdentity,
    SecureFileError,
    SecureFileErrorKind,
    remove_regular_file_no_follow,
)


def _private_file(tmp_path: Path, name: str = "segment.jsonl") -> tuple[Path, Path]:
    directory = tmp_path / "day"
    directory.mkdir(mode=0o700)
    os.chmod(directory, 0o700)  # defeat the inherited umask
    path = directory / name
    path.write_bytes(b"segment-bytes\n")
    os.chmod(path, 0o600)
    return directory, path


def test_removes_a_private_regular_file(tmp_path: Path) -> None:
    _directory, path = _private_file(tmp_path)
    remove_regular_file_no_follow(path)
    assert not path.exists()


def test_removes_with_a_matching_expected_identity(tmp_path: Path) -> None:
    _directory, path = _private_file(tmp_path)
    identity = FileIdentity.from_stat(path.stat())
    remove_regular_file_no_follow(path, expected_identity=identity)
    assert not path.exists()


def test_refuses_a_mismatched_expected_identity(tmp_path: Path) -> None:
    _directory, path = _private_file(tmp_path)
    actual = FileIdentity.from_stat(path.stat())
    with pytest.raises(SecureFileError) as captured:
        remove_regular_file_no_follow(
            path, expected_identity=FileIdentity(device=actual.device, inode=actual.inode + 1)
        )
    assert captured.value.kind is SecureFileErrorKind.CHANGED
    assert path.exists()  # a swapped-in file is refused, not unlinked


def test_refuses_a_missing_file(tmp_path: Path) -> None:
    directory, _path = _private_file(tmp_path)
    with pytest.raises(SecureFileError) as captured:
        remove_regular_file_no_follow(directory / "absent.jsonl")
    assert captured.value.kind is SecureFileErrorKind.NOT_FOUND


def test_refuses_a_symlink_leaf(tmp_path: Path) -> None:
    directory, path = _private_file(tmp_path)
    link = directory / "link.jsonl"
    link.symlink_to(path)
    with pytest.raises(SecureFileError) as captured:
        remove_regular_file_no_follow(link)
    assert captured.value.kind is SecureFileErrorKind.NOT_REGULAR
    assert link.is_symlink() and path.exists()  # neither the link nor its target is removed


def test_refuses_a_directory_leaf(tmp_path: Path) -> None:
    directory, _path = _private_file(tmp_path)
    subdirectory = directory / "sub"
    subdirectory.mkdir(mode=0o700)
    with pytest.raises(SecureFileError) as captured:
        remove_regular_file_no_follow(subdirectory)
    assert captured.value.kind is SecureFileErrorKind.NOT_REGULAR
    assert subdirectory.is_dir()


def test_refuses_a_hard_linked_file(tmp_path: Path) -> None:
    directory, path = _private_file(tmp_path)
    os.link(path, directory / "alias.jsonl")  # nlink becomes 2
    with pytest.raises(SecureFileError) as captured:
        remove_regular_file_no_follow(path)
    assert captured.value.kind is SecureFileErrorKind.NOT_REGULAR
    assert path.exists()  # unlinking one name would not remove the data


def test_refuses_a_non_private_parent(tmp_path: Path) -> None:
    directory, path = _private_file(tmp_path)
    os.chmod(directory, 0o755)
    with pytest.raises(SecureFileError) as captured:
        remove_regular_file_no_follow(path)
    assert captured.value.kind is SecureFileErrorKind.PARENT_UNSAFE
    assert path.exists()


def test_refuses_a_symlinked_ancestor(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir(mode=0o700)
    os.chmod(real, 0o700)
    path = real / "segment.jsonl"
    path.write_bytes(b"bytes\n")
    os.chmod(path, 0o600)
    alias = tmp_path / "alias"
    alias.symlink_to(real, target_is_directory=True)
    with pytest.raises(SecureFileError) as captured:
        remove_regular_file_no_follow(alias / "segment.jsonl")
    assert captured.value.kind is SecureFileErrorKind.NOT_REGULAR  # ELOOP on the no-follow chain
    assert path.exists()


def test_security_unsupported_without_no_follow(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _directory, path = _private_file(tmp_path)
    monkeypatch.setattr(config_filesystem.os, "O_NOFOLLOW", 0)
    with pytest.raises(SecureFileError) as captured:
        remove_regular_file_no_follow(path)
    assert captured.value.kind is SecureFileErrorKind.SECURITY_UNSUPPORTED
    assert path.exists()


def test_security_unsupported_without_geteuid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _directory, path = _private_file(tmp_path)
    monkeypatch.delattr(config_filesystem.os, "geteuid")
    with pytest.raises(SecureFileError) as captured:
        remove_regular_file_no_follow(path)
    assert captured.value.kind is SecureFileErrorKind.SECURITY_UNSUPPORTED


def test_an_unlink_failure_normalizes_to_write_failed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _directory, path = _private_file(tmp_path)
    real_unlink = config_filesystem.os.unlink

    def failing_unlink(name: object, *args: object, **kwargs: object) -> None:
        raise OSError("private-unlink-detail")

    monkeypatch.setattr(config_filesystem.os, "unlink", failing_unlink)
    with pytest.raises(SecureFileError) as captured:
        remove_regular_file_no_follow(path)
    assert captured.value.kind is SecureFileErrorKind.WRITE_FAILED
    assert "private" not in str(captured.value)
    monkeypatch.undo()
    assert real_unlink is config_filesystem.os.unlink


def test_a_value_error_normalizes_to_invalid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _directory, path = _private_file(tmp_path)

    def raising_stat(*args: object, **kwargs: object) -> os.stat_result:
        raise ValueError("private-value-detail")

    monkeypatch.setattr(config_filesystem.os, "stat", raising_stat)
    with pytest.raises(SecureFileError) as captured:
        remove_regular_file_no_follow(path)
    assert captured.value.kind is SecureFileErrorKind.INVALID
    assert "private" not in str(captured.value)


def test_an_unexpected_error_normalizes_to_write_failed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _directory, path = _private_file(tmp_path)

    def raising_stat(*args: object, **kwargs: object) -> os.stat_result:
        raise RuntimeError("private-runtime-detail")

    monkeypatch.setattr(config_filesystem.os, "stat", raising_stat)
    with pytest.raises(SecureFileError) as captured:
        remove_regular_file_no_follow(path)
    assert captured.value.kind is SecureFileErrorKind.WRITE_FAILED
    assert "private" not in str(captured.value)


def test_a_close_failure_after_a_successful_unlink_is_unreadable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _directory, path = _private_file(tmp_path)
    real_chain = config_filesystem._open_directory_chain
    real_close = config_filesystem.os.close
    parent_descriptor: int | None = None

    def capture_parent(selected_path: Path, *, nofollow: int) -> tuple[int, str]:
        nonlocal parent_descriptor
        parent_descriptor, leaf = real_chain(selected_path, nofollow=nofollow)
        return parent_descriptor, leaf

    def failing_close(descriptor: int) -> None:
        real_close(descriptor)
        if descriptor == parent_descriptor:
            raise OSError("private-close-detail")

    monkeypatch.setattr(config_filesystem, "_open_directory_chain", capture_parent)
    monkeypatch.setattr(config_filesystem.os, "close", failing_close)
    with pytest.raises(SecureFileError) as captured:
        remove_regular_file_no_follow(path)
    assert captured.value.kind is SecureFileErrorKind.UNREADABLE
    assert not path.exists()  # the unlink itself still succeeded
    assert "private" not in str(captured.value)


def test_a_close_failure_does_not_mask_a_prior_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    directory, _path = _private_file(tmp_path)
    real_chain = config_filesystem._open_directory_chain
    real_close = config_filesystem.os.close
    parent_descriptor: int | None = None

    def capture_parent(selected_path: Path, *, nofollow: int) -> tuple[int, str]:
        nonlocal parent_descriptor
        parent_descriptor, leaf = real_chain(selected_path, nofollow=nofollow)
        return parent_descriptor, leaf

    def failing_close(descriptor: int) -> None:
        real_close(descriptor)
        if descriptor == parent_descriptor:
            raise OSError("private-close-detail")

    monkeypatch.setattr(config_filesystem, "_open_directory_chain", capture_parent)
    monkeypatch.setattr(config_filesystem.os, "close", failing_close)
    # The leaf is missing, so the primary failure is NOT_FOUND; a later close failure must not
    # overwrite it with UNREADABLE.
    with pytest.raises(SecureFileError) as captured:
        remove_regular_file_no_follow(directory / "absent.jsonl")
    assert captured.value.kind is SecureFileErrorKind.NOT_FOUND
