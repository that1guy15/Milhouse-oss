from __future__ import annotations

import os
from pathlib import Path

import pytest

import milhouse.config.filesystem as config_filesystem
from milhouse.config.filesystem import (
    SecureFileError,
    SecureFileErrorKind,
    inspect_regular_file_no_follow,
    lexical_absolute_path,
    open_regular_file_no_follow,
)


def test_secure_file_objects_have_value_safe_representations(tmp_path: Path) -> None:
    path = tmp_path / "private-fragment-0123456789.toml"
    path.write_text("config_version = 1\n", encoding="utf-8")

    opened = open_regular_file_no_follow(path)
    try:
        assert repr(opened) == "OpenedRegularFile(open=True)"
        assert repr(opened.selection) == "FileSelection(selected=True)"
        assert os.fspath(path) not in repr(opened)
        assert os.fspath(path) not in repr(opened.selection)
    finally:
        os.close(opened.descriptor)


def test_internal_directory_walk_rejects_a_relative_path() -> None:
    with pytest.raises(SecureFileError) as excinfo:
        config_filesystem._open_directory_chain(Path("relative.toml"), nofollow=1)

    assert excinfo.value.kind is SecureFileErrorKind.INVALID


def test_lexical_path_normalization_failure_is_value_safe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_fragment = "private-normalization-fragment-0123456789"

    def fail_normalization(_value: str) -> str:
        raise ValueError(private_fragment)

    monkeypatch.setattr(config_filesystem.os.path, "normpath", fail_normalization)

    with pytest.raises(SecureFileError) as excinfo:
        lexical_absolute_path("selected.toml")

    assert excinfo.value.kind is SecureFileErrorKind.INVALID
    assert private_fragment not in str(excinfo.value)


def test_inspection_translates_descriptor_close_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "config.toml"
    path.write_text("config_version = 1\n", encoding="utf-8")
    opened = open_regular_file_no_follow(path)
    real_close = os.close

    def fail_close(_descriptor: int) -> None:
        raise OSError

    monkeypatch.setattr(config_filesystem, "open_regular_file_no_follow", lambda _path: opened)
    monkeypatch.setattr(config_filesystem.os, "close", fail_close)

    try:
        with pytest.raises(SecureFileError) as excinfo:
            inspect_regular_file_no_follow(path)
    finally:
        real_close(opened.descriptor)

    assert excinfo.value.kind is SecureFileErrorKind.UNREADABLE
