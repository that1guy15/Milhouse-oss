from __future__ import annotations

import os
from importlib import metadata
from pathlib import Path

import pytest

import milhouse.config.plugins as plugin_validation


def _path_distribution(root: object) -> metadata.PathDistribution:
    return metadata.PathDistribution(root)  # type: ignore[arg-type]


def _directory_handle(path: Path) -> plugin_validation._DirectoryHandle:
    handle = plugin_validation._open_metadata_directory(str(path))
    assert handle is not None
    return handle


def test_path_distribution_root_normalizes_hostile_or_unsupported_paths() -> None:
    class HostilePath:
        def __fspath__(self) -> str:
            raise RuntimeError("private-path-canary")

    assert plugin_validation._path_distribution_root(_path_distribution(HostilePath())) is None
    assert (
        plugin_validation._path_distribution_root(_path_distribution("relative.dist-info")) is None
    )
    assert (
        plugin_validation._path_distribution_root(_path_distribution(Path("bad\x00path"))) is None
    )


def test_relative_path_distribution_is_refused_before_filesystem_access(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("relative plugin metadata reached filesystem access")

    monkeypatch.setattr(os, "lstat", forbidden)
    monkeypatch.setattr(os, "open", forbidden)
    monkeypatch.setattr(plugin_validation, "_read_bounded_regular_file", forbidden)
    distribution = metadata.PathDistribution(Path("relative-plugin.dist-info"))

    result = plugin_validation._read_distribution_files(distribution)

    assert result.status is plugin_validation._DistributionFilesStatus.INVALID


def test_descriptor_close_failure_is_normalized(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "close", lambda _descriptor: (_ for _ in ()).throw(OSError()))

    assert plugin_validation._close_descriptor(123) is None


def test_metadata_directory_refuses_non_directory_and_lstat_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    regular_file = tmp_path / "METADATA"
    regular_file.write_text("metadata", encoding="utf-8")
    assert plugin_validation._open_metadata_directory(str(regular_file)) is None

    monkeypatch.setattr(os, "lstat", lambda _root: (_ for _ in ()).throw(OSError()))
    assert plugin_validation._open_metadata_directory(str(tmp_path)) is None


def test_metadata_directory_closes_descriptor_after_fstat_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_fstat = os.fstat
    closed: list[int] = []
    monkeypatch.setattr(os, "fstat", lambda _descriptor: (_ for _ in ()).throw(OSError()))
    monkeypatch.setattr(plugin_validation, "_close_descriptor", closed.append)

    assert plugin_validation._open_metadata_directory(str(tmp_path)) is None
    assert len(closed) == 1

    monkeypatch.setattr(os, "fstat", real_fstat)


def test_metadata_directory_refuses_changed_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    closed: list[int] = []
    monkeypatch.setattr(plugin_validation, "_same_snapshot", lambda _left, _right: False)
    monkeypatch.setattr(plugin_validation, "_close_descriptor", closed.append)

    assert plugin_validation._open_metadata_directory(str(tmp_path)) is None
    assert len(closed) == 1


def test_bounded_file_reader_handles_missing_invalid_and_non_regular_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    child_directory = tmp_path / "child"
    child_directory.mkdir()
    handle = _directory_handle(tmp_path)
    try:
        missing = plugin_validation._read_bounded_regular_file(
            handle,
            "missing",
            limit=16,
        )
        non_regular = plugin_validation._read_bounded_regular_file(
            handle,
            "child",
            limit=16,
        )

        real_stat = os.stat

        def broken_stat(
            path: str,
            *,
            dir_fd: int | None = None,
            follow_symlinks: bool = True,
        ) -> os.stat_result:
            if path == "broken":
                raise OSError
            return real_stat(path, dir_fd=dir_fd, follow_symlinks=follow_symlinks)

        monkeypatch.setattr(os, "stat", broken_stat)
        invalid = plugin_validation._read_bounded_regular_file(handle, "broken", limit=16)
    finally:
        plugin_validation._close_descriptor(handle.descriptor)

    assert missing.status is plugin_validation._FileReadStatus.MISSING
    assert non_regular.status is plugin_validation._FileReadStatus.INVALID
    assert invalid.status is plugin_validation._FileReadStatus.INVALID


def test_bounded_file_reader_refuses_opened_snapshot_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "METADATA").write_bytes(b"x")
    handle = _directory_handle(tmp_path)
    monkeypatch.setattr(plugin_validation, "_same_snapshot", lambda _left, _right: False)
    try:
        result = plugin_validation._read_bounded_regular_file(handle, "METADATA", limit=16)
    finally:
        plugin_validation._close_descriptor(handle.descriptor)

    assert result.status is plugin_validation._FileReadStatus.INVALID


def test_bounded_file_reader_stops_at_limit_when_file_grows_after_stat(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "METADATA").write_bytes(b"x")
    handle = _directory_handle(tmp_path)
    monkeypatch.setattr(os, "read", lambda _descriptor, requested: b"x" * requested)
    try:
        result = plugin_validation._read_bounded_regular_file(handle, "METADATA", limit=3)
    finally:
        plugin_validation._close_descriptor(handle.descriptor)

    assert result.status is plugin_validation._FileReadStatus.TOO_LARGE


def test_bounded_file_reader_refuses_changed_post_read_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "METADATA").write_bytes(b"x")
    handle = _directory_handle(tmp_path)
    comparisons = iter((True, False))
    monkeypatch.setattr(
        plugin_validation,
        "_same_snapshot",
        lambda _left, _right: next(comparisons),
    )
    try:
        result = plugin_validation._read_bounded_regular_file(handle, "METADATA", limit=16)
    finally:
        plugin_validation._close_descriptor(handle.descriptor)

    assert result.status is plugin_validation._FileReadStatus.INVALID


@pytest.mark.parametrize("failure", ["open", "read"])
def test_bounded_file_reader_normalizes_open_and_read_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    (tmp_path / "METADATA").write_bytes(b"x")
    handle = _directory_handle(tmp_path)
    if failure == "open":
        monkeypatch.setattr(os, "open", lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError()))
    else:
        monkeypatch.setattr(os, "read", lambda *_args: (_ for _ in ()).throw(OSError()))
    try:
        result = plugin_validation._read_bounded_regular_file(handle, "METADATA", limit=16)
    finally:
        plugin_validation._close_descriptor(handle.descriptor)

    assert result.status is plugin_validation._FileReadStatus.INVALID


def test_distribution_files_accept_pkg_info_and_absent_entry_points(tmp_path: Path) -> None:
    dist_info = tmp_path / "fallback.dist-info"
    dist_info.mkdir()
    expected = b"Name: fallback\nVersion: 1.0\n"
    (dist_info / "PKG-INFO").write_bytes(expected)

    result = plugin_validation._read_distribution_files(metadata.PathDistribution(dist_info))

    assert result == plugin_validation._DistributionFilesResult(
        plugin_validation._DistributionFilesStatus.OK,
        core_metadata=expected,
        entry_points=b"",
    )


def test_distribution_files_refuse_unopenable_directory(tmp_path: Path) -> None:
    distribution = metadata.PathDistribution(tmp_path / "missing.dist-info")

    result = plugin_validation._read_distribution_files(distribution)

    assert result.status is plugin_validation._DistributionFilesStatus.INVALID


@pytest.mark.parametrize(
    ("core", "entry_points", "expected"),
    [
        (
            plugin_validation._FileReadResult(plugin_validation._FileReadStatus.TOO_LARGE),
            plugin_validation._FileReadResult(plugin_validation._FileReadStatus.OK),
            plugin_validation._DistributionFilesStatus.TOO_LARGE,
        ),
        (
            plugin_validation._FileReadResult(plugin_validation._FileReadStatus.OK),
            plugin_validation._FileReadResult(plugin_validation._FileReadStatus.TOO_LARGE),
            plugin_validation._DistributionFilesStatus.TOO_LARGE,
        ),
        (
            plugin_validation._FileReadResult(plugin_validation._FileReadStatus.INVALID),
            plugin_validation._FileReadResult(plugin_validation._FileReadStatus.OK),
            plugin_validation._DistributionFilesStatus.INVALID,
        ),
        (
            plugin_validation._FileReadResult(
                plugin_validation._FileReadStatus.OK,
                b"Name: example\nVersion: 1\n",
            ),
            plugin_validation._FileReadResult(plugin_validation._FileReadStatus.INVALID),
            plugin_validation._DistributionFilesStatus.INVALID,
        ),
    ],
)
def test_distribution_file_statuses_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    core: plugin_validation._FileReadResult,
    entry_points: plugin_validation._FileReadResult,
    expected: plugin_validation._DistributionFilesStatus,
) -> None:
    distribution = metadata.PathDistribution(tmp_path)
    snapshot = os.stat(tmp_path)
    handle = plugin_validation._DirectoryHandle(123, snapshot)
    monkeypatch.setattr(plugin_validation, "_open_metadata_directory", lambda _root: handle)
    monkeypatch.setattr(plugin_validation, "_close_descriptor", lambda _descriptor: None)
    monkeypatch.setattr(os, "fstat", lambda _descriptor: snapshot)

    def reader(
        _directory: plugin_validation._DirectoryHandle,
        filename: str,
        *,
        limit: int,
    ) -> plugin_validation._FileReadResult:
        del limit
        return core if filename == "METADATA" else entry_points

    monkeypatch.setattr(plugin_validation, "_read_bounded_regular_file", reader)

    result = plugin_validation._read_distribution_files(distribution)

    assert result.status is expected


@pytest.mark.parametrize("changed", [False, True])
def test_distribution_files_refuse_unreadable_or_changed_directory_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    changed: bool,
) -> None:
    distribution = metadata.PathDistribution(tmp_path)
    snapshot = os.stat(tmp_path)
    handle = plugin_validation._DirectoryHandle(123, snapshot)
    monkeypatch.setattr(plugin_validation, "_open_metadata_directory", lambda _root: handle)
    monkeypatch.setattr(plugin_validation, "_close_descriptor", lambda _descriptor: None)
    monkeypatch.setattr(
        plugin_validation,
        "_read_bounded_regular_file",
        lambda *_args, **_kwargs: plugin_validation._FileReadResult(
            plugin_validation._FileReadStatus.OK,
            b"metadata",
        ),
    )
    if changed:
        monkeypatch.setattr(plugin_validation, "_same_snapshot", lambda _left, _right: False)
    else:
        monkeypatch.setattr(os, "fstat", lambda _descriptor: (_ for _ in ()).throw(OSError()))

    result = plugin_validation._read_distribution_files(distribution)

    assert result.status is plugin_validation._DistributionFilesStatus.INVALID


@pytest.mark.parametrize(
    "contents",
    [
        b"\xff",
        b"Name: example\rbroken\nVersion: 1\n",
        b"Name: example\n continuation\nVersion: 1\n",
        b"malformed\nName: example\nVersion: 1\n",
        b"Name: example\nName: duplicate\nVersion: 1\n",
        b"Name: \nVersion: 1\n",
    ],
)
def test_core_metadata_parser_refuses_malformed_headers(contents: bytes) -> None:
    assert plugin_validation._parse_core_metadata(contents) is None


def test_core_metadata_parser_accepts_crlf_and_unrelated_continuations() -> None:
    contents = (
        b"Metadata-Version: 2.4\r\n"
        b"X-Note: first\r\n"
        b" continuation\r\n"
        b"Name: example-plugin\r\n"
        b"Version: 1!2.0\r\n\r\nbody"
    )

    assert plugin_validation._parse_core_metadata(contents) == ("example-plugin", "1!2.0")


@pytest.mark.parametrize(
    "contents",
    [
        b"\xff",
        b"# comment\n; comment\n",
        b"[milhouse.collectors]\n[milhouse.collectors]\n",
        b"[milhouse.collectors]\n = module:Collector\n",
        b"[milhouse.collectors]\nentry = \n",
        (b"[milhouse.collectors]\nentry = module:Collector\nentry = module:Collector\n"),
    ],
)
def test_entry_point_parser_handles_comments_and_refuses_malformed_values(
    contents: bytes,
) -> None:
    result = plugin_validation._parse_entry_points(contents)

    if contents.startswith(b"#"):
        assert result.status is plugin_validation._EntryPointsStatus.OK
    else:
        assert result.status is plugin_validation._EntryPointsStatus.INVALID
