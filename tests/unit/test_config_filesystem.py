from __future__ import annotations

import errno
import os
import stat
from pathlib import Path

import pytest

import milhouse.config.filesystem as config_filesystem
from milhouse.config.filesystem import (
    FileIdentity,
    FileSelection,
    SecureFileError,
    SecureFileErrorKind,
    create_regular_file_no_follow,
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

    monkeypatch.setattr(
        config_filesystem,
        "open_regular_file_no_follow",
        lambda _path, **_kwargs: opened,
    )
    monkeypatch.setattr(config_filesystem.os, "close", fail_close)

    try:
        with pytest.raises(SecureFileError) as excinfo:
            inspect_regular_file_no_follow(path)
    finally:
        real_close(opened.descriptor)

    assert excinfo.value.kind is SecureFileErrorKind.UNREADABLE


@pytest.mark.parametrize(
    ("content", "mode"),
    [
        (b"", 0o600),
        (bytearray(b"value"), 0o600),
        (b"value", 0),
        (b"value", True),
        (b"value", 0o1000),
    ],
)
def test_exclusive_create_rejects_invalid_content_or_mode(
    tmp_path: Path,
    content: object,
    mode: object,
) -> None:
    with pytest.raises(SecureFileError) as excinfo:
        create_regular_file_no_follow(  # type: ignore[arg-type]
            tmp_path / "runtime.bin",
            content,
            mode=mode,
        )

    assert excinfo.value.kind is SecureFileErrorKind.INVALID


def test_exclusive_create_and_open_fail_without_nofollow_support(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(config_filesystem.os, "O_NOFOLLOW", 0)

    with pytest.raises(SecureFileError) as create_error:
        create_regular_file_no_follow(tmp_path / "runtime.bin", b"value", mode=0o600)
    with pytest.raises(SecureFileError) as open_error:
        open_regular_file_no_follow(tmp_path / "runtime.bin")

    assert create_error.value.kind is SecureFileErrorKind.SECURITY_UNSUPPORTED
    assert open_error.value.kind is SecureFileErrorKind.SECURITY_UNSUPPORTED


def test_exclusive_create_rejects_noncallable_before_publish(tmp_path: Path) -> None:
    with pytest.raises(SecureFileError) as excinfo:
        create_regular_file_no_follow(
            tmp_path / "runtime.bin",
            b"value",
            mode=0o600,
            before_publish=object(),  # type: ignore[arg-type]
        )

    assert excinfo.value.kind is SecureFileErrorKind.INVALID


def test_exclusive_rename_platform_selection_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeFunction:
        argtypes: object = None
        restype: object = None

        def __call__(self, *args: object) -> int:
            return 0

    class LinuxLibrary:
        renameat2 = FakeFunction()

    class MacLibrary:
        renameatx_np = FakeFunction()

    monkeypatch.setattr(config_filesystem.sys, "platform", "darwin")
    monkeypatch.setattr(
        config_filesystem.ctypes,
        "CDLL",
        lambda *args, **kwargs: MacLibrary(),
    )
    _primitive, flag = config_filesystem._exclusive_rename_primitive()
    assert flag == 4

    monkeypatch.setattr(config_filesystem.sys, "platform", "linux")
    monkeypatch.setattr(
        config_filesystem.ctypes,
        "CDLL",
        lambda *args, **kwargs: LinuxLibrary(),
    )
    _primitive, flag = config_filesystem._exclusive_rename_primitive()
    assert flag == 1

    monkeypatch.setattr(config_filesystem.ctypes, "CDLL", lambda *args, **kwargs: object())
    with pytest.raises(SecureFileError) as missing_symbol:
        config_filesystem._exclusive_rename_primitive()
    assert missing_symbol.value.kind is SecureFileErrorKind.SECURITY_UNSUPPORTED

    monkeypatch.setattr(config_filesystem.sys, "platform", "unsupported")
    with pytest.raises(SecureFileError) as unsupported:
        config_filesystem._exclusive_rename_primitive()
    assert unsupported.value.kind is SecureFileErrorKind.SECURITY_UNSUPPORTED


class _FakeCFunction:
    def __init__(self, result: object) -> None:
        self.argtypes: object = None
        self.restype: object = None
        self._result = result

    def __call__(self, *args: object) -> object:
        if isinstance(self._result, BaseException):
            raise self._result
        if callable(self._result):
            return self._result(*args)
        return self._result


def test_macos_acl_probe_fails_closed_on_an_unexpected_query_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_acl_query(*args: object) -> None:
        config_filesystem.ctypes.set_errno(errno.EIO)
        return None

    class MacLibrary:
        acl_get_fd_np = _FakeCFunction(fail_acl_query)
        acl_free = _FakeCFunction(0)

    monkeypatch.setattr(config_filesystem.ctypes, "CDLL", lambda *args, **kwargs: MacLibrary())
    with pytest.raises(SecureFileError) as excinfo:
        config_filesystem._macos_descriptor_has_extended_acl(3)

    assert excinfo.value.kind is SecureFileErrorKind.SECURITY_UNSUPPORTED


@pytest.mark.parametrize("no_acl_error", [errno.ENOENT, 9876])
def test_macos_acl_probe_accepts_only_documented_absent_acl_errors(
    monkeypatch: pytest.MonkeyPatch,
    no_acl_error: int,
) -> None:
    if no_acl_error != errno.ENOENT:
        monkeypatch.setattr(config_filesystem.errno, "ENOATTR", no_acl_error, raising=False)

    def no_acl(*args: object) -> None:
        config_filesystem.ctypes.set_errno(no_acl_error)
        return None

    class MacLibrary:
        acl_get_fd_np = _FakeCFunction(no_acl)
        acl_free = _FakeCFunction(0)

    monkeypatch.setattr(config_filesystem.ctypes, "CDLL", lambda *args, **kwargs: MacLibrary())

    assert config_filesystem._macos_descriptor_has_extended_acl(3) is False


def test_macos_acl_probe_fails_closed_when_functions_are_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(config_filesystem.ctypes, "CDLL", lambda *args, **kwargs: object())

    with pytest.raises(SecureFileError) as excinfo:
        config_filesystem._macos_descriptor_has_extended_acl(3)

    assert excinfo.value.kind is SecureFileErrorKind.SECURITY_UNSUPPORTED


def test_macos_acl_probe_translates_unexpected_runtime_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class MacLibrary:
        acl_get_fd_np = _FakeCFunction(RuntimeError("private-acl-query-detail"))
        acl_free = _FakeCFunction(0)

    monkeypatch.setattr(config_filesystem.ctypes, "CDLL", lambda *args, **kwargs: MacLibrary())
    with pytest.raises(SecureFileError) as excinfo:
        config_filesystem._macos_descriptor_has_extended_acl(3)

    assert excinfo.value.kind is SecureFileErrorKind.SECURITY_UNSUPPORTED
    assert "private-acl-query-detail" not in str(excinfo.value)


def test_macos_acl_probe_translates_acl_free_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class MacLibrary:
        acl_get_fd_np = _FakeCFunction(1)
        acl_free = _FakeCFunction(RuntimeError("private-acl-free-detail"))

    monkeypatch.setattr(config_filesystem.ctypes, "CDLL", lambda *args, **kwargs: MacLibrary())
    with pytest.raises(SecureFileError) as excinfo:
        config_filesystem._macos_descriptor_has_extended_acl(3)

    assert excinfo.value.kind is SecureFileErrorKind.SECURITY_UNSUPPORTED
    assert "private-acl-free-detail" not in str(excinfo.value)


@pytest.mark.parametrize(
    ("responses", "expected"),
    [
        ((0,), True),
        ((-1, 0), True),
        ((-1, -1), False),
    ],
)
def test_linux_acl_probe_detects_access_and_default_acl_xattrs(
    monkeypatch: pytest.MonkeyPatch,
    responses: tuple[int, ...],
    expected: bool,
) -> None:
    pending = list(responses)

    def query_acl(*args: object) -> int:
        result = pending.pop(0)
        if result < 0:
            config_filesystem.ctypes.set_errno(errno.ENODATA)
        return result

    class LinuxLibrary:
        fgetxattr = _FakeCFunction(query_acl)

    monkeypatch.setattr(config_filesystem.ctypes, "CDLL", lambda *args, **kwargs: LinuxLibrary())

    assert config_filesystem._linux_descriptor_has_extended_acl(3) is expected
    assert not pending


def test_linux_acl_probe_accepts_the_platform_enoattr_alias(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    enoattr = 9876
    monkeypatch.setattr(config_filesystem.errno, "ENOATTR", enoattr, raising=False)

    def no_acl(*args: object) -> int:
        config_filesystem.ctypes.set_errno(enoattr)
        return -1

    class LinuxLibrary:
        fgetxattr = _FakeCFunction(no_acl)

    monkeypatch.setattr(config_filesystem.ctypes, "CDLL", lambda *args, **kwargs: LinuxLibrary())

    assert config_filesystem._linux_descriptor_has_extended_acl(3) is False


def test_linux_acl_probe_fails_closed_on_an_unexpected_query_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_acl_query(*args: object) -> int:
        config_filesystem.ctypes.set_errno(errno.EIO)
        return -1

    class LinuxLibrary:
        fgetxattr = _FakeCFunction(fail_acl_query)

    monkeypatch.setattr(config_filesystem.ctypes, "CDLL", lambda *args, **kwargs: LinuxLibrary())
    with pytest.raises(SecureFileError) as excinfo:
        config_filesystem._linux_descriptor_has_extended_acl(3)

    assert excinfo.value.kind is SecureFileErrorKind.SECURITY_UNSUPPORTED


def test_linux_acl_probe_fails_closed_when_functions_are_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(config_filesystem.ctypes, "CDLL", lambda *args, **kwargs: object())

    with pytest.raises(SecureFileError) as excinfo:
        config_filesystem._linux_descriptor_has_extended_acl(3)

    assert excinfo.value.kind is SecureFileErrorKind.SECURITY_UNSUPPORTED


def test_linux_acl_probe_translates_unexpected_runtime_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class LinuxLibrary:
        fgetxattr = _FakeCFunction(RuntimeError("private-xattr-detail"))

    monkeypatch.setattr(config_filesystem.ctypes, "CDLL", lambda *args, **kwargs: LinuxLibrary())
    with pytest.raises(SecureFileError) as excinfo:
        config_filesystem._linux_descriptor_has_extended_acl(3)

    assert excinfo.value.kind is SecureFileErrorKind.SECURITY_UNSUPPORTED
    assert "private-xattr-detail" not in str(excinfo.value)


@pytest.mark.parametrize(
    ("platform", "helper_name"),
    [
        ("darwin", "_macos_descriptor_has_extended_acl"),
        ("linux", "_linux_descriptor_has_extended_acl"),
    ],
)
def test_acl_dispatcher_selects_supported_platform(
    monkeypatch: pytest.MonkeyPatch,
    platform: str,
    helper_name: str,
) -> None:
    calls: list[int] = []
    monkeypatch.setattr(config_filesystem.sys, "platform", platform)
    monkeypatch.setattr(
        config_filesystem,
        helper_name,
        lambda descriptor: calls.append(descriptor) or False,
    )

    assert config_filesystem._descriptor_has_extended_acl(3) is False
    assert calls == [3]


def test_acl_dispatcher_rejects_unsupported_platform(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config_filesystem.sys, "platform", "unsupported")

    with pytest.raises(SecureFileError) as excinfo:
        config_filesystem._descriptor_has_extended_acl(3)

    assert excinfo.value.kind is SecureFileErrorKind.SECURITY_UNSUPPORTED


@pytest.mark.parametrize(
    ("error_number", "kind"),
    [
        (errno.EEXIST, SecureFileErrorKind.ALREADY_EXISTS),
        (errno.ENOSYS, SecureFileErrorKind.SECURITY_UNSUPPORTED),
        (errno.EIO, SecureFileErrorKind.COMMIT_UNCERTAIN),
        (errno.ENOSPC, SecureFileErrorKind.WRITE_FAILED),
    ],
)
def test_exclusive_rename_errors_are_stable(
    error_number: int,
    kind: SecureFileErrorKind,
) -> None:
    def fail_rename(*args: object) -> int:
        config_filesystem.ctypes.set_errno(error_number)
        return -1

    with pytest.raises(SecureFileError) as excinfo:
        config_filesystem._rename_no_replace(
            1,
            "stage",
            "final",
            primitive=fail_rename,
            flag=1,
        )

    assert excinfo.value.kind is kind


def test_exclusive_rename_translates_unexpected_primitive_failure() -> None:
    def fail_rename(*args: object) -> int:
        raise RuntimeError("private-rename-detail")

    with pytest.raises(SecureFileError) as excinfo:
        config_filesystem._rename_no_replace(
            1,
            "stage",
            "final",
            primitive=fail_rename,
            flag=1,
        )

    assert excinfo.value.kind is SecureFileErrorKind.COMMIT_UNCERTAIN
    assert "private-rename-detail" not in str(excinfo.value)


def test_created_metadata_validation_fails_without_owner_checks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "runtime.bin"
    path.write_bytes(b"value")
    path.chmod(0o600)
    monkeypatch.setattr(config_filesystem.os, "geteuid", None)

    with pytest.raises(SecureFileError) as excinfo:
        config_filesystem._validate_created_metadata(
            path.stat(),
            content_size=5,
            mode=0o600,
        )

    assert excinfo.value.kind is SecureFileErrorKind.SECURITY_UNSUPPORTED


def test_staging_name_collision_bound_fails_without_publishing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "runtime.bin"
    token = "c" * 32
    staged = tmp_path / f"{config_filesystem._STAGED_FILE_PREFIX}{token}"
    staged.write_bytes(b"existing-stage")
    monkeypatch.setattr(config_filesystem.secrets, "token_hex", lambda _size: token)

    with pytest.raises(SecureFileError) as excinfo:
        create_regular_file_no_follow(path, b"value", mode=0o600)

    assert excinfo.value.kind is SecureFileErrorKind.WRITE_FAILED
    assert not path.exists()
    assert staged.read_bytes() == b"existing-stage"


def test_exclusive_create_handles_successful_short_writes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "runtime.bin"
    real_write = config_filesystem.os.write

    def short_write(descriptor: int, value: bytes) -> int:
        return real_write(descriptor, value[:2])

    monkeypatch.setattr(config_filesystem.os, "write", short_write)
    selected = create_regular_file_no_follow(path, b"runtime-value", mode=0o600)

    assert selected.path == path
    assert path.read_bytes() == b"runtime-value"


def test_descriptor_content_readback_handles_short_reads(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "runtime.bin"
    expected = b"runtime-value"
    path.write_bytes(expected)
    descriptor = os.open(path, os.O_RDONLY)
    real_pread = config_filesystem.os.pread

    def short_pread(selected: int, size: int, offset: int) -> bytes:
        return real_pread(selected, min(size, 2), offset)

    monkeypatch.setattr(config_filesystem.os, "pread", short_pread)
    try:
        assert config_filesystem._descriptor_content_matches(descriptor, expected)
    finally:
        os.close(descriptor)


def test_descriptor_content_readback_failure_is_value_safe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "runtime.bin"
    path.write_bytes(b"value")
    descriptor = os.open(path, os.O_RDONLY)

    def fail_pread(selected: int, size: int, offset: int) -> bytes:
        raise RuntimeError("private-pread-detail")

    monkeypatch.setattr(config_filesystem.os, "pread", fail_pread)
    try:
        with pytest.raises(SecureFileError) as excinfo:
            config_filesystem._descriptor_content_matches(descriptor, b"value")
    finally:
        os.close(descriptor)

    assert excinfo.value.kind is SecureFileErrorKind.UNREADABLE
    assert "private-pread-detail" not in str(excinfo.value)


def test_zero_byte_write_is_a_failure_and_is_cleaned_up(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "runtime.bin"
    monkeypatch.setattr(config_filesystem.os, "write", lambda descriptor, value: 0)

    with pytest.raises(SecureFileError) as excinfo:
        create_regular_file_no_follow(path, b"runtime-value", mode=0o600)

    assert excinfo.value.kind is SecureFileErrorKind.WRITE_FAILED
    assert not path.exists()


@pytest.mark.parametrize(
    ("error", "kind"),
    [
        (ValueError("private-detail"), SecureFileErrorKind.INVALID),
        (OSError(errno.ELOOP, "private-detail"), SecureFileErrorKind.NOT_REGULAR),
        (OSError(errno.EACCES, "private-detail"), SecureFileErrorKind.UNREADABLE),
    ],
)
def test_exclusive_create_translates_parent_open_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    error: BaseException,
    kind: SecureFileErrorKind,
) -> None:
    def fail_parent(path: Path, *, nofollow: int) -> tuple[int, str]:
        raise error

    monkeypatch.setattr(config_filesystem, "_open_directory_chain", fail_parent)
    with pytest.raises(SecureFileError) as excinfo:
        create_regular_file_no_follow(tmp_path / "runtime.bin", b"value", mode=0o600)

    assert excinfo.value.kind is kind
    assert "private-detail" not in str(excinfo.value)


@pytest.mark.parametrize(
    ("error", "kind"),
    [
        (ValueError("private-detail"), SecureFileErrorKind.INVALID),
        (OSError(errno.ELOOP, "private-detail"), SecureFileErrorKind.NOT_REGULAR),
        (OSError(errno.EACCES, "private-detail"), SecureFileErrorKind.UNREADABLE),
    ],
)
def test_open_translates_parent_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    error: BaseException,
    kind: SecureFileErrorKind,
) -> None:
    def fail_parent(path: Path, *, nofollow: int) -> tuple[int, str]:
        raise error

    monkeypatch.setattr(config_filesystem, "_open_directory_chain", fail_parent)
    with pytest.raises(SecureFileError) as excinfo:
        open_regular_file_no_follow(tmp_path / "runtime.bin")

    assert excinfo.value.kind is kind
    assert "private-detail" not in str(excinfo.value)


def test_open_closes_leaf_descriptor_before_propagating_cancellation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "runtime.bin"
    path.write_bytes(b"value")
    real_open = config_filesystem.os.open
    real_fstat = config_filesystem.os.fstat
    leaf_descriptor: int | None = None
    cancelled = False

    def capture_leaf_open(
        selected_path: str,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal leaf_descriptor
        descriptor = real_open(selected_path, flags, mode, dir_fd=dir_fd)
        if selected_path == path.name and dir_fd is not None:
            leaf_descriptor = descriptor
        return descriptor

    def cancel_leaf_stat(descriptor: int) -> os.stat_result:
        nonlocal cancelled
        if descriptor == leaf_descriptor and not cancelled:
            cancelled = True
            raise KeyboardInterrupt
        return real_fstat(descriptor)

    monkeypatch.setattr(config_filesystem.os, "open", capture_leaf_open)
    monkeypatch.setattr(config_filesystem.os, "fstat", cancel_leaf_stat)
    with pytest.raises(KeyboardInterrupt):
        open_regular_file_no_follow(path)

    assert leaf_descriptor is not None
    with pytest.raises(OSError):
        real_fstat(leaf_descriptor)


def test_failed_stage_sanitizes_exact_descriptor_without_unlinking_swapped_name(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "runtime.bin"
    staged = tmp_path / f"{config_filesystem._STAGED_FILE_PREFIX}{'a' * 32}"
    moved = tmp_path / "moved-stage"
    replacement = b"replacement-must-survive"

    monkeypatch.setattr(config_filesystem.secrets, "token_hex", lambda _size: "a" * 32)

    def swap_then_fail(descriptor: int, value: bytes) -> int:
        staged.rename(moved)
        staged.write_bytes(replacement)
        raise OSError("private-write-detail")

    monkeypatch.setattr(config_filesystem.os, "write", swap_then_fail)
    with pytest.raises(SecureFileError) as excinfo:
        create_regular_file_no_follow(path, b"sensitive-stage", mode=0o600)

    assert excinfo.value.kind is SecureFileErrorKind.WRITE_FAILED
    assert not path.exists()
    assert staged.read_bytes() == replacement
    assert moved.read_bytes() == b""


def test_post_publish_selection_mismatch_is_commit_uncertain(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "runtime.bin"
    real_inspect = config_filesystem.inspect_regular_file_no_follow

    def mismatched_selection(
        selected_path: Path, *, require_private_parent: bool = False
    ) -> FileSelection:
        selected = real_inspect(
            selected_path,
            require_private_parent=require_private_parent,
        )
        return FileSelection(
            path=selected.path,
            parent_identity=FileIdentity(
                device=selected.parent_identity.device,
                inode=selected.parent_identity.inode + 1,
            ),
            snapshot=selected.snapshot,
        )

    monkeypatch.setattr(
        config_filesystem,
        "inspect_regular_file_no_follow",
        mismatched_selection,
    )
    with pytest.raises(SecureFileError) as excinfo:
        create_regular_file_no_follow(path, b"value", mode=0o600)

    assert excinfo.value.kind is SecureFileErrorKind.COMMIT_UNCERTAIN
    assert path.read_bytes() == b"value"


def test_parent_descriptor_close_failure_is_not_reported_as_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "runtime.bin"
    real_open_chain = config_filesystem._open_directory_chain
    real_close = config_filesystem.os.close
    parent_descriptor: int | None = None

    def capture_parent(selected_path: Path, *, nofollow: int) -> tuple[int, str]:
        nonlocal parent_descriptor
        descriptor, leaf = real_open_chain(selected_path, nofollow=nofollow)
        if parent_descriptor is None:
            parent_descriptor = descriptor
        return descriptor, leaf

    def fail_parent_close(descriptor: int) -> None:
        real_close(descriptor)
        if descriptor == parent_descriptor:
            raise OSError("private-close-detail")

    monkeypatch.setattr(config_filesystem, "_open_directory_chain", capture_parent)
    monkeypatch.setattr(config_filesystem.os, "close", fail_parent_close)
    with pytest.raises(SecureFileError) as excinfo:
        create_regular_file_no_follow(path, b"value", mode=0o600)

    assert excinfo.value.kind is SecureFileErrorKind.COMMIT_UNCERTAIN
    assert path.read_bytes() == b"value"


def test_directory_walk_rejects_file_component_without_o_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    component = tmp_path / "not-a-directory"
    component.write_bytes(b"value")
    monkeypatch.setattr(config_filesystem.os, "O_DIRECTORY", 0)

    with pytest.raises(SecureFileError) as excinfo:
        open_regular_file_no_follow(component / "runtime.bin")

    assert excinfo.value.kind is SecureFileErrorKind.NOT_REGULAR


def test_directory_walk_close_failure_does_not_leak_the_next_descriptor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "one" / "two" / "runtime.bin"
    path.parent.mkdir(parents=True)
    real_open = config_filesystem.os.open
    real_close = config_filesystem.os.close
    opened_descriptors: list[int] = []
    failed_once = False

    def capture_open(*args: object, **kwargs: object) -> int:
        descriptor = real_open(*args, **kwargs)  # type: ignore[arg-type]
        opened_descriptors.append(descriptor)
        return descriptor

    def close_then_fail_once(descriptor: int) -> None:
        nonlocal failed_once
        real_close(descriptor)
        if not failed_once:
            failed_once = True
            raise OSError("private-intermediate-close-detail")

    monkeypatch.setattr(config_filesystem.os, "open", capture_open)
    monkeypatch.setattr(config_filesystem.os, "close", close_then_fail_once)
    with pytest.raises(SecureFileError) as excinfo:
        open_regular_file_no_follow(path)

    assert excinfo.value.kind is SecureFileErrorKind.UNREADABLE
    assert "private-intermediate-close-detail" not in str(excinfo.value)
    assert len(opened_descriptors) == 2
    for descriptor in opened_descriptors:
        with pytest.raises(OSError):
            os.fstat(descriptor)


def test_exclusive_create_rejects_nonregular_opened_descriptor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "runtime.bin"
    real_fstat = config_filesystem.os.fstat
    changed = False

    def report_fifo_once(descriptor: int) -> os.stat_result:
        nonlocal changed
        metadata = real_fstat(descriptor)
        if not changed and stat.S_ISREG(metadata.st_mode) and metadata.st_size == 0:
            changed = True
            values = list(metadata)
            values[0] = stat.S_IFIFO | 0o600
            return os.stat_result(values)
        return metadata

    monkeypatch.setattr(config_filesystem.os, "fstat", report_fifo_once)
    with pytest.raises(SecureFileError) as excinfo:
        create_regular_file_no_follow(path, b"value", mode=0o600)

    assert excinfo.value.kind is SecureFileErrorKind.NOT_REGULAR
    assert not path.exists()


def test_exclusive_create_rejects_changed_final_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "runtime.bin"
    real_fstat = config_filesystem.os.fstat

    def report_wrong_final_size(descriptor: int) -> os.stat_result:
        metadata = real_fstat(descriptor)
        if stat.S_ISREG(metadata.st_mode) and metadata.st_size == len(b"value"):
            values = list(metadata)
            values[6] = metadata.st_size + 1
            return os.stat_result(values)
        return metadata

    monkeypatch.setattr(config_filesystem.os, "fstat", report_wrong_final_size)
    with pytest.raises(SecureFileError) as excinfo:
        create_regular_file_no_follow(path, b"value", mode=0o600)

    assert excinfo.value.kind is SecureFileErrorKind.CHANGED
    assert not path.exists()


def test_created_file_close_failure_is_cleaned_up(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "runtime.bin"
    real_open = config_filesystem.os.open
    real_close = config_filesystem.os.close
    created_descriptor: int | None = None

    def capture_created_open(
        selected_path: str,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal created_descriptor
        descriptor = real_open(selected_path, flags, mode, dir_fd=dir_fd)
        if flags & os.O_CREAT:
            created_descriptor = descriptor
        return descriptor

    def fail_created_close(descriptor: int) -> None:
        real_close(descriptor)
        if descriptor == created_descriptor:
            raise OSError("private-close-detail")

    monkeypatch.setattr(config_filesystem.os, "open", capture_created_open)
    monkeypatch.setattr(config_filesystem.os, "close", fail_created_close)
    with pytest.raises(SecureFileError) as excinfo:
        create_regular_file_no_follow(path, b"value", mode=0o600)

    assert excinfo.value.kind is SecureFileErrorKind.COMMIT_UNCERTAIN
    assert path.read_bytes() == b"value"


def test_cleanup_preserves_primary_error_when_descriptor_close_also_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "runtime.bin"
    real_open = config_filesystem.os.open
    real_close = config_filesystem.os.close
    created_descriptor: int | None = None

    def capture_created_open(
        selected_path: str,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal created_descriptor
        descriptor = real_open(selected_path, flags, mode, dir_fd=dir_fd)
        if flags & os.O_CREAT:
            created_descriptor = descriptor
        return descriptor

    def fail_write(descriptor: int, value: bytes) -> int:
        raise OSError("private-write-detail")

    def fail_created_close(descriptor: int) -> None:
        real_close(descriptor)
        if descriptor == created_descriptor:
            raise OSError("private-close-detail")

    monkeypatch.setattr(config_filesystem.os, "open", capture_created_open)
    monkeypatch.setattr(config_filesystem.os, "write", fail_write)
    monkeypatch.setattr(config_filesystem.os, "close", fail_created_close)
    with pytest.raises(SecureFileError) as excinfo:
        create_regular_file_no_follow(path, b"value", mode=0o600)

    assert excinfo.value.kind is SecureFileErrorKind.CLEANUP_FAILED
    assert not path.exists()


def test_cleanup_failure_survives_a_parent_close_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "runtime.bin"
    real_chain = config_filesystem._open_directory_chain
    real_write = config_filesystem.os.write
    real_close = config_filesystem.os.close
    parent_descriptor: int | None = None
    write_calls = 0

    def capture_parent(selected_path: Path, *, nofollow: int) -> tuple[int, str]:
        nonlocal parent_descriptor
        descriptor, leaf = real_chain(selected_path, nofollow=nofollow)
        parent_descriptor = descriptor
        return descriptor, leaf

    def fail_after_partial_write(descriptor: int, value: bytes) -> int:
        nonlocal write_calls
        write_calls += 1
        if write_calls == 1:
            return real_write(descriptor, value[:2])
        raise OSError("private-write-detail")

    def fail_truncate(descriptor: int, length: int) -> None:
        raise OSError("private-cleanup-detail")

    def fail_parent_close(descriptor: int) -> None:
        real_close(descriptor)
        if descriptor == parent_descriptor:
            raise OSError("private-parent-close-detail")

    monkeypatch.setattr(config_filesystem, "_open_directory_chain", capture_parent)
    monkeypatch.setattr(config_filesystem.os, "write", fail_after_partial_write)
    monkeypatch.setattr(config_filesystem.os, "ftruncate", fail_truncate)
    monkeypatch.setattr(config_filesystem.os, "close", fail_parent_close)
    with pytest.raises(SecureFileError) as excinfo:
        create_regular_file_no_follow(path, b"value", mode=0o600)

    assert excinfo.value.kind is SecureFileErrorKind.CLEANUP_FAILED
    assert not path.exists()


def test_post_publish_os_failure_is_commit_uncertain(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "runtime.bin"
    real_open = config_filesystem.os.open
    real_fstat = config_filesystem.os.fstat
    real_rename = config_filesystem._rename_no_replace
    created_descriptor: int | None = None
    published = False

    def capture_created_open(
        selected_path: str,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal created_descriptor
        descriptor = real_open(selected_path, flags, mode, dir_fd=dir_fd)
        if flags & os.O_CREAT:
            created_descriptor = descriptor
        return descriptor

    def publish(
        directory_descriptor: int,
        staged_leaf: str,
        final_leaf: str,
        *,
        primitive: object,
        flag: int,
    ) -> None:
        nonlocal published
        real_rename(
            directory_descriptor,
            staged_leaf,
            final_leaf,
            primitive=primitive,
            flag=flag,
        )
        published = True

    def fail_post_publish_fstat(descriptor: int) -> os.stat_result:
        if published and descriptor == created_descriptor:
            raise OSError("private-post-publish-detail")
        return real_fstat(descriptor)

    monkeypatch.setattr(config_filesystem.os, "open", capture_created_open)
    monkeypatch.setattr(config_filesystem.os, "fstat", fail_post_publish_fstat)
    monkeypatch.setattr(config_filesystem, "_rename_no_replace", publish)
    with pytest.raises(SecureFileError) as excinfo:
        create_regular_file_no_follow(path, b"value", mode=0o600)

    assert excinfo.value.kind is SecureFileErrorKind.COMMIT_UNCERTAIN
    assert path.read_bytes() == b"value"
    assert "private-post-publish-detail" not in str(excinfo.value)


def test_open_preserves_primary_failure_when_parent_close_also_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "missing.bin"
    real_chain = config_filesystem._open_directory_chain
    real_close = config_filesystem.os.close
    parent_descriptor: int | None = None

    def capture_parent(selected_path: Path, *, nofollow: int) -> tuple[int, str]:
        nonlocal parent_descriptor
        parent_descriptor, leaf = real_chain(selected_path, nofollow=nofollow)
        return parent_descriptor, leaf

    def fail_parent_close(descriptor: int) -> None:
        real_close(descriptor)
        if descriptor == parent_descriptor:
            raise OSError("private-parent-close-detail")

    monkeypatch.setattr(config_filesystem, "_open_directory_chain", capture_parent)
    monkeypatch.setattr(config_filesystem.os, "close", fail_parent_close)
    with pytest.raises(SecureFileError) as excinfo:
        open_regular_file_no_follow(path)

    assert excinfo.value.kind is SecureFileErrorKind.NOT_FOUND
    assert "private-parent-close-detail" not in str(excinfo.value)


def test_parent_sync_success_and_failure_boundaries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "runtime.bin"
    identity = config_filesystem.sync_parent_directory_no_follow(path)
    assert identity == FileIdentity.from_stat(tmp_path.stat())

    monkeypatch.setattr(config_filesystem.os, "O_NOFOLLOW", 0)
    with pytest.raises(SecureFileError) as unsupported:
        config_filesystem.sync_parent_directory_no_follow(path)
    assert unsupported.value.kind is SecureFileErrorKind.SECURITY_UNSUPPORTED

    monkeypatch.undo()
    missing = tmp_path / "missing" / "runtime.bin"
    with pytest.raises(SecureFileError) as not_found:
        config_filesystem.sync_parent_directory_no_follow(missing)
    assert not_found.value.kind is SecureFileErrorKind.NOT_FOUND


@pytest.mark.parametrize("sync_fails", [False, True])
def test_parent_sync_close_failure_is_stable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    sync_fails: bool,
) -> None:
    path = tmp_path / "runtime.bin"
    real_chain = config_filesystem._open_directory_chain
    real_close = config_filesystem.os.close
    real_fsync = config_filesystem.os.fsync
    parent_descriptor: int | None = None

    def capture_parent(selected_path: Path, *, nofollow: int) -> tuple[int, str]:
        nonlocal parent_descriptor
        parent_descriptor, leaf = real_chain(selected_path, nofollow=nofollow)
        return parent_descriptor, leaf

    def fail_sync(descriptor: int) -> None:
        if sync_fails and descriptor == parent_descriptor:
            raise OSError("private-sync-detail")
        real_fsync(descriptor)

    def fail_parent_close(descriptor: int) -> None:
        real_close(descriptor)
        if descriptor == parent_descriptor:
            raise OSError("private-close-detail")

    monkeypatch.setattr(config_filesystem, "_open_directory_chain", capture_parent)
    monkeypatch.setattr(config_filesystem.os, "fsync", fail_sync)
    monkeypatch.setattr(config_filesystem.os, "close", fail_parent_close)
    with pytest.raises(SecureFileError) as excinfo:
        config_filesystem.sync_parent_directory_no_follow(path)

    expected = SecureFileErrorKind.SYNC_FAILED if sync_fails else SecureFileErrorKind.UNREADABLE
    assert excinfo.value.kind is expected
    assert "private" not in str(excinfo.value)
