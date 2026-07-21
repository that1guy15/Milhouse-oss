"""Descriptor-relative, no-follow primitives for selected runtime files."""

from __future__ import annotations

import ctypes
import errno
import hmac
import os
import secrets
import stat
import sys
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any


class SecureFileErrorKind(StrEnum):
    """Value-safe failure categories translated by each configuration surface."""

    ACCESS_CONTROL_UNSAFE = "access_control_unsafe"
    ALREADY_EXISTS = "already_exists"
    CHANGED = "changed"
    CLEANUP_FAILED = "cleanup_failed"
    COMMIT_UNCERTAIN = "commit_uncertain"
    INVALID = "invalid"
    NOT_FOUND = "not_found"
    NOT_REGULAR = "not_regular"
    PARENT_UNSAFE = "parent_unsafe"
    PERMISSION_FAILED = "permission_failed"
    SECURITY_UNSUPPORTED = "security_unsupported"
    SYNC_FAILED = "sync_failed"
    UNREADABLE = "unreadable"
    WRITE_FAILED = "write_failed"


_STAGED_FILE_PREFIX = ".milhouse-stage-"
_STAGED_FILE_ATTEMPTS = 16
_MACOS_ACL_TYPE_EXTENDED = 0x00000100
_LINUX_ACL_XATTR_NAMES = (
    b"system.posix_acl_access",
    b"system.posix_acl_default",
)


class _BeforePublishFailure(BaseException):
    """Carry a caller-owned failure through exact staged-file cleanup."""

    def __init__(self, error: BaseException) -> None:
        self.error = error


class SecureFileError(Exception):
    """An internal file-boundary failure whose representation contains no path or OS detail."""

    def __init__(self, kind: SecureFileErrorKind) -> None:
        super().__init__(kind.value)
        self.kind = kind


@dataclass(frozen=True, slots=True)
class FileIdentity:
    """Filesystem identity for an opened directory."""

    device: int
    inode: int

    @classmethod
    def from_stat(cls, metadata: os.stat_result) -> FileIdentity:
        return cls(device=metadata.st_dev, inode=metadata.st_ino)


@dataclass(frozen=True, slots=True)
class FileSnapshot:
    """Identity and mutation coordinates for one securely opened regular file."""

    device: int
    inode: int
    size: int
    modified_ns: int
    changed_ns: int

    @classmethod
    def from_stat(cls, metadata: os.stat_result) -> FileSnapshot:
        return cls(
            device=metadata.st_dev,
            inode=metadata.st_ino,
            size=metadata.st_size,
            modified_ns=metadata.st_mtime_ns,
            changed_ns=metadata.st_ctime_ns,
        )


@dataclass(frozen=True, slots=True, repr=False)
class FileSelection:
    """A closed, value-safe description of the exact file selected at open time."""

    path: Path
    parent_identity: FileIdentity
    snapshot: FileSnapshot

    def __repr__(self) -> str:
        return "FileSelection(selected=True)"


@dataclass(frozen=True, slots=True, repr=False)
class OpenedRegularFile:
    """An owned descriptor plus value-safe path identity captured at open time."""

    descriptor: int
    selection: FileSelection

    @property
    def path(self) -> Path:
        return self.selection.path

    @property
    def parent_identity(self) -> FileIdentity:
        return self.selection.parent_identity

    @property
    def snapshot(self) -> FileSnapshot:
        return self.selection.snapshot

    def __repr__(self) -> str:
        return "OpenedRegularFile(open=True)"


def lexical_absolute_path(path: str | Path) -> Path:
    """Normalize an explicit path without resolving any filesystem symlink."""

    try:
        candidate = Path(path)
        if not candidate.is_absolute():
            candidate = candidate.absolute()
        return Path(os.path.normpath(os.fspath(candidate)))
    except (OSError, TypeError, ValueError):
        raise SecureFileError(SecureFileErrorKind.INVALID) from None


def _open_directory_chain(path: Path, *, nofollow: int) -> tuple[int, str]:
    parts = path.parts
    if not path.is_absolute() or len(parts) < 2:
        raise SecureFileError(SecureFileErrorKind.INVALID)

    directory_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    directory_flags |= getattr(os, "O_DIRECTORY", 0) | nofollow
    directory_descriptor: int | None = None
    try:
        directory_descriptor = os.open(parts[0], directory_flags)
        for component in parts[1:-1]:
            next_descriptor: int | None = None
            try:
                next_descriptor = os.open(component, directory_flags, dir_fd=directory_descriptor)
                if not stat.S_ISDIR(os.fstat(next_descriptor).st_mode):
                    raise OSError(errno.ENOTDIR, "path component is not a directory")
            except BaseException:
                if next_descriptor is not None:
                    try:
                        os.close(next_descriptor)
                    except OSError:
                        pass
                raise
            previous_descriptor = directory_descriptor
            directory_descriptor = next_descriptor
            next_descriptor = None
            try:
                os.close(previous_descriptor)
            except OSError:
                current_descriptor = directory_descriptor
                directory_descriptor = None
                try:
                    os.close(current_descriptor)
                except OSError:
                    pass
                raise SecureFileError(SecureFileErrorKind.UNREADABLE) from None
        result = directory_descriptor
        directory_descriptor = None
        return result, parts[-1]
    except BaseException:
        if directory_descriptor is not None:
            try:
                os.close(directory_descriptor)
            except OSError:
                pass
        raise


def _exclusive_rename_primitive() -> tuple[Any, int]:
    """Return the supported kernel primitive for an atomic no-overwrite rename."""

    if sys.platform == "darwin":
        function_name = "renameatx_np"
        flag = 0x00000004  # RENAME_EXCL
    elif sys.platform.startswith("linux"):
        function_name = "renameat2"
        flag = 0x00000001  # RENAME_NOREPLACE
    else:
        raise SecureFileError(SecureFileErrorKind.SECURITY_UNSUPPORTED)
    try:
        library = ctypes.CDLL(None, use_errno=True)
        function: Any = getattr(library, function_name)
        function.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        function.restype = ctypes.c_int
    except Exception:
        raise SecureFileError(SecureFileErrorKind.SECURITY_UNSUPPORTED) from None
    return function, flag


def _rename_no_replace(
    directory_descriptor: int,
    staged_leaf: str,
    final_leaf: str,
    *,
    primitive: Any,
    flag: int,
) -> None:
    """Atomically publish one staged leaf only when the destination is absent."""

    ctypes.set_errno(0)
    try:
        result = primitive(
            directory_descriptor,
            os.fsencode(staged_leaf),
            directory_descriptor,
            os.fsencode(final_leaf),
            flag,
        )
    except Exception:
        raise SecureFileError(SecureFileErrorKind.COMMIT_UNCERTAIN) from None
    if result == 0:
        return
    error_number = ctypes.get_errno()
    if error_number in {errno.EEXIST, errno.ENOTEMPTY}:
        raise SecureFileError(SecureFileErrorKind.ALREADY_EXISTS)
    if error_number == errno.EIO:
        raise SecureFileError(SecureFileErrorKind.COMMIT_UNCERTAIN)
    if error_number in {errno.ENOSYS, errno.ENOTSUP, errno.EOPNOTSUPP, errno.EINVAL}:
        raise SecureFileError(SecureFileErrorKind.SECURITY_UNSUPPORTED)
    raise SecureFileError(SecureFileErrorKind.WRITE_FAILED)


def _macos_descriptor_has_extended_acl(descriptor: int) -> bool:
    """Inspect a descriptor for a macOS NFSv4-style extended ACL."""

    try:
        library = ctypes.CDLL(None, use_errno=True)
        get_acl: Any = library.acl_get_fd_np
        get_acl.argtypes = [ctypes.c_int, ctypes.c_int]
        get_acl.restype = ctypes.c_void_p
        free_acl: Any = library.acl_free
        free_acl.argtypes = [ctypes.c_void_p]
        free_acl.restype = ctypes.c_int
    except Exception:
        raise SecureFileError(SecureFileErrorKind.SECURITY_UNSUPPORTED) from None

    try:
        ctypes.set_errno(0)
        acl = get_acl(descriptor, _MACOS_ACL_TYPE_EXTENDED)
    except Exception:
        raise SecureFileError(SecureFileErrorKind.SECURITY_UNSUPPORTED) from None
    if not acl:
        no_acl_errors = {errno.ENOENT}
        enoattr = getattr(errno, "ENOATTR", None)
        if enoattr is not None:
            no_acl_errors.add(enoattr)
        if ctypes.get_errno() in no_acl_errors:
            return False
        raise SecureFileError(SecureFileErrorKind.SECURITY_UNSUPPORTED)
    try:
        return True
    finally:
        try:
            free_acl(acl)
        except Exception:
            raise SecureFileError(SecureFileErrorKind.SECURITY_UNSUPPORTED) from None


def _linux_descriptor_has_extended_acl(descriptor: int) -> bool:
    """Inspect a descriptor for Linux POSIX access or inheritable default ACLs."""

    try:
        library = ctypes.CDLL(None, use_errno=True)
        get_xattr: Any = library.fgetxattr
        get_xattr.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_void_p,
            ctypes.c_size_t,
        ]
        get_xattr.restype = ctypes.c_ssize_t
    except Exception:
        raise SecureFileError(SecureFileErrorKind.SECURITY_UNSUPPORTED) from None

    no_data_errors = {getattr(errno, "ENODATA", -1)}
    enoattr = getattr(errno, "ENOATTR", None)
    if enoattr is not None:
        no_data_errors.add(enoattr)
    for attribute_name in _LINUX_ACL_XATTR_NAMES:
        try:
            ctypes.set_errno(0)
            size = get_xattr(descriptor, attribute_name, None, 0)
        except Exception:
            raise SecureFileError(SecureFileErrorKind.SECURITY_UNSUPPORTED) from None
        if size >= 0:
            return True
        if ctypes.get_errno() not in no_data_errors:
            raise SecureFileError(SecureFileErrorKind.SECURITY_UNSUPPORTED)
    return False


def _descriptor_has_extended_acl(descriptor: int) -> bool:
    if sys.platform == "darwin":
        return _macos_descriptor_has_extended_acl(descriptor)
    elif sys.platform.startswith("linux"):
        return _linux_descriptor_has_extended_acl(descriptor)
    raise SecureFileError(SecureFileErrorKind.SECURITY_UNSUPPORTED)


def _require_no_extended_acl(descriptor: int) -> None:
    """Fail closed when mode bits are supplemented by an extended ACL."""

    if _descriptor_has_extended_acl(descriptor):
        raise SecureFileError(SecureFileErrorKind.ACCESS_CONTROL_UNSAFE)


def _require_private_parent(descriptor: int, metadata: os.stat_result) -> None:
    """Require the key namespace to be owned and accessible only by the current user."""

    effective_user_id = getattr(os, "geteuid", None)
    if effective_user_id is None:
        raise SecureFileError(SecureFileErrorKind.SECURITY_UNSUPPORTED)
    try:
        owner = effective_user_id()
    except OSError:
        raise SecureFileError(SecureFileErrorKind.SECURITY_UNSUPPORTED) from None
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != owner
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise SecureFileError(SecureFileErrorKind.PARENT_UNSAFE)
    try:
        _require_no_extended_acl(descriptor)
    except SecureFileError as error:
        if error.kind is SecureFileErrorKind.ACCESS_CONTROL_UNSAFE:
            raise SecureFileError(SecureFileErrorKind.PARENT_UNSAFE) from None
        raise


def _validate_created_metadata(
    metadata: os.stat_result,
    *,
    content_size: int,
    mode: int,
) -> None:
    effective_user_id = getattr(os, "geteuid", None)
    if effective_user_id is None:
        raise SecureFileError(SecureFileErrorKind.SECURITY_UNSUPPORTED)
    try:
        owner = effective_user_id()
    except OSError:
        raise SecureFileError(SecureFileErrorKind.SECURITY_UNSUPPORTED) from None
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_size != content_size
        or stat.S_IMODE(metadata.st_mode) != mode
        or metadata.st_uid != owner
        or metadata.st_nlink != 1
    ):
        raise SecureFileError(SecureFileErrorKind.CHANGED)


def _sanitize_staged_descriptor(descriptor: int) -> None:
    """Remove logical content from the exact staged inode without unlinking a mutable name."""

    try:
        os.ftruncate(descriptor, 0)
        os.fsync(descriptor)
    except OSError:
        raise SecureFileError(SecureFileErrorKind.CLEANUP_FAILED) from None


def _descriptor_content_matches(descriptor: int, expected: bytes) -> bool:
    """Read back one bounded descriptor value and compare it without content-dependent timing."""

    chunks: list[bytes] = []
    offset = 0
    remaining = len(expected) + 1
    try:
        while remaining:
            chunk = os.pread(descriptor, remaining, offset)
            if not chunk:
                break
            chunks.append(chunk)
            offset += len(chunk)
            remaining -= len(chunk)
    except Exception:
        raise SecureFileError(SecureFileErrorKind.UNREADABLE) from None
    return hmac.compare_digest(b"".join(chunks), expected)


def create_regular_file_no_follow(
    path: str | Path,
    content: bytes,
    *,
    mode: int,
    before_publish: Callable[[], None] | None = None,
    require_private_parent: bool = False,
) -> FileSelection:
    """Stage, fsync, and atomically publish one regular file without overwriting a name.

    The parent directory must already exist.  Before publication, failures sanitize the exact open
    staging inode and never unlink a path that could have been replaced.  A process interruption can
    leave an owner-only staging artifact, but the final path is either absent or a complete file.
    Failures after the atomic publication are reported as commit-uncertain for explicit recovery.
    """

    normalized = lexical_absolute_path(path)
    if type(content) is not bytes or not content:
        raise SecureFileError(SecureFileErrorKind.INVALID)
    if type(mode) is not int or not 0 < mode <= 0o777:
        raise SecureFileError(SecureFileErrorKind.INVALID)
    if before_publish is not None and not callable(before_publish):
        raise SecureFileError(SecureFileErrorKind.INVALID)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if nofollow == 0:
        raise SecureFileError(SecureFileErrorKind.SECURITY_UNSUPPORTED)
    primitive, rename_flag = _exclusive_rename_primitive()

    file_flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | nofollow
    directory_descriptor: int | None = None
    descriptor: int | None = None
    staged = False
    published = False
    publication_uncertain = False
    failure: BaseException | None = None
    result: FileSelection | None = None
    leaf = ""
    staged_leaf = ""
    try:
        directory_descriptor, leaf = _open_directory_chain(normalized, nofollow=nofollow)
        parent_metadata = os.fstat(directory_descriptor)
        if require_private_parent:
            _require_private_parent(directory_descriptor, parent_metadata)
        try:
            os.stat(leaf, dir_fd=directory_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise SecureFileError(SecureFileErrorKind.ALREADY_EXISTS)

        for _attempt in range(_STAGED_FILE_ATTEMPTS):
            try:
                staged_token = secrets.token_hex(16)
            except Exception:
                raise SecureFileError(SecureFileErrorKind.WRITE_FAILED) from None
            if (
                type(staged_token) is not str
                or len(staged_token) != 32
                or any(character not in "0123456789abcdef" for character in staged_token)
            ):
                raise SecureFileError(SecureFileErrorKind.WRITE_FAILED)
            staged_leaf = f"{_STAGED_FILE_PREFIX}{staged_token}"
            try:
                descriptor = os.open(
                    staged_leaf,
                    file_flags,
                    mode,
                    dir_fd=directory_descriptor,
                )
            except FileExistsError:
                continue
            staged = True
            break
        if descriptor is None:
            raise SecureFileError(SecureFileErrorKind.WRITE_FAILED)

        initial_metadata = os.fstat(descriptor)
        if not stat.S_ISREG(initial_metadata.st_mode):
            raise SecureFileError(SecureFileErrorKind.NOT_REGULAR)
        try:
            os.fchmod(descriptor, mode)
        except OSError:
            raise SecureFileError(SecureFileErrorKind.PERMISSION_FAILED) from None
        if require_private_parent:
            _require_no_extended_acl(descriptor)

        offset = 0
        while offset < len(content):
            try:
                written = os.write(descriptor, content[offset:])
            except OSError:
                raise SecureFileError(SecureFileErrorKind.WRITE_FAILED) from None
            if written <= 0:
                raise SecureFileError(SecureFileErrorKind.WRITE_FAILED)
            offset += written

        try:
            os.fsync(descriptor)
        except OSError:
            raise SecureFileError(SecureFileErrorKind.SYNC_FAILED) from None

        final_metadata = os.fstat(descriptor)
        _validate_created_metadata(final_metadata, content_size=len(content), mode=mode)
        if not _descriptor_content_matches(descriptor, content):
            raise SecureFileError(SecureFileErrorKind.CHANGED)
        if require_private_parent:
            _require_no_extended_acl(descriptor)
        if before_publish is not None:
            try:
                before_publish()
            except BaseException as error:
                raise _BeforePublishFailure(error) from None
        publication_uncertain = True
        try:
            _rename_no_replace(
                directory_descriptor,
                staged_leaf,
                leaf,
                primitive=primitive,
                flag=rename_flag,
            )
        except SecureFileError as error:
            if error.kind is not SecureFileErrorKind.COMMIT_UNCERTAIN:
                publication_uncertain = False
            raise
        published = True
        publication_uncertain = False
        try:
            os.fsync(directory_descriptor)
        except OSError:
            raise SecureFileError(SecureFileErrorKind.COMMIT_UNCERTAIN) from None

        published_metadata = os.fstat(descriptor)
        _validate_created_metadata(published_metadata, content_size=len(content), mode=mode)
        try:
            current = inspect_regular_file_no_follow(
                normalized,
                require_private_parent=require_private_parent,
            )
        except SecureFileError:
            raise SecureFileError(SecureFileErrorKind.COMMIT_UNCERTAIN) from None
        if current.parent_identity != FileIdentity.from_stat(
            parent_metadata
        ) or current.snapshot != FileSnapshot.from_stat(published_metadata):
            raise SecureFileError(SecureFileErrorKind.COMMIT_UNCERTAIN)
        if not _descriptor_content_matches(descriptor, content):
            raise SecureFileError(SecureFileErrorKind.COMMIT_UNCERTAIN)
        verified_metadata = os.fstat(descriptor)
        _validate_created_metadata(verified_metadata, content_size=len(content), mode=mode)
        if FileSnapshot.from_stat(verified_metadata) != current.snapshot:
            raise SecureFileError(SecureFileErrorKind.COMMIT_UNCERTAIN)
        result = current
    except _BeforePublishFailure as wrapper:
        failure = wrapper.error
    except SecureFileError as error:
        failure = (
            SecureFileError(SecureFileErrorKind.COMMIT_UNCERTAIN)
            if published or publication_uncertain
            else error
        )
    except FileNotFoundError:
        kind = (
            SecureFileErrorKind.COMMIT_UNCERTAIN
            if published or publication_uncertain
            else SecureFileErrorKind.NOT_FOUND
        )
        failure = SecureFileError(kind)
    except ValueError:
        kind = (
            SecureFileErrorKind.COMMIT_UNCERTAIN
            if published or publication_uncertain
            else SecureFileErrorKind.INVALID
        )
        failure = SecureFileError(kind)
    except OSError as exc:
        if published or publication_uncertain:
            kind = SecureFileErrorKind.COMMIT_UNCERTAIN
        else:
            kind = (
                SecureFileErrorKind.NOT_REGULAR
                if exc.errno in {errno.ELOOP, errno.ENOTDIR}
                else SecureFileErrorKind.UNREADABLE
            )
        failure = SecureFileError(kind)
    except Exception:
        kind = (
            SecureFileErrorKind.COMMIT_UNCERTAIN
            if published or publication_uncertain
            else SecureFileErrorKind.UNREADABLE
        )
        failure = SecureFileError(kind)
    except BaseException as error:
        failure = error
    finally:
        if descriptor is not None:
            if staged and not published and not publication_uncertain:
                try:
                    _sanitize_staged_descriptor(descriptor)
                except SecureFileError as cleanup_error:
                    failure = cleanup_error
            closing_descriptor = descriptor
            descriptor = None
            try:
                os.close(closing_descriptor)
            except OSError:
                failure = SecureFileError(
                    SecureFileErrorKind.COMMIT_UNCERTAIN
                    if published or publication_uncertain
                    else SecureFileErrorKind.CLEANUP_FAILED
                )
        if directory_descriptor is not None:
            closing_directory = directory_descriptor
            directory_descriptor = None
            try:
                os.close(closing_directory)
            except OSError:
                if failure is None:
                    failure = SecureFileError(
                        SecureFileErrorKind.COMMIT_UNCERTAIN
                        if published or publication_uncertain
                        else SecureFileErrorKind.UNREADABLE
                    )

    if failure is None and result is not None:
        return result
    if failure is None:  # pragma: no cover - defensive invariant
        failure = SecureFileError(SecureFileErrorKind.UNREADABLE)
    raise failure


def open_regular_file_no_follow(
    path: str | Path,
    *,
    require_private_parent: bool = False,
) -> OpenedRegularFile:
    """Open an explicit regular file without following any parent or leaf symlink."""

    normalized = lexical_absolute_path(path)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if nofollow == 0:
        raise SecureFileError(SecureFileErrorKind.SECURITY_UNSUPPORTED)

    file_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0) | nofollow
    directory_descriptor: int | None = None
    descriptor: int | None = None
    selection: FileSelection | None = None
    failure: BaseException | None = None
    try:
        directory_descriptor, leaf = _open_directory_chain(normalized, nofollow=nofollow)
        parent_metadata = os.fstat(directory_descriptor)
        if require_private_parent:
            _require_private_parent(directory_descriptor, parent_metadata)
        descriptor = os.open(leaf, file_flags, dir_fd=directory_descriptor)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise SecureFileError(SecureFileErrorKind.NOT_REGULAR)
        if require_private_parent:
            _require_no_extended_acl(descriptor)
        selection = FileSelection(
            path=normalized,
            parent_identity=FileIdentity.from_stat(parent_metadata),
            snapshot=FileSnapshot.from_stat(metadata),
        )
    except FileNotFoundError:
        failure = SecureFileError(SecureFileErrorKind.NOT_FOUND)
    except SecureFileError as error:
        failure = error
    except ValueError:
        failure = SecureFileError(SecureFileErrorKind.INVALID)
    except OSError as exc:
        kind = (
            SecureFileErrorKind.NOT_REGULAR
            if exc.errno in {errno.ELOOP, errno.ENOTDIR}
            else SecureFileErrorKind.UNREADABLE
        )
        failure = SecureFileError(kind)
    except Exception:
        failure = SecureFileError(SecureFileErrorKind.UNREADABLE)
    except BaseException as error:
        failure = error
    finally:
        if directory_descriptor is not None:
            closing_directory = directory_descriptor
            directory_descriptor = None
            try:
                os.close(closing_directory)
            except OSError:
                if failure is None:
                    failure = SecureFileError(SecureFileErrorKind.UNREADABLE)
        if failure is not None and descriptor is not None:
            closing_descriptor = descriptor
            descriptor = None
            try:
                os.close(closing_descriptor)
            except OSError:
                pass

    if failure is not None:
        raise failure
    if descriptor is None or selection is None:  # pragma: no cover - defensive invariant
        raise SecureFileError(SecureFileErrorKind.UNREADABLE)
    return OpenedRegularFile(descriptor=descriptor, selection=selection)


def sync_parent_directory_no_follow(
    path: str | Path,
    *,
    require_private_parent: bool = False,
) -> FileIdentity:
    """Durably synchronize the securely opened parent directory for one explicit path."""

    normalized = lexical_absolute_path(path)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if nofollow == 0:
        raise SecureFileError(SecureFileErrorKind.SECURITY_UNSUPPORTED)

    directory_descriptor: int | None = None
    failure: SecureFileError | None = None
    identity: FileIdentity | None = None
    try:
        directory_descriptor, _leaf = _open_directory_chain(normalized, nofollow=nofollow)
        metadata = os.fstat(directory_descriptor)
        if require_private_parent:
            _require_private_parent(directory_descriptor, metadata)
        os.fsync(directory_descriptor)
        identity = FileIdentity.from_stat(metadata)
    except FileNotFoundError:
        failure = SecureFileError(SecureFileErrorKind.NOT_FOUND)
    except SecureFileError as error:
        failure = error
    except ValueError:
        failure = SecureFileError(SecureFileErrorKind.INVALID)
    except OSError as exc:
        kind = (
            SecureFileErrorKind.NOT_REGULAR
            if exc.errno in {errno.ELOOP, errno.ENOTDIR}
            else SecureFileErrorKind.SYNC_FAILED
        )
        failure = SecureFileError(kind)
    except Exception:
        failure = SecureFileError(SecureFileErrorKind.SYNC_FAILED)
    finally:
        if directory_descriptor is not None:
            closing_directory = directory_descriptor
            directory_descriptor = None
            try:
                os.close(closing_directory)
            except OSError:
                if failure is None:
                    failure = SecureFileError(SecureFileErrorKind.UNREADABLE)

    if failure is not None:
        raise failure
    if identity is None:  # pragma: no cover - defensive invariant
        raise SecureFileError(SecureFileErrorKind.UNREADABLE)
    return identity


def inspect_regular_file_no_follow(
    path: str | Path,
    *,
    require_private_parent: bool = False,
) -> FileSelection:
    """Capture a secure file selection and close its descriptor before returning."""

    opened = open_regular_file_no_follow(
        path,
        require_private_parent=require_private_parent,
    )
    try:
        os.close(opened.descriptor)
    except OSError:
        raise SecureFileError(SecureFileErrorKind.UNREADABLE) from None
    return opened.selection


__all__ = [
    "FileIdentity",
    "FileSelection",
    "FileSnapshot",
    "OpenedRegularFile",
    "SecureFileError",
    "SecureFileErrorKind",
    "create_regular_file_no_follow",
    "inspect_regular_file_no_follow",
    "lexical_absolute_path",
    "open_regular_file_no_follow",
    "sync_parent_directory_no_follow",
]
