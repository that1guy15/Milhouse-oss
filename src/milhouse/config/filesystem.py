"""Descriptor-relative, no-follow primitives for selected configuration files."""

from __future__ import annotations

import errno
import os
import stat
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path


class SecureFileErrorKind(StrEnum):
    """Value-safe failure categories translated by each configuration surface."""

    INVALID = "invalid"
    NOT_FOUND = "not_found"
    NOT_REGULAR = "not_regular"
    SECURITY_UNSUPPORTED = "security_unsupported"
    UNREADABLE = "unreadable"


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
    directory_descriptor = os.open(parts[0], directory_flags)
    try:
        for component in parts[1:-1]:
            next_descriptor = os.open(component, directory_flags, dir_fd=directory_descriptor)
            try:
                if not stat.S_ISDIR(os.fstat(next_descriptor).st_mode):
                    raise OSError(errno.ENOTDIR, "path component is not a directory")
            except BaseException:
                os.close(next_descriptor)
                raise
            os.close(directory_descriptor)
            directory_descriptor = next_descriptor
        return directory_descriptor, parts[-1]
    except BaseException:
        os.close(directory_descriptor)
        raise


def open_regular_file_no_follow(path: str | Path) -> OpenedRegularFile:
    """Open an explicit regular file without following any parent or leaf symlink."""

    normalized = lexical_absolute_path(path)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if nofollow == 0:
        raise SecureFileError(SecureFileErrorKind.SECURITY_UNSUPPORTED)

    file_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0) | nofollow
    directory_descriptor: int | None = None
    descriptor: int | None = None
    try:
        directory_descriptor, leaf = _open_directory_chain(normalized, nofollow=nofollow)
        parent_metadata = os.fstat(directory_descriptor)
        descriptor = os.open(leaf, file_flags, dir_fd=directory_descriptor)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise SecureFileError(SecureFileErrorKind.NOT_REGULAR)
        result = OpenedRegularFile(
            descriptor=descriptor,
            selection=FileSelection(
                path=normalized,
                parent_identity=FileIdentity.from_stat(parent_metadata),
                snapshot=FileSnapshot.from_stat(metadata),
            ),
        )
        descriptor = None
        return result
    except FileNotFoundError:
        raise SecureFileError(SecureFileErrorKind.NOT_FOUND) from None
    except SecureFileError:
        raise
    except ValueError:
        raise SecureFileError(SecureFileErrorKind.INVALID) from None
    except OSError as exc:
        if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
            raise SecureFileError(SecureFileErrorKind.NOT_REGULAR) from None
        raise SecureFileError(SecureFileErrorKind.UNREADABLE) from None
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if directory_descriptor is not None:
            os.close(directory_descriptor)


def inspect_regular_file_no_follow(path: str | Path) -> FileSelection:
    """Capture a secure file selection and close its descriptor before returning."""

    opened = open_regular_file_no_follow(path)
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
    "inspect_regular_file_no_follow",
    "lexical_absolute_path",
    "open_regular_file_no_follow",
]
