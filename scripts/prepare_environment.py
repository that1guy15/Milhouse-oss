#!/usr/bin/env python3
"""Validate and restrict an existing Milhouse contributor environment."""

from __future__ import annotations

import argparse
import os
import re
import stat
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import NoReturn


class EnvironmentSafetyError(RuntimeError):
    """Raised when an existing environment cannot be trusted or restricted safely."""


INTERPRETER_LINK = re.compile(r"(?:python|python3|python3\.1[1-4])\Z")
MOUNT_ID = re.compile(r"^mnt_id:\s*([1-9][0-9]*)\s*$", re.MULTILINE)


@dataclass
class EntrySnapshot:
    """Descriptor-relative identity and policy captured before any mode mutation."""

    relative: tuple[str, ...]
    info: os.stat_result
    desired: int | None
    kind: str
    mount_id: int | None = None
    names: tuple[str, ...] | None = None


def fail(message: str) -> NoReturn:
    """Exit without printing a machine-local path."""

    print(f"environment-safety: {message}", file=sys.stderr)
    raise SystemExit(1)


def _current_owner() -> int:
    if not hasattr(os, "geteuid"):
        raise EnvironmentSafetyError("POSIX ownership checks are unavailable")
    return os.geteuid()


def _parse_mount_id(fdinfo: str) -> int:
    matches = MOUNT_ID.findall(fdinfo)
    if len(matches) != 1:
        raise EnvironmentSafetyError("the Linux mount identity could not be verified")
    return int(matches[0])


def _descriptor_flag(name: str) -> int:
    value = getattr(os, name, None)
    if not isinstance(value, int):
        raise EnvironmentSafetyError("descriptor-safe filesystem operations are unavailable")
    return value


def _directory_flags() -> int:
    return (
        os.O_RDONLY
        | _descriptor_flag("O_DIRECTORY")
        | _descriptor_flag("O_NOFOLLOW")
        | _descriptor_flag("O_CLOEXEC")
    )


def _regular_flags(*, follow_symlinks: bool = False, write_only: bool = False) -> int:
    flags = os.O_WRONLY if write_only else os.O_RDONLY
    flags |= _descriptor_flag("O_CLOEXEC") | _descriptor_flag("O_NONBLOCK")
    if not follow_symlinks:
        flags |= _descriptor_flag("O_NOFOLLOW")
    return flags


def _linux_mount_checks_required() -> bool:
    return sys.platform.startswith("linux")


def _descriptor_mount_id(descriptor: int) -> int | None:
    if not _linux_mount_checks_required():
        return None
    try:
        fdinfo = Path(f"/proc/self/fdinfo/{descriptor}").read_text(encoding="utf-8")
    except OSError as exc:
        raise EnvironmentSafetyError("the Linux mount identity could not be verified") from exc
    return _parse_mount_id(fdinfo)


def _descriptor_is_mount(descriptor: int, info: os.stat_result) -> bool:
    try:
        parent = os.stat("..", dir_fd=descriptor, follow_symlinks=False)
    except OSError as exc:
        raise EnvironmentSafetyError(
            "the environment mount boundary could not be verified"
        ) from exc
    return info.st_dev != parent.st_dev or (
        info.st_dev == parent.st_dev and info.st_ino == parent.st_ino
    )


def _classify(info: os.stat_result, *, root: bool) -> tuple[str, int | None]:
    mode = info.st_mode
    if root and stat.S_ISLNK(mode):
        raise EnvironmentSafetyError("the environment root must not be a symbolic link")
    if root and not stat.S_ISDIR(mode):
        raise EnvironmentSafetyError("the environment root must be a directory")
    if stat.S_ISLNK(mode):
        return "symlink", None
    if stat.S_ISDIR(mode):
        return "directory", 0o700
    if stat.S_ISREG(mode):
        if info.st_nlink != 1:
            raise EnvironmentSafetyError(
                "the environment contains a multiply linked regular file; "
                "remove .venv and rerun ./setup.sh"
            )
        return "regular", 0o700 if mode & stat.S_IXUSR else 0o600
    raise EnvironmentSafetyError("the environment contains a special filesystem entry")


def _same_object(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        left.st_dev,
        left.st_ino,
        left.st_uid,
        left.st_nlink,
        stat.S_IFMT(left.st_mode),
    ) == (
        right.st_dev,
        right.st_ino,
        right.st_uid,
        right.st_nlink,
        stat.S_IFMT(right.st_mode),
    )


def _require_same_object(actual: os.stat_result, expected: os.stat_result) -> None:
    if not _same_object(actual, expected):
        raise EnvironmentSafetyError("the environment changed during validation")


def _same_inode(left: os.stat_result, right: os.stat_result) -> bool:
    """Compare descriptor identity while deliberately ignoring a raced link count."""

    return (
        left.st_dev,
        left.st_ino,
        left.st_uid,
        stat.S_IFMT(left.st_mode),
    ) == (
        right.st_dev,
        right.st_ino,
        right.st_uid,
        stat.S_IFMT(right.st_mode),
    )


def _restore_descriptor_mode(
    descriptor: int,
    snapshot: EntrySnapshot,
    previous_mode: int,
) -> None:
    """Restore a mode after a raced postcondition without following any pathname."""

    try:
        os.fchmod(descriptor, previous_mode)
        restored = os.fstat(descriptor)
    except OSError as exc:
        raise EnvironmentSafetyError("the environment mode rollback could not be verified") from exc
    if not _same_inode(restored, snapshot.info) or stat.S_IMODE(restored.st_mode) != previous_mode:
        raise EnvironmentSafetyError("the environment mode rollback could not be verified")


def _open_regular_at(parent_fd: int, name: str, *, follow_symlinks: bool = False) -> int:
    last_error: OSError | None = None
    for write_only in (False, True):
        try:
            return os.open(
                name,
                _regular_flags(follow_symlinks=follow_symlinks, write_only=write_only),
                dir_fd=parent_fd,
            )
        except OSError as exc:
            last_error = exc
    assert last_error is not None
    raise last_error


def _validate_policy(
    info: os.stat_result,
    *,
    root: bool,
    owner: int,
    trusted_sync_result: bool,
    root_device: int | None,
    root_mount_id: int | None,
    mount_id: int | None,
    nested_mount: bool,
) -> tuple[str, int | None]:
    if info.st_uid != owner:
        raise EnvironmentSafetyError("the environment contains an entry owned by another user")
    if root_device is not None and info.st_dev != root_device:
        raise EnvironmentSafetyError("the environment contains an entry on another filesystem")
    if not root and nested_mount:
        raise EnvironmentSafetyError("the environment contains a nested mount point")
    kind, desired = _classify(info, root=root)
    if kind != "symlink" and root_mount_id is not None and mount_id != root_mount_id:
        raise EnvironmentSafetyError("the environment contains a nested mount point")
    write_exposed = kind != "symlink" and bool(info.st_mode & (stat.S_IWGRP | stat.S_IWOTH))
    if write_exposed and (not trusted_sync_result or root or desired is None):
        raise EnvironmentSafetyError("the environment contains a group- or world-writable entry")
    return kind, desired


def _validate_symlink(
    parent_fd: int,
    root_fd: int,
    relative: tuple[str, ...],
    info: os.stat_result,
    trusted_python_info: os.stat_result,
) -> None:
    name = relative[-1]
    if relative == ("lib64",):
        try:
            raw_target = os.readlink(name, dir_fd=parent_fd)
            target_fd = os.open("lib", _directory_flags(), dir_fd=root_fd)
            try:
                target_info = os.fstat(target_fd)
            finally:
                os.close(target_fd)
        except OSError as exc:
            raise EnvironmentSafetyError(
                "the environment contains an invalid lib64 symbolic link"
            ) from exc
        if raw_target != "lib" or not stat.S_ISDIR(target_info.st_mode):
            raise EnvironmentSafetyError(
                "the environment lib64 symbolic link must target the in-root lib directory"
            )
    elif len(relative) == 2 and relative[0] == "bin" and INTERPRETER_LINK.fullmatch(name):
        try:
            target_fd = _open_regular_at(parent_fd, name, follow_symlinks=True)
            try:
                target_info = os.fstat(target_fd)
            finally:
                os.close(target_fd)
        except OSError as exc:
            raise EnvironmentSafetyError(
                "the environment contains an invalid interpreter symbolic link"
            ) from exc
        if not stat.S_ISREG(target_info.st_mode):
            raise EnvironmentSafetyError(
                "the environment interpreter symbolic link target is not executable"
            )
        if not target_info.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
            raise EnvironmentSafetyError(
                "the environment interpreter symbolic link target is not executable"
            )
        if (target_info.st_dev, target_info.st_ino) != (
            trusted_python_info.st_dev,
            trusted_python_info.st_ino,
        ):
            raise EnvironmentSafetyError(
                "the environment interpreter symbolic link targets untrusted executable code"
            )
    else:
        raise EnvironmentSafetyError("the environment contains a prohibited symbolic link")
    try:
        current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError as exc:
        raise EnvironmentSafetyError("the environment changed during validation") from exc
    _require_same_object(current, info)


def _verify_descriptor(
    descriptor: int,
    snapshot: EntrySnapshot,
    *,
    restricted: bool,
) -> os.stat_result:
    info = os.fstat(descriptor)
    _require_same_object(info, snapshot.info)
    if snapshot.kind != "symlink":
        if _descriptor_mount_id(descriptor) != snapshot.mount_id:
            raise EnvironmentSafetyError("the environment changed during validation")
        if snapshot.relative and snapshot.kind == "directory":
            if _descriptor_is_mount(descriptor, info):
                raise EnvironmentSafetyError("the environment contains a nested mount point")
    if restricted and snapshot.desired is not None:
        if stat.S_IMODE(info.st_mode) != snapshot.desired:
            raise EnvironmentSafetyError("the environment modes were not restricted")
    return info


def _open_directory_chain(
    root_fd: int,
    relative: tuple[str, ...],
    snapshots: dict[tuple[str, ...], EntrySnapshot],
    *,
    restricted: bool,
) -> int:
    current_fd = os.dup(root_fd)
    try:
        _verify_descriptor(current_fd, snapshots[()], restricted=restricted)
        prefix: tuple[str, ...] = ()
        for name in relative:
            prefix += (name,)
            snapshot = snapshots.get(prefix)
            if snapshot is None or snapshot.kind != "directory":
                raise EnvironmentSafetyError("the environment changed during validation")
            next_fd = os.open(name, _directory_flags(), dir_fd=current_fd)
            try:
                _verify_descriptor(next_fd, snapshot, restricted=restricted)
            except Exception:
                os.close(next_fd)
                raise
            os.close(current_fd)
            current_fd = next_fd
        return current_fd
    except OSError as exc:
        os.close(current_fd)
        raise EnvironmentSafetyError("the environment changed during validation") from exc
    except Exception:
        os.close(current_fd)
        raise


def _capture_tree(
    root_fd: int,
    root_info: os.stat_result,
    root_mount_id: int | None,
    *,
    owner: int,
    trusted_sync_result: bool,
    trusted_python_info: os.stat_result,
) -> tuple[list[EntrySnapshot], dict[tuple[str, ...], EntrySnapshot]]:
    root_kind, root_desired = _validate_policy(
        root_info,
        root=True,
        owner=owner,
        trusted_sync_result=trusted_sync_result,
        root_device=None,
        root_mount_id=root_mount_id,
        mount_id=root_mount_id,
        nested_mount=False,
    )
    root_snapshot = EntrySnapshot((), root_info, root_desired, root_kind, root_mount_id)
    ordered = [root_snapshot]
    snapshots: dict[tuple[str, ...], EntrySnapshot] = {(): root_snapshot}
    directories: list[tuple[str, ...]] = [()]
    index = 0
    while index < len(directories):
        relative = directories[index]
        index += 1
        directory_fd = _open_directory_chain(root_fd, relative, snapshots, restricted=False)
        try:
            names = tuple(sorted(os.listdir(directory_fd)))
            snapshots[relative].names = names
            for name in names:
                child_relative = (*relative, name)
                raw_info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                raw_kind, _raw_desired = _classify(raw_info, root=False)
                mount_id: int | None = None
                nested_mount = False
                if raw_kind == "directory":
                    child_fd = os.open(name, _directory_flags(), dir_fd=directory_fd)
                    try:
                        pinned_info = os.fstat(child_fd)
                        _require_same_object(pinned_info, raw_info)
                        mount_id = _descriptor_mount_id(child_fd)
                        nested_mount = _descriptor_is_mount(child_fd, pinned_info)
                    finally:
                        os.close(child_fd)
                elif raw_kind == "regular":
                    child_fd = _open_regular_at(directory_fd, name)
                    try:
                        pinned_info = os.fstat(child_fd)
                        _require_same_object(pinned_info, raw_info)
                        mount_id = _descriptor_mount_id(child_fd)
                    finally:
                        os.close(child_fd)
                else:
                    pinned_info = raw_info
                    nested_mount = False
                kind, desired = _validate_policy(
                    pinned_info,
                    root=False,
                    owner=owner,
                    trusted_sync_result=trusted_sync_result,
                    root_device=root_info.st_dev,
                    root_mount_id=root_mount_id,
                    mount_id=mount_id,
                    nested_mount=nested_mount,
                )
                if kind == "symlink":
                    _validate_symlink(
                        directory_fd,
                        root_fd,
                        child_relative,
                        pinned_info,
                        trusted_python_info,
                    )
                elif (
                    kind == "regular"
                    and len(child_relative) == 2
                    and child_relative[0] == "bin"
                    and INTERPRETER_LINK.fullmatch(name)
                    and (pinned_info.st_dev, pinned_info.st_ino)
                    != (trusted_python_info.st_dev, trusted_python_info.st_ino)
                ):
                    raise EnvironmentSafetyError(
                        "the environment contains an untrusted interpreter executable"
                    )
                snapshot = EntrySnapshot(
                    child_relative,
                    pinned_info,
                    desired,
                    kind,
                    mount_id,
                )
                snapshots[child_relative] = snapshot
                ordered.append(snapshot)
                if kind == "directory":
                    directories.append(child_relative)
        finally:
            os.close(directory_fd)
    return ordered, snapshots


def _verify_root_name(
    parent_fd: int,
    root_name: str,
    snapshot: EntrySnapshot,
    *,
    restricted: bool,
) -> None:
    try:
        descriptor = os.open(root_name, _directory_flags(), dir_fd=parent_fd)
        try:
            _verify_descriptor(descriptor, snapshot, restricted=restricted)
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise EnvironmentSafetyError("the environment changed during validation") from exc


def _verify_entry_binding(
    parent_fd: int,
    root_name: str,
    root_fd: int,
    descriptor: int,
    snapshot: EntrySnapshot,
    snapshots: dict[tuple[str, ...], EntrySnapshot],
) -> None:
    """Verify the mutated descriptor is still reachable through every pinned name."""

    _verify_root_name(parent_fd, root_name, snapshots[()], restricted=False)
    entry_parent_fd = named_descriptor = -1
    try:
        if not snapshot.relative:
            named_descriptor = os.open(root_name, _directory_flags(), dir_fd=parent_fd)
        else:
            entry_parent_fd = _open_directory_chain(
                root_fd,
                snapshot.relative[:-1],
                snapshots,
                restricted=False,
            )
            if snapshot.kind == "directory":
                named_descriptor = os.open(
                    snapshot.relative[-1],
                    _directory_flags(),
                    dir_fd=entry_parent_fd,
                )
            elif snapshot.kind == "regular":
                named_descriptor = _open_regular_at(entry_parent_fd, snapshot.relative[-1])
            else:
                raise EnvironmentSafetyError("the environment changed during validation")
        named_info = _verify_descriptor(named_descriptor, snapshot, restricted=True)
        held_info = _verify_descriptor(descriptor, snapshot, restricted=True)
        _require_same_object(named_info, held_info)
        _verify_root_name(parent_fd, root_name, snapshots[()], restricted=False)
    finally:
        if named_descriptor >= 0:
            os.close(named_descriptor)
        if entry_parent_fd >= 0:
            os.close(entry_parent_fd)


def _verify_tree(
    parent_fd: int,
    root_name: str,
    root_fd: int,
    snapshots: dict[tuple[str, ...], EntrySnapshot],
    *,
    restricted: bool,
) -> None:
    _verify_root_name(parent_fd, root_name, snapshots[()], restricted=restricted)
    for relative, snapshot in snapshots.items():
        if snapshot.kind != "directory":
            continue
        directory_fd = _open_directory_chain(root_fd, relative, snapshots, restricted=restricted)
        try:
            names = tuple(sorted(os.listdir(directory_fd)))
            if names != snapshot.names:
                raise EnvironmentSafetyError("the environment changed during validation")
            for name in names:
                child_relative = (*relative, name)
                child = snapshots.get(child_relative)
                if child is None:
                    raise EnvironmentSafetyError("the environment changed during validation")
                current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                _require_same_object(current, child.info)
                if child.kind == "directory":
                    child_fd = os.open(name, _directory_flags(), dir_fd=directory_fd)
                    try:
                        _verify_descriptor(child_fd, child, restricted=restricted)
                    finally:
                        os.close(child_fd)
                elif child.kind == "regular":
                    child_fd = _open_regular_at(directory_fd, name)
                    try:
                        _verify_descriptor(child_fd, child, restricted=restricted)
                    finally:
                        os.close(child_fd)
        finally:
            os.close(directory_fd)


def _restrict_tree(
    parent_fd: int,
    root_name: str,
    root_fd: int,
    ordered: list[EntrySnapshot],
    snapshots: dict[tuple[str, ...], EntrySnapshot],
) -> None:
    for snapshot in reversed(ordered):
        if snapshot.desired is None:
            continue
        if not snapshot.relative:
            descriptor = os.dup(root_fd)
        else:
            entry_parent_fd = _open_directory_chain(
                root_fd,
                snapshot.relative[:-1],
                snapshots,
                restricted=False,
            )
            try:
                if snapshot.kind == "directory":
                    descriptor = os.open(
                        snapshot.relative[-1],
                        _directory_flags(),
                        dir_fd=entry_parent_fd,
                    )
                else:
                    descriptor = _open_regular_at(entry_parent_fd, snapshot.relative[-1])
            finally:
                os.close(entry_parent_fd)
        try:
            before = _verify_descriptor(descriptor, snapshot, restricted=False)
            previous_mode = stat.S_IMODE(before.st_mode)
            try:
                os.fchmod(descriptor, snapshot.desired)
                _verify_descriptor(descriptor, snapshot, restricted=True)
                _verify_entry_binding(
                    parent_fd,
                    root_name,
                    root_fd,
                    descriptor,
                    snapshot,
                    snapshots,
                )
            except EnvironmentSafetyError:
                _restore_descriptor_mode(descriptor, snapshot, previous_mode)
                raise
            except OSError as exc:
                _restore_descriptor_mode(descriptor, snapshot, previous_mode)
                raise EnvironmentSafetyError("the environment changed during validation") from exc
        except OSError as exc:
            raise EnvironmentSafetyError("the environment changed during validation") from exc
        finally:
            os.close(descriptor)


def prepare_environment(
    path: Path,
    *,
    trusted_sync_result: bool = False,
    trusted_python: Path | None = None,
) -> int:
    """Validate an owned tree, reject prior exposure, and restrict its modes."""

    owner = _current_owner()
    parent_fd = root_fd = trusted_python_fd = -1
    try:
        interpreter = (trusted_python or Path(sys.executable)).resolve(strict=True)
        if not interpreter.is_file() or not os.access(interpreter, os.X_OK):
            raise EnvironmentSafetyError(
                "the trusted Python interpreter must be an executable regular file"
            )
        trusted_python_fd = os.open(interpreter, _regular_flags())
        trusted_python_info = os.fstat(trusted_python_fd)
        if not stat.S_ISREG(trusted_python_info.st_mode) or not (
            trusted_python_info.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        ):
            raise EnvironmentSafetyError(
                "the trusted Python interpreter must be an executable regular file"
            )

        absolute = path.absolute()
        if not absolute.name or absolute.name in {".", ".."}:
            raise EnvironmentSafetyError("the environment path must name a directory")
        parent_fd = os.open(absolute.parent, _directory_flags())
        try:
            os.mkdir(absolute.name, mode=0o700, dir_fd=parent_fd)
        except FileExistsError:
            pass
        raw_root = os.stat(absolute.name, dir_fd=parent_fd, follow_symlinks=False)
        _classify(raw_root, root=True)
        root_fd = os.open(absolute.name, _directory_flags(), dir_fd=parent_fd)
        root_info = os.fstat(root_fd)
        _require_same_object(root_info, raw_root)
        root_mount_id = _descriptor_mount_id(root_fd)

        ordered, snapshots = _capture_tree(
            root_fd,
            root_info,
            root_mount_id,
            owner=owner,
            trusted_sync_result=trusted_sync_result,
            trusted_python_info=trusted_python_info,
        )
        _verify_tree(
            parent_fd,
            absolute.name,
            root_fd,
            snapshots,
            restricted=False,
        )
        _restrict_tree(parent_fd, absolute.name, root_fd, ordered, snapshots)
        _verify_tree(
            parent_fd,
            absolute.name,
            root_fd,
            snapshots,
            restricted=True,
        )
    except EnvironmentSafetyError:
        raise
    except OSError as exc:
        raise EnvironmentSafetyError("the environment could not be validated safely") from exc
    finally:
        for descriptor in (root_fd, parent_fd, trusted_python_fd):
            if descriptor >= 0:
                os.close(descriptor)
    return len(ordered)


def parse_args(arguments: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", type=Path)
    parser.add_argument("--trusted-python", type=Path)
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument(
        "--trusted-sync-result",
        action="store_true",
        help="restrict entries just created beneath a prevalidated private environment root",
    )
    return parser.parse_args(arguments)


def main(arguments: Sequence[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if arguments is None else arguments)
    try:
        count = prepare_environment(
            args.path,
            trusted_sync_result=args.trusted_sync_result,
            trusted_python=args.trusted_python,
        )
    except EnvironmentSafetyError as exc:
        fail(str(exc))
    if not args.quiet:
        print(f"environment-safety: {count} existing entry or entries restricted")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
