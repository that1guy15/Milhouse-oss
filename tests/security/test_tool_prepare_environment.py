from __future__ import annotations

import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from scripts import prepare_environment


def test_missing_environment_root_is_atomically_created_and_restricted(tmp_path: Path) -> None:
    environment = tmp_path / "missing"

    assert prepare_environment.prepare_environment(environment) == 1
    assert environment.is_dir()
    assert not environment.is_symlink()
    assert stat.S_IMODE(environment.stat().st_mode) == 0o700


def test_environment_requires_posix_ownership_support(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    environment = tmp_path / "environment"
    environment.mkdir()
    monkeypatch.delattr(prepare_environment.os, "geteuid")

    with pytest.raises(
        prepare_environment.EnvironmentSafetyError,
        match="POSIX ownership checks are unavailable",
    ):
        prepare_environment.prepare_environment(environment)


def test_linux_fdinfo_mount_id_parser_is_strict() -> None:
    assert prepare_environment._parse_mount_id("pos:\t0\nflags:\t010000000\nmnt_id:\t42\n") == 42

    for malformed in (
        "pos:\t0\n",
        "mnt_id:\t0\n",
        "mnt_id:\tnot-a-number\n",
        "mnt_id:\t41\nmnt_id:\t42\n",
    ):
        with pytest.raises(
            prepare_environment.EnvironmentSafetyError,
            match="Linux mount identity could not be verified",
        ):
            prepare_environment._parse_mount_id(malformed)


def test_descriptor_safety_requires_all_platform_flags(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(prepare_environment.os, "O_CLOEXEC", None)

    with pytest.raises(
        prepare_environment.EnvironmentSafetyError,
        match="descriptor-safe filesystem operations are unavailable",
    ):
        prepare_environment._directory_flags()


def test_linux_mount_identity_reads_the_pinned_descriptor_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FdInfo:
        def __init__(self, *, readable: bool) -> None:
            self.readable = readable

        def read_text(self, *, encoding: str) -> str:
            assert encoding == "utf-8"
            if not self.readable:
                raise OSError("synthetic procfs failure")
            return "pos:\t0\nmnt_id:\t73\n"

    monkeypatch.setattr(prepare_environment, "_linux_mount_checks_required", lambda: True)
    monkeypatch.setattr(prepare_environment, "Path", lambda _value: FdInfo(readable=True))
    assert prepare_environment._descriptor_mount_id(19) == 73

    monkeypatch.setattr(prepare_environment, "Path", lambda _value: FdInfo(readable=False))
    with pytest.raises(
        prepare_environment.EnvironmentSafetyError,
        match="Linux mount identity could not be verified",
    ):
        prepare_environment._descriptor_mount_id(19)


def test_descriptor_mount_identity_is_disabled_on_non_linux(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(prepare_environment, "_linux_mount_checks_required", lambda: False)
    monkeypatch.setattr(
        prepare_environment,
        "Path",
        lambda _value: pytest.fail("non-Linux platforms must not inspect procfs"),
    )

    assert prepare_environment._descriptor_mount_id(-1) is None


def test_mode_rollback_failure_is_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entry = tmp_path / "entry"
    entry.write_text("synthetic\n", encoding="utf-8")
    entry.chmod(0o600)
    descriptor = os.open(entry, os.O_RDONLY)
    try:
        info = os.fstat(descriptor)
        snapshot = prepare_environment.EntrySnapshot(
            ("entry",),
            info,
            0o600,
            "regular",
        )
        changed = list(info)
        changed[1] += 1
        monkeypatch.setattr(
            prepare_environment.os,
            "fstat",
            lambda _descriptor: os.stat_result(changed),
        )

        with pytest.raises(
            prepare_environment.EnvironmentSafetyError,
            match="mode rollback could not be verified",
        ):
            prepare_environment._restore_descriptor_mode(descriptor, snapshot, 0o600)
    finally:
        os.close(descriptor)


def test_policy_rejects_owner_and_nested_mount_mismatches(tmp_path: Path) -> None:
    entry = tmp_path / "entry"
    entry.write_text("synthetic\n", encoding="utf-8")
    info = entry.stat()
    common = {
        "root": False,
        "trusted_sync_result": False,
        "root_device": info.st_dev,
        "root_mount_id": None,
        "mount_id": None,
    }

    with pytest.raises(
        prepare_environment.EnvironmentSafetyError,
        match="owned by another user",
    ):
        prepare_environment._validate_policy(
            info,
            owner=info.st_uid + 1,
            nested_mount=False,
            **common,
        )

    with pytest.raises(
        prepare_environment.EnvironmentSafetyError,
        match="nested mount point",
    ):
        prepare_environment._validate_policy(
            info,
            owner=info.st_uid,
            nested_mount=True,
            **common,
        )


def test_interpreter_symlink_to_directory_is_rejected(tmp_path: Path) -> None:
    environment = tmp_path / "environment"
    binary = environment / "bin"
    binary.mkdir(parents=True)
    directory_target = tmp_path / "directory-target"
    directory_target.mkdir()
    (binary / "python").symlink_to(directory_target, target_is_directory=True)

    with pytest.raises(
        prepare_environment.EnvironmentSafetyError,
        match="target is not executable",
    ):
        prepare_environment.prepare_environment(environment)


def test_descriptor_postconditions_reject_mount_and_mode_changes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entry = tmp_path / "entry"
    entry.write_text("synthetic\n", encoding="utf-8")
    entry.chmod(0o600)
    descriptor = os.open(entry, os.O_RDONLY)
    try:
        info = os.fstat(descriptor)
        snapshot = prepare_environment.EntrySnapshot(
            ("entry",),
            info,
            0o600,
            "regular",
            mount_id=None,
        )
        monkeypatch.setattr(prepare_environment, "_descriptor_mount_id", lambda _fd: 91)
        with pytest.raises(
            prepare_environment.EnvironmentSafetyError,
            match="changed during validation",
        ):
            prepare_environment._verify_descriptor(descriptor, snapshot, restricted=False)

        monkeypatch.setattr(prepare_environment, "_descriptor_mount_id", lambda _fd: None)
        wrong_mode = prepare_environment.EntrySnapshot(
            ("entry",),
            info,
            0o700,
            "regular",
            mount_id=None,
        )
        with pytest.raises(
            prepare_environment.EnvironmentSafetyError,
            match="modes were not restricted",
        ):
            prepare_environment._verify_descriptor(descriptor, wrong_mode, restricted=True)
    finally:
        os.close(descriptor)

    nested = tmp_path / "nested"
    nested.mkdir()
    directory_descriptor = os.open(nested, os.O_RDONLY)
    try:
        directory_info = os.fstat(directory_descriptor)
        directory_snapshot = prepare_environment.EntrySnapshot(
            ("nested",),
            directory_info,
            0o700,
            "directory",
            mount_id=None,
        )
        monkeypatch.setattr(prepare_environment, "_descriptor_is_mount", lambda *_args: True)
        with pytest.raises(
            prepare_environment.EnvironmentSafetyError,
            match="nested mount point",
        ):
            prepare_environment._verify_descriptor(
                directory_descriptor,
                directory_snapshot,
                restricted=False,
            )
    finally:
        os.close(directory_descriptor)


def test_directory_chain_rejects_missing_snapshot_and_missing_component(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "root"
    root.mkdir()
    root_descriptor = os.open(root, os.O_RDONLY)
    try:
        monkeypatch.setattr(prepare_environment, "_descriptor_mount_id", lambda _fd: None)
        root_info = os.fstat(root_descriptor)
        root_snapshot = prepare_environment.EntrySnapshot(
            (),
            root_info,
            0o700,
            "directory",
            mount_id=None,
        )
        with pytest.raises(
            prepare_environment.EnvironmentSafetyError,
            match="changed during validation",
        ):
            prepare_environment._open_directory_chain(
                root_descriptor,
                ("missing",),
                {(): root_snapshot},
                restricted=False,
            )

        wrong_kind = prepare_environment.EntrySnapshot(
            ("missing",),
            root_info,
            0o600,
            "regular",
            mount_id=None,
        )
        with pytest.raises(
            prepare_environment.EnvironmentSafetyError,
            match="changed during validation",
        ):
            prepare_environment._open_directory_chain(
                root_descriptor,
                ("missing",),
                {(): root_snapshot, ("missing",): wrong_kind},
                restricted=False,
            )

        missing_snapshot = prepare_environment.EntrySnapshot(
            ("missing",),
            root_info,
            0o700,
            "directory",
            mount_id=None,
        )
        with pytest.raises(
            prepare_environment.EnvironmentSafetyError,
            match="changed during validation",
        ):
            prepare_environment._open_directory_chain(
                root_descriptor,
                ("missing",),
                {(): root_snapshot, ("missing",): missing_snapshot},
                restricted=False,
            )
    finally:
        os.close(root_descriptor)


def test_tree_verification_rejects_inventory_changes_and_missing_snapshots(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    environment = tmp_path / "environment"
    environment.mkdir()
    (environment / "payload").write_text("synthetic\n", encoding="utf-8")
    parent_descriptor = os.open(tmp_path, os.O_RDONLY)
    root_descriptor = os.open(environment, os.O_RDONLY)
    try:
        monkeypatch.setattr(prepare_environment, "_descriptor_mount_id", lambda _fd: None)
        root_info = os.fstat(root_descriptor)
        root_snapshot = prepare_environment.EntrySnapshot(
            (),
            root_info,
            0o700,
            "directory",
            mount_id=None,
            names=(),
        )
        with pytest.raises(
            prepare_environment.EnvironmentSafetyError,
            match="changed during validation",
        ):
            prepare_environment._verify_tree(
                parent_descriptor,
                environment.name,
                root_descriptor,
                {(): root_snapshot},
                restricted=False,
            )

        root_snapshot.names = ("payload",)
        with pytest.raises(
            prepare_environment.EnvironmentSafetyError,
            match="changed during validation",
        ):
            prepare_environment._verify_tree(
                parent_descriptor,
                environment.name,
                root_descriptor,
                {(): root_snapshot},
                restricted=False,
            )
    finally:
        os.close(root_descriptor)
        os.close(parent_descriptor)


def test_entry_binding_rejects_an_unexpected_nonmutable_snapshot_kind(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    environment = tmp_path / "environment"
    environment.mkdir(mode=0o700)
    target = tmp_path / "target"
    target.write_text("outside\n", encoding="utf-8")
    link = environment / "link"
    link.symlink_to(target)
    parent_descriptor = os.open(tmp_path, os.O_RDONLY)
    root_descriptor = os.open(environment, os.O_RDONLY)
    try:
        monkeypatch.setattr(prepare_environment, "_descriptor_mount_id", lambda _fd: None)
        root_info = os.fstat(root_descriptor)
        root_snapshot = prepare_environment.EntrySnapshot(
            (),
            root_info,
            0o700,
            "directory",
            mount_id=None,
        )
        link_snapshot = prepare_environment.EntrySnapshot(
            ("link",),
            os.stat(link, follow_symlinks=False),
            None,
            "symlink",
            mount_id=None,
        )

        with pytest.raises(
            prepare_environment.EnvironmentSafetyError,
            match="changed during validation",
        ):
            prepare_environment._verify_entry_binding(
                parent_descriptor,
                environment.name,
                root_descriptor,
                root_descriptor,
                link_snapshot,
                {(): root_snapshot, ("link",): link_snapshot},
            )
    finally:
        os.close(root_descriptor)
        os.close(parent_descriptor)


def test_environment_rejects_invalid_trusted_interpreter_and_root_path(tmp_path: Path) -> None:
    with pytest.raises(
        prepare_environment.EnvironmentSafetyError,
        match="trusted Python interpreter must be an executable regular file",
    ):
        prepare_environment.prepare_environment(
            tmp_path / "environment",
            trusted_python=tmp_path,
        )

    with pytest.raises(
        prepare_environment.EnvironmentSafetyError,
        match="environment path must name a directory",
    ):
        prepare_environment.prepare_environment(Path("/"))


def test_trusted_interpreter_name_swap_to_directory_is_rejected_before_environment_creation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    interpreter = tmp_path / "python"
    interpreter.write_text("synthetic executable\n", encoding="utf-8")
    interpreter.chmod(0o700)
    detached = tmp_path / "detached-python"
    environment = tmp_path / "environment"
    original_open = prepare_environment.os.open
    swapped = False

    def swap_before_open(path: object, flags: int, *args: object, **kwargs: object) -> int:
        nonlocal swapped
        if not swapped and os.fspath(path) == os.fspath(interpreter):
            interpreter.rename(detached)
            interpreter.mkdir(mode=0o700)
            swapped = True
        return original_open(path, flags, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(prepare_environment.os, "open", swap_before_open)

    with pytest.raises(
        prepare_environment.EnvironmentSafetyError,
        match="trusted Python interpreter must be an executable regular file",
    ):
        prepare_environment.prepare_environment(environment, trusted_python=interpreter)

    assert swapped
    assert detached.read_text(encoding="utf-8") == "synthetic executable\n"
    assert stat.S_IMODE(detached.stat().st_mode) == 0o700
    assert interpreter.is_dir()
    assert stat.S_IMODE(interpreter.stat().st_mode) == 0o700
    assert not environment.exists()


def test_owned_tree_is_restricted_without_following_symlinks(tmp_path: Path) -> None:
    environment = tmp_path / "environment"
    scripts = environment / "bin"
    scripts.mkdir(parents=True, mode=0o755)
    config = environment / "pyvenv.cfg"
    config.write_text("synthetic\n", encoding="utf-8")
    config.chmod(0o644)
    executable = scripts / "tool"
    executable.write_text("synthetic\n", encoding="utf-8")
    executable.chmod(0o755)
    target = tmp_path / "target"
    target.write_text("outside\n", encoding="utf-8")
    target.chmod(0o700)
    link = scripts / "python"
    link.symlink_to(target)

    assert prepare_environment.prepare_environment(environment, trusted_python=target) == 5

    assert stat.S_IMODE(environment.stat().st_mode) == 0o700
    assert stat.S_IMODE(scripts.stat().st_mode) == 0o700
    assert stat.S_IMODE(config.stat().st_mode) == 0o600
    assert stat.S_IMODE(executable.stat().st_mode) == 0o700
    assert link.is_symlink()
    assert stat.S_IMODE(target.stat().st_mode) == 0o700


@pytest.mark.parametrize("mode", (0o720, 0o702))
def test_write_exposed_tree_is_rejected_before_any_modes_change(
    tmp_path: Path,
    mode: int,
) -> None:
    environment = tmp_path / "environment"
    environment.mkdir(mode=0o700)
    exposed = environment / "exposed.txt"
    exposed.write_text("synthetic\n", encoding="utf-8")
    exposed.chmod(mode)

    with pytest.raises(
        prepare_environment.EnvironmentSafetyError,
        match="group- or world-writable",
    ):
        prepare_environment.prepare_environment(environment)

    assert stat.S_IMODE(exposed.stat().st_mode) == mode


def test_trusted_sync_result_restricts_new_single_link_entries(tmp_path: Path) -> None:
    environment = tmp_path / "environment"
    environment.mkdir(mode=0o700)
    lock = environment / ".lock"
    lock.write_text("", encoding="utf-8")
    lock.chmod(0o666)

    assert (
        prepare_environment.prepare_environment(
            environment,
            trusted_sync_result=True,
        )
        == 2
    )
    assert stat.S_IMODE(environment.stat().st_mode) == 0o700
    assert stat.S_IMODE(lock.stat().st_mode) == 0o600


def test_symlink_root_and_special_entry_are_rejected(tmp_path: Path) -> None:
    environment = tmp_path / "environment"
    environment.mkdir()
    link = tmp_path / "environment-link"
    link.symlink_to(environment, target_is_directory=True)
    with pytest.raises(
        prepare_environment.EnvironmentSafetyError,
        match="root must not be a symbolic link",
    ):
        prepare_environment.prepare_environment(link)

    regular_root = tmp_path / "regular-root"
    regular_root.write_text("not a directory\n", encoding="utf-8")
    with pytest.raises(
        prepare_environment.EnvironmentSafetyError,
        match="root must be a directory",
    ):
        prepare_environment.prepare_environment(regular_root)

    fifo = environment / "pipe"
    os.mkfifo(fifo, mode=0o600)
    with pytest.raises(
        prepare_environment.EnvironmentSafetyError,
        match="special filesystem entry",
    ):
        prepare_environment.prepare_environment(environment)


@pytest.mark.parametrize("trusted_sync_result", [False, True])
def test_hard_link_is_rejected_without_modifying_outside_state(
    tmp_path: Path,
    trusted_sync_result: bool,
) -> None:
    environment = tmp_path / "environment"
    environment.mkdir()
    external = tmp_path / "external"
    external.write_text("outside\n", encoding="utf-8")
    external.chmod(0o644)
    os.link(external, environment / "linked")

    with pytest.raises(
        prepare_environment.EnvironmentSafetyError,
        match=r"multiply linked regular file; remove \.venv and rerun \./setup\.sh",
    ):
        prepare_environment.prepare_environment(
            environment,
            trusted_sync_result=trusted_sync_result,
        )

    assert stat.S_IMODE(external.stat().st_mode) == 0o644


def test_nested_entry_on_another_filesystem_is_rejected_before_modes_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    environment = tmp_path / "environment"
    environment.mkdir(mode=0o700)
    nested = environment / "mounted-entry"
    nested.write_text("synthetic\n", encoding="utf-8")
    nested.chmod(0o640)
    original_validate = prepare_environment._validate_policy

    def cross_device(info: os.stat_result, **kwargs: object) -> tuple[str, int | None]:
        if not kwargs["root"] and stat.S_ISREG(info.st_mode):
            values = list(info)
            values[2] += 1
            info = os.stat_result(values)
        return original_validate(info, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(prepare_environment, "_validate_policy", cross_device)

    with pytest.raises(
        prepare_environment.EnvironmentSafetyError,
        match="entry on another filesystem",
    ):
        prepare_environment.prepare_environment(environment)

    assert stat.S_IMODE(nested.stat().st_mode) == 0o640


def test_linux_mount_identity_allows_root_but_rejects_descendant_mount(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    environment = tmp_path / "environment"
    nested = environment / "nested-mount"
    nested.mkdir(parents=True)
    environment.chmod(0o700)
    nested.chmod(0o750)
    root_inode = environment.stat().st_ino
    nested_inode = nested.stat().st_ino

    def mount_id(descriptor: int) -> int:
        inode = os.fstat(descriptor).st_ino
        assert inode in {root_inode, nested_inode}
        return 41 if inode == root_inode else 42

    monkeypatch.setattr(
        prepare_environment,
        "_descriptor_mount_id",
        mount_id,
    )
    monkeypatch.setattr(prepare_environment, "_descriptor_is_mount", lambda *_args: False)

    with pytest.raises(
        prepare_environment.EnvironmentSafetyError,
        match="nested mount point",
    ):
        prepare_environment.prepare_environment(environment)

    assert stat.S_IMODE(environment.stat().st_mode) == 0o700
    assert stat.S_IMODE(nested.stat().st_mode) == 0o750


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux bind-mount regression")
def test_real_same_device_bind_mount_is_rejected_when_mount_capability_is_available(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mount = shutil.which("mount")
    unmount = shutil.which("umount")
    if mount is None or unmount is None:
        pytest.skip("mount utilities are unavailable")
    environment = tmp_path / "environment"
    nested = environment / "nested-mount"
    source = tmp_path / "bind-source"
    nested.mkdir(parents=True)
    source.mkdir()
    mounted = subprocess.run(
        [mount, "--bind", os.fspath(source), os.fspath(nested)],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    if mounted.returncode != 0:
        pytest.skip("bind-mount capability is unavailable")

    try:
        assert environment.stat().st_dev == nested.stat().st_dev
        monkeypatch.setattr(prepare_environment, "_descriptor_is_mount", lambda *_args: False)
        with pytest.raises(
            prepare_environment.EnvironmentSafetyError,
            match="nested mount point",
        ):
            prepare_environment.prepare_environment(environment)
    finally:
        released = subprocess.run(
            [unmount, os.fspath(nested)],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if released.returncode != 0:
            released = subprocess.run(
                [unmount, "-l", os.fspath(nested)],
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
        assert released.returncode == 0


def test_internal_noninterpreter_symlink_is_rejected_without_touching_outside_state(
    tmp_path: Path,
) -> None:
    environment = tmp_path / "environment"
    library = environment / "lib"
    library.mkdir(parents=True)
    outside = tmp_path / "outside-packages"
    outside.mkdir()
    sentinel = outside / "sentinel.txt"
    sentinel.write_text("unchanged\n", encoding="utf-8")
    inventory = outside / "inventory.json"
    inventory.write_text('{"state": "unchanged"}\n', encoding="utf-8")
    (library / "site-packages").symlink_to(outside, target_is_directory=True)

    with pytest.raises(
        prepare_environment.EnvironmentSafetyError,
        match="prohibited symbolic link",
    ):
        prepare_environment.prepare_environment(environment)

    assert sentinel.read_text(encoding="utf-8") == "unchanged\n"
    assert inventory.read_text(encoding="utf-8") == '{"state": "unchanged"}\n'


def test_root_swap_before_descriptor_mutation_never_touches_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    environment = tmp_path / "environment"
    environment.mkdir(mode=0o700)
    internal = environment / "payload.txt"
    internal.write_text("internal\n", encoding="utf-8")
    internal.chmod(0o644)
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o700)
    sentinel = outside / "payload.txt"
    sentinel.write_text("outside\n", encoding="utf-8")
    sentinel.chmod(0o644)
    detached = tmp_path / "detached-environment"
    original_fchmod = prepare_environment.os.fchmod
    swapped = False

    def swap_root(descriptor: int, mode: int) -> None:
        nonlocal swapped
        if not swapped:
            environment.rename(detached)
            environment.symlink_to(outside, target_is_directory=True)
            swapped = True
        original_fchmod(descriptor, mode)

    monkeypatch.setattr(prepare_environment.os, "fchmod", swap_root)
    monkeypatch.setattr(
        prepare_environment.os,
        "chmod",
        lambda *_args, **_kwargs: pytest.fail("pathname chmod is prohibited"),
    )

    with pytest.raises(
        prepare_environment.EnvironmentSafetyError,
        match="changed during validation",
    ):
        prepare_environment.prepare_environment(environment)

    assert swapped
    detached_payload = detached / "payload.txt"
    assert detached_payload.read_text(encoding="utf-8") == "internal\n"
    assert stat.S_IMODE(detached_payload.stat().st_mode) == 0o644
    assert sentinel.read_text(encoding="utf-8") == "outside\n"
    assert stat.S_IMODE(sentinel.stat().st_mode) == 0o644


def test_nested_swap_before_descriptor_mutation_never_touches_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    environment = tmp_path / "environment"
    nested = environment / "nested"
    nested.mkdir(parents=True, mode=0o700)
    internal = nested / "payload.txt"
    internal.write_text("internal\n", encoding="utf-8")
    internal.chmod(0o644)
    internal_inode = internal.stat().st_ino
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o700)
    sentinel = outside / "payload.txt"
    sentinel.write_text("outside\n", encoding="utf-8")
    sentinel.chmod(0o644)
    detached = environment / "detached-nested"
    original_fchmod = prepare_environment.os.fchmod
    swapped = False

    def swap_nested(descriptor: int, mode: int) -> None:
        nonlocal swapped
        if not swapped and os.fstat(descriptor).st_ino == internal_inode:
            nested.rename(detached)
            nested.symlink_to(outside, target_is_directory=True)
            swapped = True
        original_fchmod(descriptor, mode)

    monkeypatch.setattr(prepare_environment.os, "fchmod", swap_nested)
    monkeypatch.setattr(
        prepare_environment.os,
        "chmod",
        lambda *_args, **_kwargs: pytest.fail("pathname chmod is prohibited"),
    )

    with pytest.raises(
        prepare_environment.EnvironmentSafetyError,
        match="changed during validation",
    ):
        prepare_environment.prepare_environment(environment)

    assert swapped
    detached_payload = detached / "payload.txt"
    assert detached_payload.read_text(encoding="utf-8") == "internal\n"
    assert stat.S_IMODE(detached_payload.stat().st_mode) == 0o644
    assert sentinel.read_text(encoding="utf-8") == "outside\n"
    assert stat.S_IMODE(sentinel.stat().st_mode) == 0o644


def test_regular_file_swap_before_descriptor_mutation_never_touches_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    environment = tmp_path / "environment"
    environment.mkdir(mode=0o700)
    internal = environment / "payload.txt"
    internal.write_text("internal\n", encoding="utf-8")
    internal.chmod(0o644)
    internal_inode = internal.stat().st_ino
    detached = environment / "detached-payload.txt"
    outside = tmp_path / "outside-payload.txt"
    outside.write_text("outside\n", encoding="utf-8")
    outside.chmod(0o644)
    outside_inode = outside.stat().st_ino
    original_fchmod = prepare_environment.os.fchmod
    swapped = False

    def swap_file(descriptor: int, mode: int) -> None:
        nonlocal swapped
        if not swapped and os.fstat(descriptor).st_ino == internal_inode:
            internal.rename(detached)
            os.link(outside, internal)
            swapped = True
        original_fchmod(descriptor, mode)

    monkeypatch.setattr(prepare_environment.os, "fchmod", swap_file)
    monkeypatch.setattr(
        prepare_environment.os,
        "chmod",
        lambda *_args, **_kwargs: pytest.fail("pathname chmod is prohibited"),
    )

    with pytest.raises(
        prepare_environment.EnvironmentSafetyError,
        match="changed during validation",
    ):
        prepare_environment.prepare_environment(environment)

    assert swapped
    assert internal.stat().st_ino == outside_inode
    assert detached.read_text(encoding="utf-8") == "internal\n"
    assert stat.S_IMODE(detached.stat().st_mode) == 0o644
    assert outside.read_text(encoding="utf-8") == "outside\n"
    assert stat.S_IMODE(outside.stat().st_mode) == 0o644


def test_regular_file_escaped_outside_environment_during_fchmod_is_rolled_back(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    environment = tmp_path / "environment"
    environment.mkdir(mode=0o700)
    internal = environment / "payload.txt"
    internal.write_text("internal\n", encoding="utf-8")
    internal.chmod(0o644)
    internal_inode = internal.stat().st_ino
    escaped = tmp_path / "escaped-payload.txt"
    outside = tmp_path / "outside-replacement.txt"
    outside.write_text("outside\n", encoding="utf-8")
    outside.chmod(0o640)
    outside_inode = outside.stat().st_ino
    original_fchmod = prepare_environment.os.fchmod
    escaped_once = False

    def escape_file(descriptor: int, mode: int) -> None:
        nonlocal escaped_once
        if not escaped_once and os.fstat(descriptor).st_ino == internal_inode:
            internal.rename(escaped)
            os.link(outside, internal)
            escaped_once = True
        original_fchmod(descriptor, mode)

    monkeypatch.setattr(prepare_environment.os, "fchmod", escape_file)
    monkeypatch.setattr(
        prepare_environment.os,
        "chmod",
        lambda *_args, **_kwargs: pytest.fail("pathname chmod is prohibited"),
    )

    with pytest.raises(
        prepare_environment.EnvironmentSafetyError,
        match="changed during validation",
    ):
        prepare_environment.prepare_environment(environment)

    assert escaped_once
    assert escaped.stat().st_ino == internal_inode
    assert escaped.read_text(encoding="utf-8") == "internal\n"
    assert stat.S_IMODE(escaped.stat().st_mode) == 0o644
    assert internal.stat().st_ino == outside_inode
    assert internal.read_text(encoding="utf-8") == "outside\n"
    assert stat.S_IMODE(internal.stat().st_mode) == 0o640
    assert outside.read_text(encoding="utf-8") == "outside\n"
    assert stat.S_IMODE(outside.stat().st_mode) == 0o640


def test_nested_directory_escaped_outside_environment_during_fchmod_is_rolled_back(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    environment = tmp_path / "environment"
    nested = environment / "nested"
    nested.mkdir(parents=True, mode=0o755)
    nested.chmod(0o755)
    payload = nested / "payload.txt"
    payload.write_text("internal\n", encoding="utf-8")
    payload.chmod(0o600)
    nested_inode = nested.stat().st_ino
    escaped = tmp_path / "escaped-nested"

    replacement = tmp_path / "replacement-nested"
    replacement.mkdir(mode=0o750)
    replacement.chmod(0o750)
    replacement_payload = replacement / "payload.txt"
    replacement_payload.write_text("replacement\n", encoding="utf-8")
    replacement_payload.chmod(0o640)
    replacement_inode = replacement.stat().st_ino

    outside = tmp_path / "outside-sentinel.txt"
    outside.write_text("outside\n", encoding="utf-8")
    outside.chmod(0o644)
    original_fchmod = prepare_environment.os.fchmod
    escaped_once = False

    def escape_directory(descriptor: int, mode: int) -> None:
        nonlocal escaped_once
        if not escaped_once and os.fstat(descriptor).st_ino == nested_inode:
            nested.rename(escaped)
            replacement.rename(nested)
            escaped_once = True
        original_fchmod(descriptor, mode)

    monkeypatch.setattr(prepare_environment.os, "fchmod", escape_directory)
    monkeypatch.setattr(
        prepare_environment.os,
        "chmod",
        lambda *_args, **_kwargs: pytest.fail("pathname chmod is prohibited"),
    )

    with pytest.raises(
        prepare_environment.EnvironmentSafetyError,
        match="changed during validation",
    ):
        prepare_environment.prepare_environment(environment)

    assert escaped_once
    assert escaped.stat().st_ino == nested_inode
    assert stat.S_IMODE(escaped.stat().st_mode) == 0o755
    escaped_payload = escaped / "payload.txt"
    assert escaped_payload.read_text(encoding="utf-8") == "internal\n"
    assert stat.S_IMODE(escaped_payload.stat().st_mode) == 0o600
    assert nested.stat().st_ino == replacement_inode
    assert stat.S_IMODE(nested.stat().st_mode) == 0o750
    assert (nested / "payload.txt").read_text(encoding="utf-8") == "replacement\n"
    assert stat.S_IMODE((nested / "payload.txt").stat().st_mode) == 0o640
    assert outside.read_text(encoding="utf-8") == "outside\n"
    assert stat.S_IMODE(outside.stat().st_mode) == 0o644


def test_hardlink_race_during_descriptor_mutation_restores_outside_alias_mode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    environment = tmp_path / "environment"
    environment.mkdir(mode=0o700)
    internal = environment / "payload.txt"
    internal.write_text("internal\n", encoding="utf-8")
    internal.chmod(0o644)
    internal_inode = internal.stat().st_ino
    outside_alias = tmp_path / "outside-alias.txt"
    original_fchmod = prepare_environment.os.fchmod
    linked = False

    def link_outward_before_fchmod(descriptor: int, mode: int) -> None:
        nonlocal linked
        if not linked and os.fstat(descriptor).st_ino == internal_inode:
            os.link(internal, outside_alias)
            linked = True
        original_fchmod(descriptor, mode)

    monkeypatch.setattr(prepare_environment.os, "fchmod", link_outward_before_fchmod)
    monkeypatch.setattr(
        prepare_environment.os,
        "chmod",
        lambda *_args, **_kwargs: pytest.fail("pathname chmod is prohibited"),
    )

    with pytest.raises(
        prepare_environment.EnvironmentSafetyError,
        match="changed during validation",
    ):
        prepare_environment.prepare_environment(environment)

    assert linked
    assert outside_alias.stat().st_ino == internal_inode
    assert outside_alias.read_text(encoding="utf-8") == "internal\n"
    assert stat.S_IMODE(outside_alias.stat().st_mode) == 0o644


def test_legitimate_uv_interpreter_symlink_chain_is_valid_and_idempotent(tmp_path: Path) -> None:
    environment = tmp_path / "environment"
    binary = environment / "bin"
    binary.mkdir(parents=True)
    (environment / "lib").mkdir()
    (environment / "lib64").symlink_to("lib", target_is_directory=True)
    interpreter = tmp_path / "python3.13"
    interpreter.write_text("synthetic executable\n", encoding="utf-8")
    interpreter.chmod(0o700)
    (binary / "python").symlink_to(interpreter)
    (binary / "python3").symlink_to("python")
    (binary / "python3.13").symlink_to("python")

    assert prepare_environment.prepare_environment(environment, trusted_python=interpreter) == 7
    assert prepare_environment.prepare_environment(environment, trusted_python=interpreter) == 7
    assert (binary / "python").resolve() == interpreter.resolve()


@pytest.mark.parametrize("target_kind", ["absolute", "wrong-relative", "missing"])
def test_lib64_symlink_must_resolve_to_exact_in_root_lib(
    tmp_path: Path,
    target_kind: str,
) -> None:
    environment = tmp_path / "environment"
    environment.mkdir()
    library = environment / "lib"
    library.mkdir()
    outside = tmp_path / "outside-lib"
    outside.mkdir()
    if target_kind == "absolute":
        target: Path | str = outside
    elif target_kind == "wrong-relative":
        target = "../outside-lib"
    else:
        target = "missing"
    (environment / "lib64").symlink_to(target, target_is_directory=True)

    with pytest.raises(
        prepare_environment.EnvironmentSafetyError,
        match="lib64 symbolic link",
    ):
        prepare_environment.prepare_environment(environment)


@pytest.mark.parametrize(
    "name",
    ["python2", "python3.10", "python3.15", "python3.999", "python3.13t", "activate"],
)
def test_unreviewed_bin_symlink_names_are_rejected(tmp_path: Path, name: str) -> None:
    environment = tmp_path / "environment"
    binary = environment / "bin"
    binary.mkdir(parents=True)
    target = tmp_path / "executable"
    target.write_text("synthetic\n", encoding="utf-8")
    target.chmod(0o700)
    (binary / name).symlink_to(target)

    with pytest.raises(
        prepare_environment.EnvironmentSafetyError,
        match="prohibited symbolic link",
    ):
        prepare_environment.prepare_environment(environment)


@pytest.mark.parametrize(
    "name",
    ["python", "python3", "python3.11", "python3.12", "python3.13", "python3.14"],
)
def test_supported_interpreter_link_names_are_exact(name: str) -> None:
    assert prepare_environment.INTERPRETER_LINK.fullmatch(name)


def test_interpreter_symlink_target_must_exist_and_be_executable(tmp_path: Path) -> None:
    environment = tmp_path / "environment"
    binary = environment / "bin"
    binary.mkdir(parents=True)
    missing = binary / "python"
    missing.symlink_to(tmp_path / "missing")
    with pytest.raises(
        prepare_environment.EnvironmentSafetyError,
        match="invalid interpreter symbolic link",
    ):
        prepare_environment.prepare_environment(environment)

    missing.unlink()
    nonexecutable = tmp_path / "nonexecutable"
    nonexecutable.write_text("synthetic\n", encoding="utf-8")
    nonexecutable.chmod(0o600)
    missing.symlink_to(nonexecutable)
    with pytest.raises(
        prepare_environment.EnvironmentSafetyError,
        match="target is not executable",
    ):
        prepare_environment.prepare_environment(environment)


@pytest.mark.parametrize("entry_kind", ["symlink", "regular"])
def test_executable_python_entry_must_match_explicit_trusted_interpreter(
    tmp_path: Path,
    entry_kind: str,
) -> None:
    environment = tmp_path / "environment"
    binary = environment / "bin"
    binary.mkdir(parents=True)
    untrusted = tmp_path / "untrusted-python"
    untrusted.write_text("synthetic executable\n", encoding="utf-8")
    untrusted.chmod(0o700)
    candidate = binary / "python"
    if entry_kind == "symlink":
        candidate.symlink_to(untrusted)
    else:
        candidate.write_bytes(untrusted.read_bytes())
        candidate.chmod(0o700)

    with pytest.raises(
        prepare_environment.EnvironmentSafetyError,
        match=r"untrusted executable code|untrusted interpreter executable",
    ):
        prepare_environment.prepare_environment(
            environment,
            trusted_python=Path(sys.executable),
        )


def test_changed_entry_and_cli_failure_are_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    environment = tmp_path / "environment"
    environment.mkdir()
    monkeypatch.setattr(
        prepare_environment,
        "prepare_environment",
        lambda _path, **_kwargs: (_ for _ in ()).throw(
            prepare_environment.EnvironmentSafetyError("unsafe synthetic environment")
        ),
    )
    with pytest.raises(SystemExit) as caught:
        prepare_environment.main([str(environment)])
    assert caught.value.code == 1
    assert "unsafe synthetic environment" in capsys.readouterr().err


def test_environment_os_errors_are_normalized_and_cli_success_honors_quiet(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    environment = tmp_path / "environment"
    environment.mkdir()

    original_open = prepare_environment.os.open

    def unavailable(*_args: object, **_kwargs: object) -> int:
        raise OSError("synthetic local detail")

    monkeypatch.setattr(prepare_environment.os, "open", unavailable)
    with pytest.raises(
        prepare_environment.EnvironmentSafetyError,
        match="could not be validated safely",
    ):
        prepare_environment.prepare_environment(environment)
    monkeypatch.setattr(prepare_environment.os, "open", original_open)

    monkeypatch.setattr(prepare_environment, "prepare_environment", lambda *_args, **_kwargs: 3)
    assert prepare_environment.main([str(environment)]) == 0
    assert "3 existing entry" in capsys.readouterr().out
    assert prepare_environment.main([str(environment), "--quiet"]) == 0
    assert capsys.readouterr().out == ""


def _fake_uv(path: Path, sync_marker: Path | None = None) -> Path:
    path.write_text(
        "\n".join(
            (
                f"#!{sys.executable}",
                "import os",
                "import pathlib",
                "import sys",
                "if sys.argv[1:] == ['--version']:",
                "    print('uv 0.11.29')",
                "    raise SystemExit(0)",
                "arguments = sys.argv[1:]",
                "if 'sync' not in arguments:",
                "    raise SystemExit('expected sync command')",
                "arguments = arguments[arguments.index('sync'):]",
                "if '--link-mode' not in arguments or "
                "arguments[arguments.index('--link-mode') + 1] != 'copy':",
                "    raise SystemExit('expected --link-mode copy')",
                "if '--python' not in arguments:",
                "    raise SystemExit('expected --python')",
                "trusted_python = pathlib.Path(arguments[arguments.index('--python') + 1])",
                "if not trusted_python.samefile(pathlib.Path(sys.executable)):",
                "    raise SystemExit('expected the trusted bootstrap interpreter')",
                f"sync_marker = {None if sync_marker is None else os.fspath(sync_marker)!r}",
                "root = pathlib.Path.cwd() / '.venv'",
                "if not root.is_dir() or root.is_symlink():",
                "    raise SystemExit('expected precreated environment root')",
                "if sync_marker:",
                "    pathlib.Path(sync_marker).write_text('sync ran', encoding='utf-8')",
                "(root / 'bin').mkdir(parents=True, exist_ok=True, mode=0o777)",
                "for relative, mode in (('.lock', 0o666), ('pyvenv.cfg', 0o666), "
                "('bin/tool', 0o777)):",
                "    target = root / relative",
                "    if not target.exists():",
                "        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)",
                "        os.close(descriptor)",
                "os.chmod(root / '.lock', 0o666)",
                "",
            )
        ),
        encoding="utf-8",
    )
    path.chmod(0o700)
    return path


def _bootstrap_repository(tmp_path: Path) -> Path:
    source = Path(__file__).resolve().parents[2]
    repository = tmp_path / "repository"
    (repository / "scripts").mkdir(parents=True)
    for relative in (
        "setup.sh",
        "pyproject.toml",
        "uv.lock",
        "scripts/prepare_environment.py",
        "scripts/run_uv.py",
    ):
        destination = repository / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source / relative, destination)
    return repository


def test_setup_under_hostile_umask_is_restrictive_and_idempotent(tmp_path: Path) -> None:
    repository = _bootstrap_repository(tmp_path)
    uv = _fake_uv(tmp_path / "uv")
    shell_poison = tmp_path / "shell-environment"
    shell_poison.write_text("exit 97\n", encoding="utf-8")
    environment = os.environ.copy()
    environment["PATH"] = os.pathsep.join(
        (os.fspath(Path(sys.executable).resolve().parent), environment.get("PATH", ""))
    )
    environment["MILHOUSE_UV"] = os.fspath(uv)
    environment["BASH_ENV"] = os.fspath(shell_poison)
    environment["ENV"] = os.fspath(shell_poison)

    for _ in range(2):
        completed = subprocess.run(
            ["/bin/sh", "-c", "umask 000; ./setup.sh"],
            cwd=repository,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert completed.returncode == 0, completed.stderr

    created = repository / ".venv"
    for candidate in (created, *created.rglob("*")):
        if not candidate.is_symlink():
            assert stat.S_IMODE(candidate.stat().st_mode) & 0o077 == 0


def test_setup_rejects_existing_directory_symlink_before_sync_and_preserves_outside_state(
    tmp_path: Path,
) -> None:
    repository = _bootstrap_repository(tmp_path)

    library = repository / ".venv" / "lib"
    library.mkdir(parents=True, mode=0o700)
    outside = tmp_path / "outside"
    outside.mkdir()
    sentinel = outside / "sentinel.txt"
    sentinel.write_text("unchanged\n", encoding="utf-8")
    inventory = outside / "inventory.json"
    inventory.write_text('{"state": "unchanged"}\n', encoding="utf-8")
    (library / "site-packages").symlink_to(outside, target_is_directory=True)

    sync_marker = tmp_path / "sync-marker"
    uv = _fake_uv(tmp_path / "uv", sync_marker)
    environment = os.environ.copy()
    environment["PATH"] = os.pathsep.join(
        (os.fspath(Path(sys.executable).resolve().parent), environment.get("PATH", ""))
    )
    environment["MILHOUSE_UV"] = os.fspath(uv)

    completed = subprocess.run(
        ["./setup.sh"],
        cwd=repository,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert completed.returncode != 0
    assert "prohibited symbolic link" in completed.stderr
    assert not sync_marker.exists()
    assert sentinel.read_text(encoding="utf-8") == "unchanged\n"
    assert inventory.read_text(encoding="utf-8") == '{"state": "unchanged"}\n'


@pytest.mark.parametrize(
    ("poison", "expected_success"),
    [("shellopts", True), ("function", False), ("combined", False)],
)
def test_setup_sanitizes_shell_options_and_rejects_exported_functions(
    tmp_path: Path,
    poison: str,
    expected_success: bool,
) -> None:
    repository = _bootstrap_repository(tmp_path)
    sync_marker = tmp_path / "sync-marker"
    poison_marker = tmp_path / "poison-ran"
    uv = _fake_uv(tmp_path / "uv", sync_marker)
    shell_poison = tmp_path / "shell-environment"
    shell_poison.write_text("exit 97\n", encoding="utf-8")
    environment = {
        name: value for name, value in os.environ.items() if not name.startswith("BASH_FUNC_")
    }
    environment["PATH"] = os.pathsep.join(
        (os.fspath(Path(sys.executable).resolve().parent), environment.get("PATH", ""))
    )
    environment["MILHOUSE_UV"] = os.fspath(uv)
    environment["MILHOUSE_POISON_MARKER"] = os.fspath(poison_marker)
    if poison in {"shellopts", "combined"}:
        environment["SHELLOPTS"] = "noexec"
    if poison in {"function", "combined"}:
        environment["BASH_FUNC_python3%%"] = (
            '() { /usr/bin/touch "$MILHOUSE_POISON_MARKER"; /usr/bin/true; }'
        )
    if poison == "combined":
        environment["BASH_ENV"] = os.fspath(shell_poison)
        environment["ENV"] = os.fspath(shell_poison)
        environment["BASHOPTS"] = "extdebug"

    completed = subprocess.run(
        ["./setup.sh"],
        cwd=repository,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert not poison_marker.exists()
    if expected_success or completed.returncode == 0:
        assert completed.returncode == 0, completed.stderr
        assert sync_marker.read_text(encoding="utf-8") == "sync ran"
    else:
        assert completed.returncode != 0
        assert "exported shell functions are prohibited" in completed.stderr
        assert not sync_marker.exists()


def test_explicit_bash_preserves_exported_function_for_setup_rejection(tmp_path: Path) -> None:
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("Bash is unavailable")
    repository = _bootstrap_repository(tmp_path)
    sync_marker = tmp_path / "sync-marker"
    poison_marker = tmp_path / "poison-ran"
    uv = _fake_uv(tmp_path / "uv", sync_marker)
    environment = {
        name: value for name, value in os.environ.items() if not name.startswith("BASH_FUNC_")
    }
    environment["PATH"] = os.pathsep.join(
        (os.fspath(Path(sys.executable).resolve().parent), environment.get("PATH", ""))
    )
    environment["MILHOUSE_UV"] = os.fspath(uv)
    environment["MILHOUSE_POISON_MARKER"] = os.fspath(poison_marker)
    environment["BASH_FUNC_python3%%"] = (
        '() { /usr/bin/touch "$MILHOUSE_POISON_MARKER"; /usr/bin/true; }'
    )

    completed = subprocess.run(
        [bash, "./setup.sh"],
        cwd=repository,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert completed.returncode != 0
    assert "exported shell functions are prohibited" in completed.stderr
    assert not poison_marker.exists()
    assert not sync_marker.exists()
