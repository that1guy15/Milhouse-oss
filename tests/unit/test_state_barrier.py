from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from milhouse.config.filesystem import SecureFileError, SecureFileErrorKind
from milhouse.state import GlobalCommitBarrier, StateError
from milhouse.state import barrier as barrier_module

_HOLD = r"""
import sys, time
from pathlib import Path
from milhouse.state import GlobalCommitBarrier

lock_path, mode, ready, release = sys.argv[1:5]
barrier = GlobalCommitBarrier(lock_path)
context = barrier.shared() if mode == "shared" else barrier.exclusive()
with context:
    Path(ready).write_text("held")
    deadline = time.monotonic() + 25.0
    while not Path(release).exists() and time.monotonic() < deadline:
        time.sleep(0.01)
"""


def _control_dir(tmp_path: Path) -> Path:
    directory = tmp_path / "control"
    directory.mkdir(mode=0o700)
    os.chmod(directory, 0o700)
    return directory


def _lock_path(tmp_path: Path) -> Path:
    return _control_dir(tmp_path) / "commit.lock"


def _spawn_holder(lock: Path, mode: str, ready: Path, release: Path) -> subprocess.Popen[bytes]:
    proc = subprocess.Popen(
        [sys.executable, "-c", _HOLD, str(lock), mode, str(ready), str(release)],
        env=dict(os.environ),
    )
    deadline = time.monotonic() + 25.0
    while not ready.exists() and time.monotonic() < deadline:
        if proc.poll() is not None:
            raise AssertionError(f"{mode} holder child exited before acquiring")
        time.sleep(0.01)
    assert ready.exists(), f"{mode} holder child did not acquire in time"
    return proc


# --- basic readers-writer semantics -------------------------------------------------------------


def test_two_shared_holders_coexist(tmp_path: Path) -> None:
    barrier = GlobalCommitBarrier(_lock_path(tmp_path))
    with barrier.shared(blocking=False):
        with barrier.shared(blocking=False):
            pass


def test_a_shared_holder_blocks_the_exclusive_side(tmp_path: Path) -> None:
    barrier = GlobalCommitBarrier(_lock_path(tmp_path))
    with barrier.shared():
        with pytest.raises(StateError) as captured:
            with barrier.exclusive(blocking=False):
                pass
        assert captured.value.code == "MH_STATE_BARRIER_BUSY"


def test_an_exclusive_holder_blocks_the_shared_side(tmp_path: Path) -> None:
    barrier = GlobalCommitBarrier(_lock_path(tmp_path))
    with barrier.exclusive():
        with pytest.raises(StateError) as captured:
            with barrier.shared(blocking=False):
                pass
        assert captured.value.code == "MH_STATE_BARRIER_BUSY"


def test_the_barrier_is_free_after_release(tmp_path: Path) -> None:
    barrier = GlobalCommitBarrier(_lock_path(tmp_path))
    with barrier.exclusive():
        pass
    with barrier.exclusive(blocking=False):
        pass


def test_cross_process_exclusion_and_recovery(tmp_path: Path) -> None:
    lock = _lock_path(tmp_path)
    ready = tmp_path / "ready"
    release = tmp_path / "release"
    holder = _spawn_holder(lock, "exclusive", ready, release)
    try:
        barrier = GlobalCommitBarrier(lock)
        with pytest.raises(StateError) as captured:
            with barrier.shared(blocking=False):
                pass
        assert captured.value.code == "MH_STATE_BARRIER_BUSY"
    finally:
        release.write_text("go")
        assert holder.wait(timeout=25) == 0
    with barrier.shared(blocking=False):
        pass


def test_writer_preference_a_queued_exclusive_blocks_new_shared(tmp_path: Path) -> None:
    # A holds shared; B queues an exclusive (grabs the gate, blocks on the drained main lock); while
    # B is queued a new shared entrant is refused at the gate (the writer-preference turnstile).
    lock = _lock_path(tmp_path)
    ready_a, release_a = tmp_path / "ready_a", tmp_path / "release_a"
    ready_b, release_b = tmp_path / "ready_b", tmp_path / "release_b"
    holder_a = _spawn_holder(lock, "shared", ready_a, release_a)
    holder_b = subprocess.Popen(
        [sys.executable, "-c", _HOLD, str(lock), "exclusive", str(ready_b), str(release_b)],
        env=dict(os.environ),
    )
    try:
        barrier = GlobalCommitBarrier(lock)
        # Once B has taken the gate exclusively, a new non-blocking shared entrant is refused.
        deadline = time.monotonic() + 25.0
        blocked = False
        while time.monotonic() < deadline:
            try:
                with barrier.shared(blocking=False):
                    pass
            except StateError as error:
                assert error.code == "MH_STATE_BARRIER_BUSY"
                blocked = True
                break
            time.sleep(0.02)
        assert blocked, "a queued exclusive did not block a new shared entrant"
        assert not ready_b.exists(), "the exclusive acquired while a shared holder was still active"
    finally:
        release_a.write_text("go")
        release_b.write_text("go")
        assert holder_a.wait(timeout=25) == 0
        assert holder_b.wait(timeout=25) == 0


# --- secure lock-file validation (never truncate or trust a foreign inode) -----------------------


def test_a_hard_linked_lock_file_is_rejected_and_never_truncated(tmp_path: Path) -> None:
    directory = _control_dir(tmp_path)
    victim = directory / "important-control-state"
    victim.write_bytes(b"important-control-state")
    os.chmod(victim, 0o600)
    lock = directory / "commit.lock"
    os.link(victim, lock)  # a hard link, exactly what the review flagged

    barrier = GlobalCommitBarrier(lock)
    with pytest.raises(StateError) as captured:
        with barrier.exclusive(blocking=False):
            pass
    assert captured.value.code == "MH_STATE_BARRIER_UNSAFE"
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None
    # the foreign file must be byte-for-byte intact
    assert victim.read_bytes() == b"important-control-state"


def test_a_symlinked_lock_file_is_rejected(tmp_path: Path) -> None:
    directory = _control_dir(tmp_path)
    target = directory / "target"
    target.write_bytes(b"x")
    os.chmod(target, 0o600)
    lock = directory / "commit.lock"
    lock.symlink_to(target)
    with pytest.raises(StateError) as captured:
        with GlobalCommitBarrier(lock).shared(blocking=False):
            pass
    assert captured.value.code in {"MH_STATE_BARRIER", "MH_STATE_BARRIER_UNSAFE"}


def test_a_non_regular_lock_file_is_rejected(tmp_path: Path) -> None:
    directory = _control_dir(tmp_path)
    lock = directory / "commit.lock"
    os.mkfifo(lock, 0o600)
    with pytest.raises(StateError) as captured:
        with GlobalCommitBarrier(lock).shared(blocking=False):
            pass
    assert captured.value.code in {"MH_STATE_BARRIER", "MH_STATE_BARRIER_UNSAFE"}


def test_a_loose_mode_lock_file_is_rejected(tmp_path: Path) -> None:
    directory = _control_dir(tmp_path)
    lock = directory / "commit.lock"
    lock.write_bytes(b"x")
    os.chmod(lock, 0o666)
    with pytest.raises(StateError) as captured:
        with GlobalCommitBarrier(lock).shared(blocking=False):
            pass
    assert captured.value.code == "MH_STATE_BARRIER_UNSAFE"


def test_a_concurrent_lock_creator_is_retried(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lock = _lock_path(tmp_path)
    real_create = barrier_module.create_regular_file_no_follow

    def _win_race_then_report_existing(*args: object, **kwargs: object) -> None:
        real_create(*args, **kwargs)  # type: ignore[arg-type]
        raise SecureFileError(SecureFileErrorKind.ALREADY_EXISTS)

    monkeypatch.setattr(
        barrier_module, "create_regular_file_no_follow", _win_race_then_report_existing
    )
    with GlobalCommitBarrier(lock).exclusive(blocking=False):
        pass


def test_a_lock_creation_error_is_normalized(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _fail_create(*_args: object, **_kwargs: object) -> None:
        raise SecureFileError(SecureFileErrorKind.PERMISSION_FAILED)

    monkeypatch.setattr(barrier_module, "create_regular_file_no_follow", _fail_create)
    with pytest.raises(StateError) as captured:
        with GlobalCommitBarrier(_lock_path(tmp_path)).shared():
            pass
    assert captured.value.code == "MH_STATE_BARRIER"
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None


def test_a_lock_still_missing_after_creation_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _still_missing(*_args: object, **_kwargs: object) -> None:
        raise SecureFileError(SecureFileErrorKind.NOT_FOUND)

    def _pretend_create(*_args: object, **_kwargs: object) -> None:
        pass

    monkeypatch.setattr(barrier_module, "open_regular_file_no_follow", _still_missing)
    monkeypatch.setattr(barrier_module, "create_regular_file_no_follow", _pretend_create)
    with pytest.raises(StateError) as captured:
        with GlobalCommitBarrier(_lock_path(tmp_path)).exclusive():
            pass
    assert captured.value.code == "MH_STATE_BARRIER"


@pytest.mark.parametrize("side", ["shared", "exclusive"])
def test_a_gate_open_failure_closes_the_main_descriptor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, side: str
) -> None:
    lock = _lock_path(tmp_path)
    barrier = GlobalCommitBarrier(lock)
    real_open = barrier_module.open_regular_file_no_follow
    main_descriptors: list[int] = []

    def _fail_gate(path: Path, **kwargs: object):  # type: ignore[no-untyped-def]
        if Path(path).name.endswith(".gate"):
            raise SecureFileError(SecureFileErrorKind.PERMISSION_FAILED)
        opened = real_open(path, **kwargs)  # type: ignore[arg-type]
        main_descriptors.append(opened.descriptor)
        return opened

    monkeypatch.setattr(barrier_module, "open_regular_file_no_follow", _fail_gate)
    with pytest.raises(StateError) as captured:
        with getattr(barrier, side)():
            pass
    assert captured.value.code == "MH_STATE_BARRIER"
    assert len(main_descriptors) == 1
    with pytest.raises(OSError):
        os.fstat(main_descriptors[0])


def test_a_shared_main_acquisition_failure_releases_the_held_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    barrier = GlobalCommitBarrier(_lock_path(tmp_path))
    real_acquire = barrier_module._acquire
    calls = 0

    def _fail_second_acquire(descriptor: int, operation: int, *, blocking: bool) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise StateError("MH_STATE_BARRIER", "planted main-lock acquisition failure")
        real_acquire(descriptor, operation, blocking=blocking)

    with monkeypatch.context() as scoped:
        scoped.setattr(barrier_module, "_acquire", _fail_second_acquire)
        with pytest.raises(StateError) as captured:
            with barrier.shared():
                pass
        assert captured.value.code == "MH_STATE_BARRIER"

    # A fresh exclusive acquisition proves the shared path released its already-held gate.
    with barrier.exclusive(blocking=False):
        pass
