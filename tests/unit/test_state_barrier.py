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

_TRY_BARRIER = r"""
import sys
from milhouse.state import GlobalCommitBarrier, StateError

lock_path, mode = sys.argv[1:3]
barrier = GlobalCommitBarrier(lock_path)
context = barrier.shared(blocking=False) if mode == "shared" else barrier.exclusive(blocking=False)
try:
    with context:
        print("held")
except StateError as error:
    print(error.code)
"""

_TRY_RAW = r"""
import fcntl, os, sys

lock_path, mode = sys.argv[1:3]
descriptor = os.open(lock_path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
operation = fcntl.LOCK_SH if mode == "shared" else fcntl.LOCK_EX
try:
    try:
        fcntl.flock(descriptor, operation | fcntl.LOCK_NB)
    except BlockingIOError:
        print("busy")
    else:
        print("held")
        fcntl.flock(descriptor, fcntl.LOCK_UN)
finally:
    os.close(descriptor)
"""


def _control_dir(tmp_path: Path) -> Path:
    directory = tmp_path / "control"
    directory.mkdir(mode=0o700)
    os.chmod(directory, 0o700)
    return directory


def _lock_path(tmp_path: Path) -> Path:
    return _control_dir(tmp_path) / "commit.lock"


def test_barrier_binding_requires_exact_initialized_main_and_gate_paths(tmp_path: Path) -> None:
    lock = _lock_path(tmp_path)
    gate = lock.with_name(lock.name + ".gate")
    assert barrier_module._is_bound_barrier(GlobalCommitBarrier(lock), lock)

    class DerivedBarrier(GlobalCommitBarrier):
        pass

    assert not barrier_module._is_bound_barrier(DerivedBarrier(lock), lock)
    assert not barrier_module._is_bound_barrier(object.__new__(GlobalCommitBarrier), lock)

    missing_gate = object.__new__(GlobalCommitBarrier)
    object.__setattr__(missing_gate, "_path", lock)
    assert not barrier_module._is_bound_barrier(missing_gate, lock)

    wrong_main_type = GlobalCommitBarrier(lock)
    object.__setattr__(wrong_main_type, "_path", str(lock))
    assert not barrier_module._is_bound_barrier(wrong_main_type, lock)

    wrong_gate_type = GlobalCommitBarrier(lock)
    object.__setattr__(wrong_gate_type, "_gate_path", str(gate))
    assert not barrier_module._is_bound_barrier(wrong_gate_type, lock)

    wrong_main = GlobalCommitBarrier(lock)
    object.__setattr__(wrong_main, "_path", tmp_path / "other.lock")
    assert not barrier_module._is_bound_barrier(wrong_main, lock)

    wrong_gate = GlobalCommitBarrier(lock)
    object.__setattr__(wrong_gate, "_gate_path", tmp_path / "other.lock.gate")
    assert not barrier_module._is_bound_barrier(wrong_gate, lock)


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


def _run_probe(script: str, lock: Path, mode: str) -> str:
    completed = subprocess.run(
        [sys.executable, "-c", script, str(lock), mode],
        check=False,
        capture_output=True,
        env=dict(os.environ),
        text=True,
        timeout=10,
    )
    assert completed.returncode == 0, completed.stderr
    return completed.stdout.strip()


def _try_barrier(lock: Path, mode: str) -> str:
    return _run_probe(_TRY_BARRIER, lock, mode)


def _try_raw_lock(lock: Path, mode: str) -> str:
    return _run_probe(_TRY_RAW, lock, mode)


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


def test_exclusive_then_shared_hands_recovery_to_a_writer_without_a_barrier_gap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lock = _lock_path(tmp_path)
    barrier = GlobalCommitBarrier(lock)
    real_acquire = barrier_module._acquire
    acquisition_count = 0
    handoff_observations: list[str] = []

    def _observe_handoff(descriptor: int, operation: int, *, blocking: bool) -> None:
        nonlocal acquisition_count
        acquisition_count += 1
        if acquisition_count == 3:
            assert operation == barrier_module.fcntl.LOCK_SH
            assert blocking is True
            # A cooperating writer cannot pass the exclusive gate immediately before or after the
            # real main-lock conversion. The gate is released only after the conversion returns.
            handoff_observations.append(_try_barrier(lock, "shared"))
            real_acquire(descriptor, operation, blocking=blocking)
            handoff_observations.append(_try_barrier(lock, "shared"))
            return
        real_acquire(descriptor, operation, blocking=blocking)

    with monkeypatch.context() as scoped:
        scoped.setattr(barrier_module, "_acquire", _observe_handoff)
        with barrier.exclusive_then_shared(blocking=False) as transition:
            # Recovery owns the main lock exclusively and the turnstile excludes cooperating
            # writers before the phase transition.
            assert _try_raw_lock(lock, "shared") == "busy"
            assert _try_barrier(lock, "shared") == "MH_STATE_BARRIER_BUSY"

            transition()

            assert handoff_observations == [
                "MH_STATE_BARRIER_BUSY",
                "MH_STATE_BARRIER_BUSY",
            ]
            # The durable-writer phase holds the main side shared. Raw and cooperating shared
            # holders coexist, while a proper maintenance exclusive remains blocked.
            assert _try_raw_lock(lock, "shared") == "held"
            assert _try_barrier(lock, "shared") == "held"
            assert _try_barrier(lock, "exclusive") == "MH_STATE_BARRIER_BUSY"

    assert _try_barrier(lock, "exclusive") == "held"


def test_exclusive_then_shared_transition_callback_is_single_use_and_lexically_scoped(
    tmp_path: Path,
) -> None:
    barrier = GlobalCommitBarrier(_lock_path(tmp_path))

    with barrier.exclusive_then_shared() as transition:
        transition()
        with pytest.raises(StateError) as captured:
            transition()
        assert captured.value.code == "MH_STATE_BARRIER"

    with pytest.raises(StateError) as captured:
        transition()
    assert captured.value.code == "MH_STATE_BARRIER"

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


@pytest.mark.parametrize("side", ["shared", "exclusive", "exclusive_then_shared"])
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


@pytest.mark.parametrize("failed_acquisition", [1, 2, 3])
def test_exclusive_then_shared_failure_releases_locks_and_closes_descriptors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failed_acquisition: int
) -> None:
    barrier = GlobalCommitBarrier(_lock_path(tmp_path))
    real_descriptor = barrier_module._secure_lock_descriptor
    real_flock = barrier_module.fcntl.flock
    opened_descriptors: list[int] = []
    acquisition_count = 0

    def _track_descriptor(path: Path) -> int:
        descriptor = real_descriptor(path)
        opened_descriptors.append(descriptor)
        return descriptor

    def _fail_selected_flock(descriptor: int, operation: int) -> None:
        nonlocal acquisition_count
        if operation & (barrier_module.fcntl.LOCK_SH | barrier_module.fcntl.LOCK_EX):
            acquisition_count += 1
            if acquisition_count == failed_acquisition:
                raise OSError("planted barrier acquisition failure")
        real_flock(descriptor, operation)

    with monkeypatch.context() as scoped:
        scoped.setattr(barrier_module, "_secure_lock_descriptor", _track_descriptor)
        scoped.setattr(barrier_module.fcntl, "flock", _fail_selected_flock)
        with pytest.raises(StateError) as captured:
            with barrier.exclusive_then_shared() as transition:
                transition()
        assert captured.value.code == "MH_STATE_BARRIER"

    assert len(opened_descriptors) == 2
    for descriptor in opened_descriptors:
        with pytest.raises(OSError):
            os.fstat(descriptor)

    # A real cross-process acquisition proves a failed gate, main, or transition acquisition left
    # neither underlying lock held after the context unwound.
    assert _try_barrier(barrier.path, "exclusive") == "held"


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
