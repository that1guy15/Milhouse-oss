from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from milhouse.state import GlobalCommitBarrier, StateError

_CHILD = r"""
import sys, time
from pathlib import Path
from milhouse.state import GlobalCommitBarrier

lock_path, mode, ready, release = sys.argv[1:5]
barrier = GlobalCommitBarrier(lock_path)
context = barrier.shared() if mode == "shared" else barrier.exclusive()
with context:
    Path(ready).write_text("held")
    deadline = time.monotonic() + 20.0
    while not Path(release).exists() and time.monotonic() < deadline:
        time.sleep(0.01)
"""


def _lock_path(tmp_path: Path) -> Path:
    directory = tmp_path / "control"
    directory.mkdir(mode=0o700)
    os.chmod(directory, 0o700)
    return directory / "commit.lock"


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


def _spawn_holder(lock: Path, mode: str, ready: Path, release: Path) -> subprocess.Popen[bytes]:
    proc = subprocess.Popen(
        [sys.executable, "-c", _CHILD, str(lock), mode, str(ready), str(release)],
        env=dict(os.environ),
    )
    deadline = time.monotonic() + 20.0
    while not ready.exists() and time.monotonic() < deadline:
        if proc.poll() is not None:
            raise AssertionError("barrier holder child exited before acquiring")
        time.sleep(0.01)
    assert ready.exists(), "barrier holder child did not acquire in time"
    return proc


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
        assert holder.wait(timeout=20) == 0
    # once the cross-process exclusive holder is gone, the barrier is free again
    with barrier.shared(blocking=False):
        pass
