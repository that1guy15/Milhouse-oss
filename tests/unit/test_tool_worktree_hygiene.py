from __future__ import annotations

import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import check_worktree_hygiene as hygiene

HEAD = "a" * 40
ORIGIN = "b" * 40


def worktree_record(path: Path, *, head: str = HEAD, branch: str | None = "main") -> bytes:
    fields = [f"worktree {path}".encode(), f"HEAD {head}".encode()]
    fields.append(f"branch refs/heads/{branch}".encode() if branch else b"detached")
    return b"\0".join(fields) + b"\0\0"


def snapshot(
    path: Path,
    *,
    head: str = HEAD,
    branch: str | None = "refs/heads/main",
    prunable: bool = False,
    dirty: int | None = 0,
) -> hygiene.Worktree:
    return hygiene.Worktree(path, head, branch, prunable, dirty)


def test_parse_worktrees_preserves_branch_detached_and_prunable_state(tmp_path: Path) -> None:
    primary = tmp_path / "primary"
    task = tmp_path / "task"
    raw = worktree_record(primary) + (
        f"worktree {task}\0HEAD {ORIGIN}\0detached\0prunable metadata missing\0\0".encode()
    )

    parsed = hygiene.parse_worktrees(raw)

    assert parsed == (
        hygiene.Worktree(primary, HEAD, "refs/heads/main"),
        hygiene.Worktree(task, ORIGIN, None, prunable=True),
    )


@pytest.mark.parametrize(
    "raw, message",
    (
        (b"", "malformed"),
        (b"worktree /repo\0HEAD " + HEAD.encode(), "malformed"),
        (b"HEAD " + HEAD.encode() + b"\0detached\0\0", "omitted required"),
        (b"worktree /repo\0HEAD invalid\0detached\0\0", "invalid worktree head"),
        (b"worktree /repo\0HEAD " + HEAD.encode() + b"\0\0", "omitted the worktree branch"),
        (
            b"worktree /repo\0worktree /other\0HEAD " + HEAD.encode() + b"\0detached\0\0",
            "malformed",
        ),
        (
            b"worktree /repo\0HEAD " + HEAD.encode() + b"\0branch \xff\0\0",
            "non-UTF-8",
        ),
    ),
)
def test_parse_worktrees_rejects_malformed_metadata(raw: bytes, message: str) -> None:
    with pytest.raises(hygiene.HygieneError, match=message):
        hygiene.parse_worktrees(raw)


def test_parse_worktrees_rejects_duplicate_paths(tmp_path: Path) -> None:
    raw = worktree_record(tmp_path) + worktree_record(tmp_path, branch=None)

    with pytest.raises(hygiene.HygieneError, match="duplicate"):
        hygiene.parse_worktrees(raw)


@pytest.mark.parametrize(
    "raw, expected",
    (
        (b"", 0),
        (b" M file\0?? new\0", 2),
        (b"R  new\0old\0 M other\0", 2),
        (b" C copy\0source\0", 1),
    ),
)
def test_count_status_entries(raw: bytes, expected: int) -> None:
    assert hygiene.count_status_entries(raw) == expected


@pytest.mark.parametrize(
    "raw, message",
    (
        (b" M file", "malformed"),
        (b"invalid\0", "malformed"),
        (b"R  new\0", "omitted"),
    ),
)
def test_count_status_entries_rejects_malformed_status(raw: bytes, message: str) -> None:
    with pytest.raises(hygiene.HygieneError, match=message):
        hygiene.count_status_entries(raw)


def test_clean_primary_and_task_pass(tmp_path: Path) -> None:
    primary = tmp_path / "primary"
    task = tmp_path / "task"
    primary.mkdir()
    task.mkdir()
    worktrees = (
        snapshot(primary),
        snapshot(task, branch="refs/heads/codex/task"),
    )

    assert hygiene.audit_worktrees(worktrees, HEAD, maximum=3) == ()


def test_audit_reports_every_blocking_primary_and_registry_state(tmp_path: Path) -> None:
    primary = tmp_path / "primary"
    first = tmp_path / "first"
    second = tmp_path / "second"
    primary.mkdir()
    first.mkdir()
    worktrees = (
        snapshot(primary, head=HEAD, branch="refs/heads/topic", dirty=2),
        snapshot(first, branch=None, dirty=1),
        snapshot(second, branch="refs/heads/claude/task", prunable=True, dirty=None),
    )

    findings = hygiene.audit_worktrees(worktrees, ORIGIN, maximum=2)

    assert [(item.severity, item.label, item.message) for item in findings] == [
        ("ERROR", "primary", "state=blocked; branch is not main"),
        ("ERROR", "primary", "state=blocked; main is stale against origin/main"),
        ("ERROR", "primary", "state=blocked; dirty=2; primary must be clean-main"),
        ("ERROR", "registry", "registered=3 exceeds maximum=2"),
        (
            "WARNING",
            "task-1 detached",
            "dirty=1; classify as active, recovery-stashed, or blocked",
        ),
        ("WARNING", "task-1 detached", "state=blocked; task worktree is detached"),
        (
            "ERROR",
            "task-2 branch=claude/task",
            "registration is missing or prunable",
        ),
    ]


def test_audit_reports_unreadable_status_and_missing_expectation(tmp_path: Path) -> None:
    primary = tmp_path / "primary"
    task = tmp_path / "task"
    missing = tmp_path / "missing"
    primary.mkdir()
    task.mkdir()
    worktrees = (
        snapshot(primary, dirty=None),
        snapshot(task, branch="refs/heads/codex/task", dirty=None),
    )

    findings = hygiene.audit_worktrees(
        worktrees,
        HEAD,
        maximum=3,
        expected=(
            hygiene.ExpectedWorktree("codex", task),
            hygiene.ExpectedWorktree("claude", missing),
        ),
    )

    assert findings == (
        hygiene.Finding("ERROR", "primary", "state=blocked; status could not be verified"),
        hygiene.Finding("ERROR", "claude", "expected worktree registration is missing"),
        hygiene.Finding(
            "ERROR",
            "task-1 branch=codex/task",
            "state=blocked; status could not be verified",
        ),
    )


def test_collect_worktrees_adds_status_counts(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    primary = tmp_path / "primary"
    task = tmp_path / "task"
    primary.mkdir()
    task.mkdir()
    metadata = worktree_record(primary) + worktree_record(task, branch="codex/task")

    def fake_git(repository: Path, arguments: list[str], *, timeout: int = 30) -> bytes:
        assert timeout == 30
        if arguments[:2] == ["worktree", "list"]:
            return metadata
        if arguments[0] == "rev-parse":
            return f"{HEAD}\n".encode()
        if repository == primary:
            return b""
        if repository == task:
            return b" M changed\0?? new\0"
        raise AssertionError(arguments)

    monkeypatch.setattr(hygiene, "_git", fake_git)

    worktrees, origin = hygiene.collect_worktrees(tmp_path)

    assert origin == HEAD
    assert [item.dirty_count for item in worktrees] == [0, 2]


def test_collect_worktrees_marks_failed_or_prunable_status_unknown(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    primary = tmp_path / "primary"
    primary.mkdir()
    metadata = worktree_record(primary).replace(b"\0\0", b"\0prunable gone\0\0")

    def fake_git(repository: Path, arguments: list[str], *, timeout: int = 30) -> bytes:
        if arguments[:2] == ["worktree", "list"]:
            return metadata
        if arguments[0] == "rev-parse":
            return f"{HEAD}\n".encode()
        raise hygiene.HygieneError("failed")

    monkeypatch.setattr(hygiene, "_git", fake_git)

    worktrees, _ = hygiene.collect_worktrees(tmp_path)

    assert worktrees[0].dirty_count is None


def test_collect_worktrees_rejects_invalid_origin_head(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def fake_git(repository: Path, arguments: list[str], *, timeout: int = 30) -> bytes:
        if arguments[:2] == ["worktree", "list"]:
            return worktree_record(tmp_path)
        return b"invalid\n"

    monkeypatch.setattr(hygiene, "_git", fake_git)

    with pytest.raises(hygiene.HygieneError, match="invalid origin/main"):
        hygiene.collect_worktrees(tmp_path)


def test_git_sanitizes_environment_and_rejects_failures(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    captured: dict[str, object] = {}

    def run(command: list[str], **kwargs: object) -> SimpleNamespace:
        captured["command"] = command
        captured.update(kwargs)
        return SimpleNamespace(returncode=0, stdout=b"result")

    monkeypatch.setattr(subprocess, "run", run)

    assert hygiene._git(tmp_path, ["status"]) == b"result"
    assert captured["command"][-1] == "status"  # type: ignore[index]
    environment = captured["env"]
    assert isinstance(environment, dict)
    assert environment["GIT_OPTIONAL_LOCKS"] == "0"
    assert environment["GIT_CONFIG_NOSYSTEM"] == "1"

    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=1, stdout=b"", stderr=b"private"),
    )
    with pytest.raises(hygiene.HygieneError, match="could not complete"):
        hygiene._git(tmp_path, ["status"])

    def timeout(*args: object, **kwargs: object) -> SimpleNamespace:
        raise subprocess.TimeoutExpired("git", 30)

    monkeypatch.setattr(subprocess, "run", timeout)
    with pytest.raises(hygiene.HygieneError, match="could not complete"):
        hygiene._git(tmp_path, ["status"])


@pytest.mark.parametrize("value", ("missing", "UPPER=/tmp/task", "label=", "=path"))
def test_parse_expected_rejects_unsafe_labels(value: str) -> None:
    with pytest.raises(Exception, match="LABEL=PATH"):
        hygiene.parse_expected(value)


def test_main_reports_warnings_and_strict_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    primary = tmp_path / "primary"
    task = tmp_path / "task"
    primary.mkdir()
    task.mkdir()
    worktrees = (
        snapshot(primary),
        snapshot(task, branch="refs/heads/codex/task", dirty=1),
    )
    monkeypatch.setattr(hygiene, "collect_worktrees", lambda repository: (worktrees, HEAD))

    assert hygiene.main([]) == 0
    output = capsys.readouterr().out
    assert "WARNING task-1 branch=codex/task" in output
    assert "PASS state=clean-main registered=2 warnings=1" in output

    assert hygiene.main(["--strict"]) == 1
    output = capsys.readouterr().out
    assert "ERROR task-1 branch=codex/task" in output
    assert "FAIL errors=1 warnings=0 registered=2" in output


def test_main_rejects_nonpositive_limit_and_collection_error(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as nonpositive:
        hygiene.main(["--max-worktrees", "0"])
    assert nonpositive.value.code == 1
    assert "must be positive" in capsys.readouterr().err

    def fail_collection(repository: Path) -> tuple[tuple[hygiene.Worktree, ...], str]:
        raise hygiene.HygieneError("audit unavailable")

    monkeypatch.setattr(hygiene, "collect_worktrees", fail_collection)
    with pytest.raises(SystemExit) as unavailable:
        hygiene.main([])
    assert unavailable.value.code == 1
    assert "audit unavailable" in capsys.readouterr().err
