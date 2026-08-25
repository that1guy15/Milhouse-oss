#!/usr/bin/env python3
"""Report whether a local Milhouse checkout follows the worktree contract."""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import NoReturn

HEAD_PATTERN = re.compile(r"[0-9a-f]{40,64}\Z")
EXPECTED_PATTERN = re.compile(r"[a-z][a-z0-9-]{0,63}\Z")
MAIN_BRANCH = "refs/heads/main"


class HygieneError(ValueError):
    """Raised when local Git state cannot be audited safely."""


@dataclass(frozen=True)
class Worktree:
    """One parsed Git worktree registration."""

    path: Path
    head: str
    branch: str | None
    prunable: bool = False
    dirty_count: int | None = None


@dataclass(frozen=True)
class ExpectedWorktree:
    """One caller-named worktree registration expected to exist."""

    label: str
    path: Path


@dataclass(frozen=True)
class Finding:
    """One privacy-safe worktree audit result."""

    severity: str
    label: str
    message: str


def fail(message: str) -> NoReturn:
    """Exit without printing a machine-local path."""

    print(f"worktree-hygiene: {message}", file=sys.stderr)
    raise SystemExit(1)


def _decode(raw: bytes, field: str) -> str:
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HygieneError(f"Git returned a non-UTF-8 {field}") from exc


def parse_worktrees(raw: bytes) -> tuple[Worktree, ...]:
    """Parse ``git worktree list --porcelain -z`` output."""

    if not raw or not raw.endswith(b"\0\0"):
        raise HygieneError("Git returned malformed worktree metadata")
    worktrees: list[Worktree] = []
    for record in raw.split(b"\0\0"):
        if not record:
            continue
        fields: dict[bytes, bytes] = {}
        markers: set[bytes] = set()
        for item in record.split(b"\0"):
            key, separator, value = item.partition(b" ")
            if not key or key in fields or key in markers:
                raise HygieneError("Git returned malformed worktree metadata")
            if separator:
                fields[key] = value
            else:
                markers.add(key)
        try:
            raw_path = fields[b"worktree"]
            raw_head = fields[b"HEAD"]
        except KeyError as exc:
            raise HygieneError("Git omitted required worktree metadata") from exc
        head = _decode(raw_head, "worktree head")
        if not HEAD_PATTERN.fullmatch(head):
            raise HygieneError("Git returned an invalid worktree head")
        raw_branch = fields.get(b"branch")
        branch = _decode(raw_branch, "worktree branch") if raw_branch is not None else None
        if branch is None and b"detached" not in markers and b"bare" not in markers:
            raise HygieneError("Git omitted the worktree branch state")
        worktrees.append(
            Worktree(
                path=Path(os.fsdecode(raw_path)),
                head=head,
                branch=branch,
                prunable=b"prunable" in fields or b"prunable" in markers,
            )
        )
    if not worktrees:
        raise HygieneError("Git returned no worktree registrations")
    if len({os.path.normcase(os.path.realpath(item.path)) for item in worktrees}) != len(worktrees):
        raise HygieneError("Git returned duplicate worktree registrations")
    return tuple(worktrees)


def count_status_entries(raw: bytes) -> int:
    """Count entries in ``git status --porcelain=v1 -z`` output."""

    if not raw:
        return 0
    if not raw.endswith(b"\0"):
        raise HygieneError("Git returned malformed worktree status")
    entries = raw.split(b"\0")
    count = 0
    index = 0
    while index < len(entries) - 1:
        entry = entries[index]
        if len(entry) < 4 or entry[2:3] != b" ":
            raise HygieneError("Git returned malformed worktree status")
        status = entry[:2]
        count += 1
        index += 1
        if b"R" in status or b"C" in status:
            if index >= len(entries) - 1 or not entries[index]:
                raise HygieneError("Git omitted a renamed worktree path")
            index += 1
    return count


def _git(repository: Path, arguments: Sequence[str], *, timeout: int = 30) -> bytes:
    environment = os.environ.copy()
    environment.update(
        {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "LC_ALL": "C",
        }
    )
    try:
        completed = subprocess.run(
            [
                "git",
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.hooksPath=/dev/null",
                "-C",
                os.fspath(repository),
                *arguments,
            ],
            capture_output=True,
            check=False,
            env=environment,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise HygieneError("Git could not complete the worktree audit") from exc
    if completed.returncode != 0:
        raise HygieneError("Git could not complete the worktree audit")
    return completed.stdout


def collect_worktrees(repository: Path) -> tuple[tuple[Worktree, ...], str]:
    """Collect registration, status, and local protected-main state."""

    parsed = parse_worktrees(_git(repository, ["worktree", "list", "--porcelain", "-z"]))
    raw_origin = _git(repository, ["rev-parse", "--verify", "origin/main^{commit}"])
    origin_main = _decode(raw_origin, "origin/main head").strip()
    if not HEAD_PATTERN.fullmatch(origin_main):
        raise HygieneError("Git returned an invalid origin/main head")

    collected: list[Worktree] = []
    for item in parsed:
        dirty_count: int | None = None
        if item.path.is_dir() and not item.prunable:
            try:
                raw_status = _git(
                    item.path,
                    [
                        "status",
                        "--porcelain=v1",
                        "-z",
                        "--untracked-files=normal",
                        "--ignore-submodules=all",
                    ],
                )
                dirty_count = count_status_entries(raw_status)
            except HygieneError:
                dirty_count = None
        collected.append(
            Worktree(
                path=item.path,
                head=item.head,
                branch=item.branch,
                prunable=item.prunable,
                dirty_count=dirty_count,
            )
        )
    return tuple(collected), origin_main


def _normalized(path: Path) -> str:
    return os.path.normcase(os.path.realpath(path))


def _label(index: int, worktree: Worktree) -> str:
    if index == 0:
        return "primary"
    branch = worktree.branch
    if branch is not None and branch.startswith("refs/heads/"):
        return f"task-{index} branch={branch.removeprefix('refs/heads/')}"
    return f"task-{index} detached"


def audit_worktrees(
    worktrees: Sequence[Worktree],
    origin_main: str,
    *,
    maximum: int,
    expected: Sequence[ExpectedWorktree] = (),
) -> tuple[Finding, ...]:
    """Evaluate worktree state without exposing registered paths."""

    if not worktrees:
        raise HygieneError("no worktree registrations are available")
    findings: list[Finding] = []
    primary = worktrees[0]
    if primary.branch != MAIN_BRANCH:
        findings.append(Finding("ERROR", "primary", "state=blocked; branch is not main"))
    if primary.head != origin_main:
        findings.append(
            Finding("ERROR", "primary", "state=blocked; main is stale against origin/main")
        )
    if primary.dirty_count is None:
        findings.append(Finding("ERROR", "primary", "state=blocked; status could not be verified"))
    elif primary.dirty_count:
        findings.append(
            Finding(
                "ERROR",
                "primary",
                f"state=blocked; dirty={primary.dirty_count}; primary must be clean-main",
            )
        )
    if len(worktrees) > maximum:
        findings.append(
            Finding(
                "ERROR",
                "registry",
                f"registered={len(worktrees)} exceeds maximum={maximum}",
            )
        )

    registered = {_normalized(item.path) for item in worktrees}
    for expected_item in expected:
        if _normalized(expected_item.path) not in registered:
            findings.append(
                Finding(
                    "ERROR",
                    expected_item.label,
                    "expected worktree registration is missing",
                )
            )

    for index, worktree in enumerate(worktrees):
        label = _label(index, worktree)
        if worktree.prunable or not worktree.path.is_dir():
            findings.append(Finding("ERROR", label, "registration is missing or prunable"))
            continue
        if index == 0:
            continue
        if worktree.dirty_count is None:
            findings.append(Finding("ERROR", label, "state=blocked; status could not be verified"))
        elif worktree.dirty_count:
            findings.append(
                Finding(
                    "WARNING",
                    label,
                    f"dirty={worktree.dirty_count}; classify as active, "
                    "recovery-stashed, or blocked",
                )
            )
        if worktree.branch is None:
            findings.append(Finding("WARNING", label, "state=blocked; task worktree is detached"))
    return tuple(findings)


def parse_expected(value: str) -> ExpectedWorktree:
    """Parse a privacy-safe ``LABEL=PATH`` expectation."""

    label, separator, raw_path = value.partition("=")
    if not separator or not EXPECTED_PATTERN.fullmatch(label) or not raw_path:
        raise argparse.ArgumentTypeError("expected worktree must use LABEL=PATH")
    return ExpectedWorktree(label, Path(raw_path))


def parse_args(arguments: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--max-worktrees",
        type=int,
        default=3,
        help="maximum primary-plus-task registrations (default: 3)",
    )
    parser.add_argument(
        "--expect",
        action="append",
        default=[],
        metavar="LABEL=PATH",
        type=parse_expected,
        help="require a named path to appear in Git's worktree registry",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="treat dirty or detached task-worktree warnings as errors",
    )
    return parser.parse_args(arguments)


def main(arguments: Sequence[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if arguments is None else arguments)
    if args.max_worktrees < 1:
        fail("--max-worktrees must be positive")
    repository = Path(__file__).resolve().parent.parent
    try:
        worktrees, origin_main = collect_worktrees(repository)
        findings = audit_worktrees(
            worktrees,
            origin_main,
            maximum=args.max_worktrees,
            expected=args.expect,
        )
    except (HygieneError, OSError) as exc:
        fail(str(exc))

    errors = 0
    warnings = 0
    for finding in findings:
        severity = "ERROR" if args.strict and finding.severity == "WARNING" else finding.severity
        if severity == "ERROR":
            errors += 1
        else:
            warnings += 1
        print(f"worktree-hygiene: {severity} {finding.label}: {finding.message}")
    if errors:
        print(
            f"worktree-hygiene: FAIL errors={errors} warnings={warnings} "
            f"registered={len(worktrees)}"
        )
        return 1
    print(
        f"worktree-hygiene: PASS state=clean-main registered={len(worktrees)} warnings={warnings}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
