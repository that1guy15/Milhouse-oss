#!/usr/bin/env python3
"""Verify DCO sign-offs for every commit in an explicit Git range."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import unicodedata
from collections.abc import Sequence
from pathlib import Path
from typing import NoReturn

SAFE_REF = re.compile(r"^(?!-)[A-Za-z0-9][A-Za-z0-9._/@{}^~:-]{0,199}$")
SIGN_OFF = re.compile(r"^Signed-off-by:\s*(.+?)\s*<([^<>\s]+)>\s*$", re.IGNORECASE)


class DCOError(ValueError):
    """Raised for an unsafe range, Git error, or missing matching sign-off."""


def fail(message: str) -> NoReturn:
    print(f"dco: {message}", file=sys.stderr)
    raise SystemExit(1)


def _git(repository: Path, arguments: Sequence[str], input_text: str | None = None) -> str:
    try:
        completed = subprocess.run(
            ["git", "-C", str(repository), *arguments],
            input=input_text,
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise DCOError(f"cannot execute Git: {exc}") from exc
    if completed.returncode != 0:
        detail = completed.stderr.strip().splitlines()
        summary = detail[-1][:200] if detail else "Git command failed"
        raise DCOError(summary)
    return completed.stdout


def _resolve(repository: Path, reference: str) -> str:
    if not SAFE_REF.fullmatch(reference):
        raise DCOError(f"unsafe Git reference {reference!r}")
    resolved = _git(repository, ["rev-parse", "--verify", f"{reference}^{{commit}}"]).strip()
    if not re.fullmatch(r"[0-9a-f]{40,64}", resolved):
        raise DCOError(f"Git reference {reference!r} did not resolve to a commit")
    return resolved


def _identity(value: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", value).split()).casefold()


def verify_range(repository: Path, range_spec: str) -> tuple[str, ...]:
    """Verify each commit reachable from head but not base."""

    if range_spec.count("..") != 1 or "..." in range_spec:
        raise DCOError("range must use the exact BASE..HEAD form")
    base_ref, head_ref = range_spec.split("..", 1)
    base = _resolve(repository, base_ref)
    head = _resolve(repository, head_ref)
    commits = tuple(
        line
        for line in _git(repository, ["rev-list", "--reverse", f"{base}..{head}"]).splitlines()
        if line
    )
    if not commits:
        raise DCOError("the selected range contains no commits")

    failures: list[str] = []
    for commit in commits:
        raw = _git(repository, ["show", "-s", "--format=%an%x00%ae%x00%B", commit])
        parts = raw.split("\x00", 2)
        if len(parts) != 3:
            raise DCOError(f"cannot parse commit metadata for {commit[:12]}")
        author_name, author_email, message = parts
        trailers = _git(repository, ["interpret-trailers", "--parse"], input_text=message)
        matches = []
        for line in trailers.splitlines():
            match = SIGN_OFF.fullmatch(line)
            if match:
                matches.append((match.group(1), match.group(2)))
        author = (_identity(author_name), _identity(author_email))
        if not any((_identity(name), _identity(email)) == author for name, email in matches):
            failures.append(commit[:12])
    if failures:
        raise DCOError(
            "commit(s) lack an author-matching Signed-off-by trailer: " + ", ".join(failures)
        )
    return commits


def parse_args(arguments: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--range", dest="range_spec", required=True, metavar="BASE..HEAD")
    parser.add_argument("--repository", type=Path, default=Path.cwd())
    return parser.parse_args(arguments)


def main(arguments: Sequence[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if arguments is None else arguments)
    try:
        repository = args.repository.resolve(strict=True)
        commits = verify_range(repository, args.range_spec)
    except (DCOError, OSError) as exc:
        fail(str(exc))
    print(f"dco: {len(commits)} commit(s) passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
