#!/usr/bin/env python3
"""Run fail-closed current-tree/history secret scans and planted-secret proofs."""

from __future__ import annotations

import argparse
import os
import secrets
import string
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import NoReturn

if __package__:
    from .gitleaks import GitleaksError, ensure_gitleaks
else:
    from gitleaks import GitleaksError, ensure_gitleaks  # type: ignore[import-not-found, no-redef]


DETECTED_EXIT = 23


class ScanError(RuntimeError):
    """Raised when a scan is unavailable, broken, or unexpectedly clean."""


def fail(message: str) -> NoReturn:
    print(f"secret-scan: {message}", file=sys.stderr)
    raise SystemExit(1)


def _run(command: Sequence[str], *, capture: bool) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            list(command),
            check=False,
            capture_output=capture,
            text=True,
            timeout=300,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ScanError(f"scanner execution failed: {exc}") from exc


def _git(repository: Path, arguments: Sequence[str]) -> str:
    completed = _run(["git", "-C", str(repository), *arguments], capture=True)
    if completed.returncode != 0:
        raise ScanError("Git prerequisite failed for the history scan")
    return completed.stdout.strip()


def tree_command(binary: Path, source: Path) -> tuple[str, ...]:
    return (
        str(binary),
        "dir",
        "--no-banner",
        "--redact=100",
        f"--exit-code={DETECTED_EXIT}",
        str(source),
    )


def history_command(binary: Path, repository: Path) -> tuple[str, ...]:
    return (
        str(binary),
        "git",
        "--no-banner",
        "--redact=100",
        f"--exit-code={DETECTED_EXIT}",
        "--log-opts=--all",
        str(repository),
    )


def scan_clean(command: Sequence[str], label: str) -> None:
    completed = _run(command, capture=False)
    if completed.returncode == 0:
        return
    if completed.returncode == DETECTED_EXIT:
        raise ScanError(f"{label} found a potential secret")
    raise ScanError(f"{label} failed with scanner exit {completed.returncode}")


def require_detection(command: Sequence[str], label: str) -> None:
    completed = _run(command, capture=True)
    if completed.returncode != DETECTED_EXIT:
        if completed.returncode == 0:
            raise ScanError(f"{label} missed the disposable planted secret")
        raise ScanError(f"{label} failed with scanner exit {completed.returncode}")


def scan_tree(binary: Path, source: Path) -> None:
    resolved = source.resolve(strict=True)
    if not resolved.is_dir():
        raise ScanError("current-tree scan source must be a directory")
    scan_clean(tree_command(binary, resolved), "current-tree scan")


def scan_history(binary: Path, repository: Path) -> None:
    resolved = repository.resolve(strict=True)
    if _git(resolved, ["rev-parse", "--is-inside-work-tree"]) != "true":
        raise ScanError("history scan source is not a Git work tree")
    if _git(resolved, ["rev-parse", "--is-shallow-repository"]) != "false":
        raise ScanError("full-history scan refuses a shallow repository")
    scan_clean(history_command(binary, resolved), "full-history scan")


def _plant_value() -> str:
    prefix = "".join(("g", "h", "p", "_"))
    alphabet = string.ascii_letters + string.digits
    return prefix + "".join(secrets.choice(alphabet) for _ in range(36))


def self_test(binary: Path) -> None:
    """Prove both scanner paths detect a value generated only at runtime."""

    with tempfile.TemporaryDirectory(prefix="milhouse-secret-proof-") as temporary:
        root = Path(temporary)
        os.chmod(root, 0o700)
        planted = _plant_value()

        tree = root / "tree"
        tree.mkdir(mode=0o700)
        tree_file = tree / "synthetic.txt"
        descriptor = os.open(tree_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            output.write("token=" + planted + "\n")
        require_detection(tree_command(binary, tree), "current-tree negative test")

        history = root / "history"
        history.mkdir(mode=0o700)
        for arguments in (
            ("init", "--quiet"),
            ("config", "user.name", "Milhouse Synthetic Test"),
            ("config", "user.email", "synthetic@example.invalid"),
        ):
            _git(history, arguments)
        history_file = history / "synthetic.txt"
        descriptor = os.open(history_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            output.write("token=" + planted + "\n")
        _git(history, ("add", "synthetic.txt"))
        _git(history, ("commit", "--quiet", "-m", "synthetic scanner proof"))
        require_detection(history_command(binary, history), "full-history negative test")

        planted = ""


def parse_args(arguments: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("tree", "history", "self-test", "all"))
    parser.add_argument("--source", type=Path, default=Path.cwd())
    parser.add_argument("--cache-dir", type=Path)
    return parser.parse_args(arguments)


def main(arguments: Sequence[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if arguments is None else arguments)
    try:
        binary = ensure_gitleaks(args.cache_dir)
        if args.mode in {"tree", "all"}:
            scan_tree(binary, args.source)
        if args.mode in {"history", "all"}:
            scan_history(binary, args.source)
        if args.mode in {"self-test", "all"}:
            self_test(binary)
    except (GitleaksError, OSError, ScanError) as exc:
        fail(str(exc))
    print(f"secret-scan: {args.mode} passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
