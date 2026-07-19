#!/usr/bin/env python3
"""Run the exact uv version used by Milhouse's reproducible toolchain."""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import NoReturn

UV_VERSION = "0.11.29"
UV_ENVIRONMENT_OVERRIDE = "MILHOUSE_UV"
_VERSION_PATTERN = re.compile(rf"^uv {re.escape(UV_VERSION)}(?: \([^\n]+\))?$")
REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
_SCRUBBED_ENVIRONMENT_NAMES = {
    "CONDA_PREFIX",
    "MYPYPATH",
    "PYTHONHOME",
    "PYTHONPATH",
    "PYTHONSTARTUP",
    "PYTHONWARNINGS",
    "VIRTUAL_ENV",
}
_SCRUBBED_ENVIRONMENT_PREFIXES = (
    "COV_CORE_",
    "COVERAGE_",
    "GITLEAKS_",
    "HYPOTHESIS_",
    "MYPY_",
    "PIP_",
    "PYTHON",
    "PYTEST_",
    "RUFF_",
    "TWINE_",
    "UV_",
    "ZIZMOR_",
)


def fail(message: str, exit_code: int = 2) -> NoReturn:
    """Exit with one concise, non-sensitive diagnostic."""

    print(f"run_uv: {message}", file=sys.stderr)
    raise SystemExit(exit_code)


def candidate_uv() -> Path:
    """Resolve the explicitly configured or PATH-provided uv executable."""

    override = os.environ.get(UV_ENVIRONMENT_OVERRIDE)
    raw_path = override if override else shutil.which("uv")
    if raw_path is None:
        fail(
            f"uv {UV_VERSION} is required; install that exact version or set "
            f"{UV_ENVIRONMENT_OVERRIDE}"
        )
    path = Path(raw_path).expanduser()
    try:
        resolved = path.resolve(strict=True)
    except OSError:
        fail("cannot resolve the configured uv executable")
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        fail("the resolved uv path is not an executable regular file")
    return resolved


def verify_uv(path: Path) -> None:
    """Reject missing, malformed, or non-exact uv versions."""

    try:
        completed = subprocess.run(
            [str(path), "--version"],
            check=False,
            capture_output=True,
            env=uv_environment(),
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        fail("could not execute uv --version")
    output = (completed.stdout or completed.stderr).strip()
    if completed.returncode != 0 or not _VERSION_PATTERN.fullmatch(output):
        fail(f"expected uv {UV_VERSION}; the resolved executable reported another version")


def uv_environment() -> dict[str, str]:
    """Return an environment that cannot redirect or poison locked project commands."""

    return {
        name: value
        for name, value in os.environ.items()
        if not name.startswith(_SCRUBBED_ENVIRONMENT_PREFIXES)
        and name not in _SCRUBBED_ENVIRONMENT_NAMES
    }


def run_uv(arguments: Sequence[str]) -> int:
    """Run uv after verifying the exact executable version."""

    path = candidate_uv()
    verify_uv(path)
    if not arguments:
        print(f"uv {UV_VERSION} ready")
        return 0
    if (
        not (REPOSITORY_ROOT / "pyproject.toml").is_file()
        or not (REPOSITORY_ROOT / "uv.lock").is_file()
    ):
        fail("the repository project or lock file is missing")
    command = [
        str(path),
        "--directory",
        str(REPOSITORY_ROOT),
        "--project",
        str(REPOSITORY_ROOT),
        "--no-config",
        *arguments,
    ]
    try:
        return subprocess.run(
            command,
            check=False,
            cwd=REPOSITORY_ROOT,
            env=uv_environment(),
        ).returncode
    except OSError:
        fail("could not execute uv")


def parse_args(arguments: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=f"Verify and run exactly uv {UV_VERSION}.")
    parser.add_argument(
        "--print-path",
        action="store_true",
        help="print the verified executable path and exit",
    )
    parser.add_argument("uv_arguments", nargs=argparse.REMAINDER)
    return parser.parse_args(arguments)


def main(arguments: Sequence[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if arguments is None else arguments)
    if args.print_path:
        path = candidate_uv()
        verify_uv(path)
        print(path)
        return 0
    uv_arguments: list[str] = args.uv_arguments
    if uv_arguments[:1] == ["--"]:
        uv_arguments = uv_arguments[1:]
    return run_uv(uv_arguments)


if __name__ == "__main__":
    raise SystemExit(main())
