from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


def _repository() -> Path:
    return Path(__file__).resolve().parents[2]


@pytest.mark.parametrize(
    "make_flags",
    ("-i", "-n", "-q", "-t", "--dry-run", "--ignore-errors", "--question", "--touch"),
)
def test_make_refuses_modes_that_can_bypass_required_recipes(make_flags: str) -> None:
    environment = os.environ.copy()
    environment["MAKEFLAGS"] = make_flags

    completed = subprocess.run(
        ["make", "lock-check"],
        cwd=_repository(),
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert completed.returncode != 0
    assert "refuse" in completed.stderr


def _capturing_uv(path: Path, capture: Path) -> Path:
    path.write_text(
        "\n".join(
            (
                f"#!{sys.executable}",
                "import json",
                "import pathlib",
                "import sys",
                "if sys.argv[1:] == ['--version']:",
                "    print('uv 0.11.29')",
                "    raise SystemExit(0)",
                f"pathlib.Path({os.fspath(capture)!r}).write_text(",
                "    json.dumps(sys.argv[1:]), encoding='utf-8'",
                ")",
                "",
            )
        ),
        encoding="utf-8",
    )
    path.chmod(0o700)
    return path


def test_required_make_commands_cannot_be_replaced_with_command_line_variables(
    tmp_path: Path,
) -> None:
    capture = tmp_path / "capture.json"
    exact_uv = _capturing_uv(tmp_path / "uv", capture)
    environment = os.environ.copy()
    environment["MILHOUSE_UV"] = os.fspath(exact_uv)
    environment.pop("MAKEFLAGS", None)

    completed = subprocess.run(
        [
            "make",
            "-s",
            "lock-check",
            "PYTHON=/usr/bin/false",
            "UV=/usr/bin/false",
            "SHELL=/usr/bin/false",
        ],
        cwd=_repository(),
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert completed.returncode == 0, completed.stderr
    arguments = json.loads(capture.read_text(encoding="utf-8"))
    assert arguments[-2:] == ["lock", "--check"]
    assert "--no-config" in arguments
