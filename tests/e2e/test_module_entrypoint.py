import os
import subprocess
import sys
from pathlib import Path

from milhouse import __version__


def _source_environment() -> dict[str, str]:
    project_root = Path(__file__).resolve().parents[2]
    environment = os.environ.copy()
    existing = environment.get("PYTHONPATH")
    paths = [str(project_root / "src")]
    if existing:
        paths.append(existing)
    environment["PYTHONPATH"] = os.pathsep.join(paths)
    return environment


def test_python_module_entrypoint_help_and_version(tmp_path: Path) -> None:
    environment = _source_environment()

    help_result = subprocess.run(
        [sys.executable, "-m", "milhouse", "--help"],
        cwd=tmp_path,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    version_result = subprocess.run(
        [sys.executable, "-m", "milhouse", "--version"],
        cwd=tmp_path,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    assert help_result.returncode == 0, help_result.stderr
    assert "pre-alpha" in help_result.stdout
    assert version_result.returncode == 0, version_result.stderr
    assert version_result.stdout == f"milhouse, version {__version__}\n"
