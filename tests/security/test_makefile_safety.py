from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

CRITICAL_COVERAGE_FILES = {
    "src/milhouse/config/filesystem.py",
    "src/milhouse/config/loader.py",
    "src/milhouse/config/paths.py",
    "src/milhouse/config/secrets.py",
    "src/milhouse/resources/__init__.py",
    "src/milhouse/core/canonical.py",
    "src/milhouse/domain/identity.py",
    "src/milhouse/domain/records.py",
    "src/milhouse/privacy/keys.py",
    "src/milhouse/privacy/allowlist.py",
    "src/milhouse/privacy/pseudonym.py",
    "src/milhouse/privacy/redact.py",
    "src/milhouse/privacy/render.py",
    "src/milhouse/privacy/sanitize.py",
    "scripts/check_artifacts.py",
    "scripts/check_coverage.py",
    "scripts/check_dco.py",
    "scripts/check_links.py",
    "scripts/check_private_identifiers.py",
    "scripts/gitleaks.py",
    "scripts/prepare_environment.py",
    "scripts/required_ci.py",
    "scripts/run_make.py",
    "scripts/run_uv.py",
    "scripts/secret_scan.py",
    "scripts/validate_config.py",
    "scripts/validate_workflows.py",
    "scripts/milhouse_tools/strict_data.py",
}


def test_makefile_enumerates_every_critical_coverage_module() -> None:
    repository = Path(__file__).resolve().parents[2]
    makefile = (repository / "Makefile").read_text(encoding="utf-8")
    target = makefile.split("test-coverage:\n", 1)[1].split("\nrepo-check:", 1)[0]

    assert set(re.findall(r"--critical '([^']+)'", target)) == CRITICAL_COVERAGE_FILES
    assert target.count("--critical '") == len(CRITICAL_COVERAGE_FILES)
    assert "--line 90 --branch 85" in target
    assert "--critical-branch 95" in target


def test_makefile_refuses_an_outside_working_directory_before_cleanup(tmp_path: Path) -> None:
    make = shutil.which("make")
    assert make is not None
    source_repository = Path(__file__).resolve().parents[2]
    repository = tmp_path / "repository"
    repository.mkdir()
    shutil.copyfile(source_repository / "Makefile", repository / "Makefile")
    outside = tmp_path / "outside"
    build = outside / "build"
    build.mkdir(parents=True)
    sentinel = build / "sentinel.txt"
    sentinel.write_text("preserve\n", encoding="utf-8")

    result = subprocess.run(
        [make, "-f", os.fspath(Path("..") / "repository" / "Makefile"), "build"],
        cwd=outside,
        env={"LC_ALL": "C", "PATH": os.environ.get("PATH", "/usr/bin:/bin")},
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )

    assert result.returncode != 0
    assert "must be run from its repository root" in result.stderr
    assert os.fspath(repository.resolve()) not in result.stderr
    assert sentinel.read_text(encoding="utf-8") == "preserve\n"


def test_makefile_refuses_environment_preloads_before_a_false_green(tmp_path: Path) -> None:
    make = shutil.which("make")
    assert make is not None
    source_repository = Path(__file__).resolve().parents[2]
    repository = tmp_path / "repository"
    repository.mkdir()
    shutil.copyfile(source_repository / "Makefile", repository / "Makefile")
    preload = repository / "preload.mk"
    preload.write_text(
        "quality: override UV := /usr/bin/true\nquality: override UV_RUN := /usr/bin/true\n",
        encoding="utf-8",
    )
    environment = os.environ.copy()
    environment.pop("MAKEFLAGS", None)
    environment["MAKEFILES"] = os.fspath(preload)

    result = subprocess.run(
        [make, "-f", "Makefile", "quality"],
        cwd=repository,
        env=environment,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )

    assert result.returncode != 0
    assert "refuse MAKEFILES preloads" in result.stderr
    assert os.fspath(repository.resolve()) not in result.stderr


def test_make_launcher_removes_a_preload_before_it_can_false_green_a_gate(
    tmp_path: Path,
) -> None:
    make = shutil.which("make")
    assert make is not None
    source_repository = Path(__file__).resolve().parents[2]
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "Makefile").write_text(
        "GATE_COMMAND ?= /usr/bin/false\n\ngate:\n\t@$(GATE_COMMAND)\n",
        encoding="utf-8",
    )
    preload = repository / "preload.mk"
    preload.write_text(
        "override GATE_COMMAND := /usr/bin/true\n",
        encoding="utf-8",
    )
    environment = os.environ.copy()
    environment.pop("GNUMAKEFLAGS", None)
    environment.pop("MAKEFLAGS", None)
    environment["MAKEFILES"] = os.fspath(preload)

    bypassed = subprocess.run(
        [make, "gate"],
        cwd=repository,
        env=environment,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    clean_environment = environment.copy()
    clean_environment.pop("MAKEFILES")
    expected_failure = subprocess.run(
        [make, "gate"],
        cwd=repository,
        env=clean_environment,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    protected = subprocess.run(
        [os.fspath(source_repository / "scripts" / "run_make.py"), "gate"],
        cwd=repository,
        env=environment,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )

    assert bypassed.returncode == 0, bypassed.stderr
    assert expected_failure.returncode != 0
    assert protected.returncode == expected_failure.returncode


def test_canonical_target_overrides_defeat_earlier_target_specific_values(
    tmp_path: Path,
) -> None:
    make = shutil.which("make")
    assert make is not None
    repository = Path(__file__).resolve().parents[2]
    preload = tmp_path / "explicit-preload.mk"
    preload.write_text(
        "skill-check: override SHELL := /usr/bin/true\n"
        "skill-check: override .SHELLFLAGS := -c\n"
        "skill-check: override UV := /usr/bin/true\n"
        "skill-check: override UV_RUN := /usr/bin/true\n",
        encoding="utf-8",
    )
    marker = tmp_path / "canonical-command-ran"
    fake_uv = tmp_path / "uv"
    fake_uv.write_text(
        "\n".join(
            (
                f"#!{sys.executable}",
                "import pathlib",
                "import sys",
                "if sys.argv[1:] == ['--version']:",
                "    print('uv 0.11.29')",
                "    raise SystemExit(0)",
                f"pathlib.Path({os.fspath(marker)!r}).write_text('ran', encoding='utf-8')",
                "",
            )
        ),
        encoding="utf-8",
    )
    fake_uv.chmod(0o700)
    environment = os.environ.copy()
    environment.pop("MAKEFLAGS", None)
    environment.pop("MAKEFILES", None)
    environment["MILHOUSE_UV"] = os.fspath(fake_uv)

    result = subprocess.run(
        [make, "-f", os.fspath(preload), "-f", "Makefile", "skill-check"],
        cwd=repository,
        env=environment,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert marker.read_text(encoding="utf-8") == "ran"
