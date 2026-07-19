#!/usr/bin/env python3
"""Strictly parse repository TOML, JSON, and YAML documents."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Iterable, Sequence
from pathlib import Path, PurePosixPath
from typing import NoReturn

if __package__:
    from .milhouse_tools.strict_data import (
        SUPPORTED_SUFFIXES,
        DataError,
        load_data,
        require_mapping,
    )
else:
    from milhouse_tools.strict_data import (  # type: ignore[import-not-found, no-redef]
        SUPPORTED_SUFFIXES,
        DataError,
        load_data,
        require_mapping,
    )

EXPECTED_PYTEST_ADDOPTS = ("--strict-config", "--strict-markers")
COMPETING_PYTEST_CONFIGS = ("pytest.ini", ".pytest.ini", "tox.ini", "setup.cfg")
EXPECTED_PYTEST_MARKERS = (
    "contract: public and repository contract tests",
    "e2e: installed or end-to-end workflow tests",
    "integration: multi-module integration tests",
    "migration: migration foundation tests",
    "packaging: artifact and package inventory tests",
    "property: Hypothesis property tests",
    "security: security and privacy tests",
    "unit: isolated unit tests",
)
EXPECTED_COVERAGE_EXCLUSIONS = ("if TYPE_CHECKING:", "raise NotImplementedError")
EXPECTED_MYPY = {
    "files": ["src/milhouse", "scripts"],
    "pretty": True,
    "python_version": "3.11",
    "show_error_codes": True,
    "strict": True,
    "warn_unreachable": True,
}
EXPECTED_DEPENDABOT_POLICY = {
    "version": 2,
    "updates": [
        {
            "package-ecosystem": "github-actions",
            "directory": "/",
            "schedule": {
                "interval": "weekly",
                "day": "monday",
                "time": "07:30",
                "timezone": "America/Chicago",
            },
            "open-pull-requests-limit": 5,
        },
    ],
}
REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
CANONICAL_POLICIES = {
    (REPOSITORY_ROOT / "pyproject.toml").resolve(): "pyproject",
    (REPOSITORY_ROOT / ".github" / "dependabot.yml").resolve(): "dependabot",
}
DANGEROUS_PYTEST_OPTIONS = (
    "-k",
    "--collect-only",
    "--continue-on-collection-errors",
    "--deselect",
    "--ff",
    "--ignore",
    "--ignore-glob",
    "--lf",
    "--maxfail",
    "--stepwise",
)


def fail(message: str) -> NoReturn:
    print(f"config-validation: {message}", file=sys.stderr)
    raise SystemExit(1)


def discover(inputs: Iterable[Path]) -> tuple[Path, ...]:
    """Resolve explicit files and recursively discover supported files in directories."""

    discovered: set[Path] = set()
    for input_path in inputs:
        if input_path.is_symlink():
            raise DataError(f"{input_path}: symlink inputs are prohibited")
        if input_path.is_file():
            if input_path.suffix.lower() not in SUPPORTED_SUFFIXES:
                raise DataError(f"{input_path}: unsupported file type")
            discovered.add(input_path)
            continue
        if input_path.is_dir():
            for candidate in input_path.rglob("*"):
                if candidate.is_symlink():
                    if candidate.suffix.lower() in SUPPORTED_SUFFIXES:
                        raise DataError(f"{candidate}: symlink documents are prohibited")
                    continue
                if candidate.is_file() and candidate.suffix.lower() in SUPPORTED_SUFFIXES:
                    discovered.add(candidate)
            continue
        raise DataError(f"{input_path}: input does not exist")
    if not discovered:
        raise DataError("no supported data files were selected")
    return tuple(sorted(discovered))


def _exact_strings(value: object, expected: tuple[str, ...], label: str) -> None:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise DataError(f"{label} must be a string list")
    if tuple(value) != expected:
        raise DataError(f"{label} differs from the fail-closed repository policy")


def _exact_keys(value: dict[str, object], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise DataError(f"{label} contains missing or unreviewed keys")


def validate_pyproject_policy(value: object, path: Path) -> None:
    """Protect the semantic settings that define repository quality gates."""

    for name in COMPETING_PYTEST_CONFIGS:
        competing = path.parent / name
        if competing.exists() or competing.is_symlink():
            raise DataError(f"{path}: competing pytest configuration {name!r} is prohibited")

    root = require_mapping(value, str(path))
    tool = require_mapping(root.get("tool"), f"{path}:tool")

    pytest_config = require_mapping(tool.get("pytest"), f"{path}:tool.pytest")
    _exact_keys(pytest_config, {"ini_options"}, f"{path}: pytest configuration")
    pytest_options = require_mapping(
        pytest_config.get("ini_options"), f"{path}:tool.pytest.ini_options"
    )
    _exact_keys(
        pytest_options,
        {"addopts", "markers", "testpaths"},
        f"{path}: pytest ini_options",
    )
    raw_addopts = pytest_options.get("addopts")
    if isinstance(raw_addopts, list):
        for option in raw_addopts:
            if isinstance(option, str) and any(
                option == dangerous or option.startswith(f"{dangerous}=")
                for dangerous in DANGEROUS_PYTEST_OPTIONS
            ):
                raise DataError(f"{path}: pytest addopts contains prohibited selector {option!r}")
    _exact_strings(raw_addopts, EXPECTED_PYTEST_ADDOPTS, f"{path}: pytest addopts")
    _exact_strings(pytest_options.get("testpaths"), ("tests",), f"{path}: pytest testpaths")
    _exact_strings(
        pytest_options.get("markers"),
        EXPECTED_PYTEST_MARKERS,
        f"{path}: pytest markers",
    )

    coverage = require_mapping(tool.get("coverage"), f"{path}:tool.coverage")
    _exact_keys(coverage, {"json", "report", "run"}, f"{path}: coverage configuration")
    coverage_run = require_mapping(coverage.get("run"), f"{path}:tool.coverage.run")
    _exact_keys(coverage_run, {"branch", "source"}, f"{path}: coverage run")
    if coverage_run.get("branch") is not True:
        raise DataError(f"{path}: coverage branch measurement must be enabled")
    _exact_strings(
        coverage_run.get("source"),
        ("milhouse", "scripts"),
        f"{path}: coverage source",
    )
    coverage_report = require_mapping(coverage.get("report"), f"{path}:tool.coverage.report")
    _exact_keys(
        coverage_report,
        {"exclude_also", "fail_under", "show_missing", "skip_covered"},
        f"{path}: coverage report",
    )
    fail_under = coverage_report.get("fail_under")
    if type(fail_under) is not int or fail_under != 0:
        raise DataError(
            f"{path}: coverage.py fail_under must remain 0 so independent thresholds apply"
        )
    _exact_strings(
        coverage_report.get("exclude_also"),
        EXPECTED_COVERAGE_EXCLUSIONS,
        f"{path}: coverage exclusions",
    )
    if (
        coverage_report.get("show_missing") is not True
        or coverage_report.get("skip_covered") is not True
    ):
        raise DataError(f"{path}: coverage report visibility settings differ from policy")
    coverage_json = require_mapping(coverage.get("json"), f"{path}:tool.coverage.json")
    _exact_keys(coverage_json, {"output", "show_contexts"}, f"{path}: coverage json")
    if coverage_json != {"output": "build/coverage.json", "show_contexts": True}:
        raise DataError(f"{path}: coverage JSON evidence settings differ from policy")

    mypy = require_mapping(tool.get("mypy"), f"{path}:tool.mypy")
    _exact_keys(mypy, set(EXPECTED_MYPY), f"{path}: mypy configuration")
    if mypy != EXPECTED_MYPY:
        raise DataError(f"{path}: mypy configuration differs from strict repository policy")

    ruff = require_mapping(tool.get("ruff"), f"{path}:tool.ruff")
    _exact_keys(
        ruff,
        {"extend-exclude", "line-length", "lint", "target-version"},
        f"{path}: Ruff configuration",
    )
    if (
        ruff.get("target-version") != "py311"
        or ruff.get("line-length") != 100
        or ruff.get("extend-exclude") != ["build", "dist", "site"]
    ):
        raise DataError(f"{path}: Ruff root configuration differs from policy")
    ruff_lint = require_mapping(ruff.get("lint"), f"{path}:tool.ruff.lint")
    _exact_keys(
        ruff_lint,
        {"per-file-ignores", "select"},
        f"{path}: Ruff lint configuration",
    )
    _exact_strings(
        ruff_lint.get("select"),
        ("B", "E", "F", "I", "RUF", "UP"),
        f"{path}: Ruff lint selection",
    )
    per_file_ignores = require_mapping(
        ruff_lint.get("per-file-ignores"),
        f"{path}:tool.ruff.lint.per-file-ignores",
    )
    if per_file_ignores != {"tests/**": ["S101"]}:
        raise DataError(f"{path}: Ruff per-file ignores differ from policy")


def _dependabot_directory(repository_root: Path, value: object, label: str) -> Path:
    if not isinstance(value, str):
        raise DataError(f"{label}: directory must be an absolute repository path")
    if (
        not value.startswith("/")
        or "\\" in value
        or "//" in value
        or (value != "/" and value.endswith("/"))
        or (value != "/" and any(part in {"", ".", ".."} for part in value[1:].split("/")))
    ):
        raise DataError(f"{label}: directory must be a canonical absolute repository path")

    relative_parts = PurePosixPath(value).parts[1:]
    candidate = repository_root.joinpath(*relative_parts)
    current = repository_root
    for part in relative_parts:
        current /= part
        if current.is_symlink():
            raise DataError(f"{label}: directory traverses a symlink")
    if not candidate.is_dir():
        raise DataError(f"{label}: directory does not exist")
    return candidate


def _regular_file(path: Path) -> bool:
    return path.is_file() and not path.is_symlink()


def _validate_dependabot_manifests(value: object, path: Path) -> None:
    root = require_mapping(value, str(path))
    updates = root.get("updates")
    if not isinstance(updates, list):
        raise DataError(f"{path}: Dependabot updates must be a list")

    repository_root = path.parent.parent
    for index, raw_update in enumerate(updates):
        label = f"{path}: Dependabot update {index}"
        update = require_mapping(raw_update, label)
        ecosystem = update.get("package-ecosystem")
        try:
            directory = _dependabot_directory(repository_root, update.get("directory"), label)
            if ecosystem == "uv":
                required = (directory / "pyproject.toml", directory / "uv.lock")
                if not all(_regular_file(candidate) for candidate in required):
                    raise DataError(
                        f"{label}: uv requires regular pyproject.toml and uv.lock files"
                    )
            elif ecosystem == "github-actions":
                workflows = directory / ".github" / "workflows"
                manifests = (
                    candidate
                    for pattern in ("*.yml", "*.yaml")
                    for candidate in workflows.glob(pattern)
                )
                if (
                    workflows.is_symlink()
                    or not workflows.is_dir()
                    or not any(_regular_file(item) for item in manifests)
                ):
                    raise DataError(f"{label}: github-actions requires a regular workflow manifest")
            elif ecosystem == "docker":
                manifests = (
                    candidate
                    for candidate in directory.iterdir()
                    if candidate.name == "Dockerfile" or candidate.name.startswith("Dockerfile.")
                )
                if not any(_regular_file(item) for item in manifests):
                    raise DataError(
                        f"{label}: Milhouse docker policy requires a regular Dockerfile manifest"
                    )
            elif ecosystem == "docker-compose":
                names = (
                    "compose.yml",
                    "compose.yaml",
                    "docker-compose.yml",
                    "docker-compose.yaml",
                )
                if not any(_regular_file(directory / name) for name in names):
                    raise DataError(f"{label}: docker-compose requires a regular Compose manifest")
        except OSError:
            raise DataError("Dependabot manifest inspection failed safely") from None


def validate_dependabot_policy(value: object, path: Path) -> None:
    """Require exact ecosystems, usable manifests, and bounded schedules."""

    _validate_dependabot_manifests(value, path)
    if value != EXPECTED_DEPENDABOT_POLICY:
        raise DataError(f"{path}: Dependabot ecosystems or schedules differ from policy")


def parse_args(arguments: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--require-repository-policy", action="store_true")
    parser.add_argument("paths", nargs="+", type=Path)
    return parser.parse_args(arguments)


def main(arguments: Sequence[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if arguments is None else arguments)
    try:
        paths = discover(args.paths)
        observed_policies: set[str] = set()
        for path in paths:
            value = load_data(path)
            policy = CANONICAL_POLICIES.get(path.resolve())
            if policy == "pyproject":
                validate_pyproject_policy(value, path)
                observed_policies.add(policy)
            elif policy == "dependabot":
                validate_dependabot_policy(value, path)
                observed_policies.add(policy)
        if args.require_repository_policy and observed_policies != set(CANONICAL_POLICIES.values()):
            raise DataError("repository validation must include all canonical policy files")
    except DataError as exc:
        fail(str(exc))
    print(f"config-validation: {len(paths)} file(s) passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
