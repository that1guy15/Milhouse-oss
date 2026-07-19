from copy import deepcopy
from pathlib import Path

import pytest

from scripts.milhouse_tools.strict_data import DataError
from scripts.validate_config import (
    EXPECTED_COVERAGE_EXCLUSIONS,
    EXPECTED_DEPENDABOT_POLICY,
    EXPECTED_PYTEST_MARKERS,
    discover,
    main,
    validate_dependabot_policy,
    validate_pyproject_policy,
)

REPO_ROOT = Path(__file__).resolve().parents[2]


def _gate_policy() -> dict[str, object]:
    return {
        "tool": {
            "pytest": {
                "ini_options": {
                    "addopts": ["--strict-config", "--strict-markers"],
                    "markers": list(EXPECTED_PYTEST_MARKERS),
                    "testpaths": ["tests"],
                }
            },
            "coverage": {
                "run": {"branch": True, "source": ["milhouse", "scripts"]},
                "report": {
                    "exclude_also": list(EXPECTED_COVERAGE_EXCLUSIONS),
                    "fail_under": 0,
                    "show_missing": True,
                    "skip_covered": True,
                },
                "json": {"output": "build/coverage.json", "show_contexts": True},
            },
            "mypy": {
                "files": ["src/milhouse", "scripts"],
                "pretty": True,
                "python_version": "3.11",
                "show_error_codes": True,
                "strict": True,
                "warn_unreachable": True,
            },
            "ruff": {
                "extend-exclude": ["build", "dist", "site"],
                "line-length": 100,
                "target-version": "py311",
                "lint": {
                    "select": ["B", "E", "F", "I", "RUF", "UP"],
                    "per-file-ignores": {"tests/**": ["S101"]},
                },
            },
        }
    }


def _dependabot_repository(tmp_path: Path) -> Path:
    config = tmp_path / ".github" / "dependabot.yml"
    config.parent.mkdir(parents=True)
    (tmp_path / "pyproject.toml").write_text("[project]\nname = 'fixture'\n", encoding="utf-8")
    (tmp_path / "uv.lock").write_text("version = 1\n", encoding="utf-8")
    workflows = config.parent / "workflows"
    workflows.mkdir()
    (workflows / "ci.yml").write_text("name: fixture\n", encoding="utf-8")
    return config


def _uv_update() -> dict[str, object]:
    return {
        "package-ecosystem": "uv",
        "directory": "/",
        "schedule": {"interval": "weekly"},
    }


def test_config_discovery_accepts_supported_files_and_recurses_deterministically(
    tmp_path: Path,
) -> None:
    direct = tmp_path / "direct.toml"
    direct.write_text("value = 1\n", encoding="utf-8")
    nested = tmp_path / "nested"
    nested.mkdir()
    data = nested / "data.json"
    data.write_text('{"value": 1}\n', encoding="utf-8")
    (nested / "ignored.txt").write_text("ignored\n", encoding="utf-8")
    ignored_link = nested / "ignored-link.txt"
    ignored_link.symlink_to(nested / "ignored.txt")

    assert discover((nested, direct)) == tuple(sorted((direct, data)))


def test_config_discovery_rejects_unsupported_missing_and_empty_inputs(tmp_path: Path) -> None:
    unsupported = tmp_path / "data.txt"
    unsupported.write_text("value\n", encoding="utf-8")
    empty = tmp_path / "empty"
    empty.mkdir()

    with pytest.raises(DataError, match="unsupported file type"):
        discover((unsupported,))
    with pytest.raises(DataError, match="input does not exist"):
        discover((tmp_path / "missing.json",))
    with pytest.raises(DataError, match="no supported data files"):
        discover((empty,))


def test_config_discovery_rejects_supported_symlink_documents(tmp_path: Path) -> None:
    target = tmp_path / "target.json"
    target.write_text('{"value": 1}\n', encoding="utf-8")
    direct_link = tmp_path / "direct.json"
    direct_link.symlink_to(target)

    with pytest.raises(DataError, match="symlink inputs"):
        discover((direct_link,))

    directory = tmp_path / "documents"
    directory.mkdir()
    nested_link = directory / "nested.yaml"
    nested_link.symlink_to(target)
    with pytest.raises(DataError, match="symlink documents"):
        discover((directory,))


def test_config_validation_main_reports_success_and_parse_failure(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    valid = tmp_path / "valid.json"
    valid.write_text('{"value": 1}\n', encoding="utf-8")

    assert main([str(valid)]) == 0
    assert "1 file(s) passed" in capsys.readouterr().out

    invalid = tmp_path / "invalid.json"
    invalid.write_text("{", encoding="utf-8")
    with pytest.raises(SystemExit) as caught:
        main([str(invalid)])
    assert caught.value.code == 1
    assert "config-validation:" in capsys.readouterr().err


def test_pyproject_semantic_gate_policy_accepts_only_the_reviewed_contract() -> None:
    validate_pyproject_policy(_gate_policy(), REPO_ROOT / "pyproject.toml")
    assert main([str(REPO_ROOT / "pyproject.toml")]) == 0


@pytest.mark.parametrize(
    ("section", "key", "value", "message"),
    [
        ("pytest", "testpaths", ["tests/unit"], "pytest testpaths"),
        ("pytest", "markers", ["unit: only unit tests"], "pytest markers"),
        ("coverage-run", "branch", False, "branch measurement"),
        ("coverage-run", "source", ["milhouse"], "coverage source"),
        ("coverage-report", "fail_under", 90, "independent thresholds"),
        ("coverage-report", "fail_under", False, "independent thresholds"),
        ("coverage-report", "exclude_also", [".*"], "coverage exclusions"),
        ("coverage-report", "show_missing", False, "visibility settings"),
        ("coverage-json", "output", "other.json", "JSON evidence settings"),
        ("coverage-json", "show_contexts", False, "JSON evidence settings"),
        ("mypy", "strict", False, "strict repository policy"),
        ("mypy", "files", ["src/milhouse"], "strict repository policy"),
        ("ruff", "target-version", "py314", "root configuration"),
        ("ruff", "extend-exclude", ["src"], "root configuration"),
        ("ruff-lint", "select", ["E", "F"], "lint selection"),
        ("ruff-per-file", "tests/**", ["S101", "F401"], "per-file ignores"),
    ],
)
def test_pyproject_semantic_gate_policy_rejects_reduced_scope(
    section: str,
    key: str,
    value: object,
    message: str,
) -> None:
    document = deepcopy(_gate_policy())
    tool = document["tool"]
    assert isinstance(tool, dict)
    if section == "pytest":
        pytest_config = tool["pytest"]
        assert isinstance(pytest_config, dict)
        target = pytest_config["ini_options"]
    elif section == "coverage-run":
        coverage = tool["coverage"]
        assert isinstance(coverage, dict)
        target = coverage["run"]
    elif section == "coverage-report":
        coverage = tool["coverage"]
        assert isinstance(coverage, dict)
        target = coverage["report"]
    elif section == "coverage-json":
        coverage = tool["coverage"]
        assert isinstance(coverage, dict)
        target = coverage["json"]
    elif section == "ruff-lint":
        ruff = tool["ruff"]
        assert isinstance(ruff, dict)
        target = ruff["lint"]
    elif section == "ruff-per-file":
        ruff = tool["ruff"]
        assert isinstance(ruff, dict)
        lint = ruff["lint"]
        assert isinstance(lint, dict)
        target = lint["per-file-ignores"]
    else:
        target = tool[section]
    assert isinstance(target, dict)
    target[key] = value

    with pytest.raises(DataError, match=message):
        validate_pyproject_policy(document, REPO_ROOT / "pyproject.toml")


@pytest.mark.parametrize(
    ("path", "key", "value"),
    [
        (("pytest", "ini_options"), "python_files", ["test_one.py"]),
        (("pytest", "ini_options"), "norecursedirs", ["tests/security"]),
        (("coverage", "run"), "omit", ["scripts/*"]),
        (("coverage", "report"), "exclude_lines", [".*"]),
        (("coverage", "json"), "pretty_print", True),
        (("mypy",), "exclude", "scripts"),
        (("mypy",), "ignore_errors", True),
        (("mypy",), "follow_imports", "skip"),
        (("ruff",), "exclude", ["src", "scripts"]),
        (("ruff", "lint"), "ignore", ["F"]),
        (("ruff", "lint", "per-file-ignores"), "scripts/**", ["F401"]),
    ],
)
def test_pyproject_semantic_gate_policy_rejects_unreviewed_sibling_bypasses(
    path: tuple[str, ...],
    key: str,
    value: object,
) -> None:
    document = _gate_policy()
    target: object = document["tool"]
    for part in path:
        assert isinstance(target, dict)
        target = target[part]
    assert isinstance(target, dict)
    target[key] = value

    with pytest.raises(DataError, match=r"missing or unreviewed keys|per-file ignores"):
        validate_pyproject_policy(document, REPO_ROOT / "pyproject.toml")


@pytest.mark.parametrize(
    "option",
    [
        "-k",
        "--collect-only",
        "--continue-on-collection-errors",
        "--deselect=tests/unit/test_example.py",
        "--ff",
        "--ignore=tests/security",
        "--ignore-glob=tests/security/*",
        "--lf",
        "--maxfail=1",
        "--stepwise",
    ],
)
def test_pyproject_semantic_gate_policy_rejects_pytest_selection_overrides(
    option: str,
) -> None:
    document = _gate_policy()
    tool = document["tool"]
    assert isinstance(tool, dict)
    pytest_config = tool["pytest"]
    assert isinstance(pytest_config, dict)
    ini_options = pytest_config["ini_options"]
    assert isinstance(ini_options, dict)
    addopts = ini_options["addopts"]
    assert isinstance(addopts, list)
    addopts.append(option)

    with pytest.raises(DataError, match="prohibited selector"):
        validate_pyproject_policy(document, REPO_ROOT / "pyproject.toml")


def test_pyproject_semantic_gate_policy_rejects_local_value_diagnostics() -> None:
    document = _gate_policy()
    tool = document["tool"]
    assert isinstance(tool, dict)
    pytest_config = tool["pytest"]
    assert isinstance(pytest_config, dict)
    ini_options = pytest_config["ini_options"]
    assert isinstance(ini_options, dict)
    addopts = ini_options["addopts"]
    assert isinstance(addopts, list)
    addopts.append("--showlocals")

    with pytest.raises(DataError, match="pytest addopts"):
        validate_pyproject_policy(document, REPO_ROOT / "pyproject.toml")


def test_pyproject_semantic_gate_policy_rejects_nonlist_addopts() -> None:
    document = _gate_policy()
    tool = document["tool"]
    assert isinstance(tool, dict)
    pytest_config = tool["pytest"]
    assert isinstance(pytest_config, dict)
    ini_options = pytest_config["ini_options"]
    assert isinstance(ini_options, dict)
    ini_options["addopts"] = "--strict-config"

    with pytest.raises(DataError, match="must be a string list"):
        validate_pyproject_policy(document, REPO_ROOT / "pyproject.toml")


@pytest.mark.parametrize("name", ("pytest.ini", ".pytest.ini", "tox.ini", "setup.cfg"))
def test_pyproject_semantic_gate_policy_rejects_competing_pytest_configuration(
    tmp_path: Path,
    name: str,
) -> None:
    (tmp_path / name).write_text("[pytest]\n", encoding="utf-8")

    with pytest.raises(DataError, match="competing pytest configuration"):
        validate_pyproject_policy(_gate_policy(), tmp_path / "pyproject.toml")


def test_pyproject_semantic_gate_policy_rejects_dangling_competing_symlink(
    tmp_path: Path,
) -> None:
    (tmp_path / "pytest.ini").symlink_to(tmp_path / "missing.ini")

    with pytest.raises(DataError, match="competing pytest configuration"):
        validate_pyproject_policy(_gate_policy(), tmp_path / "pyproject.toml")


def test_dependabot_policy_requires_github_actions_and_exact_bounded_schedule() -> None:
    path = REPO_ROOT / ".github" / "dependabot.yml"
    assert main([str(path)]) == 0
    validate_dependabot_policy(deepcopy(EXPECTED_DEPENDABOT_POLICY), path)


def test_dependabot_policy_rejects_ecosystem_without_a_supported_manifest() -> None:
    policy = deepcopy(EXPECTED_DEPENDABOT_POLICY)
    updates = policy["updates"]
    assert isinstance(updates, list)
    updates.append(
        {
            "package-ecosystem": "docker",
            "directory": "/ops/clickhouse",
            "schedule": {"interval": "weekly"},
        }
    )

    with pytest.raises(DataError, match="docker policy requires a regular Dockerfile manifest"):
        validate_dependabot_policy(policy, REPO_ROOT / ".github" / "dependabot.yml")


@pytest.mark.parametrize("directory", [None, "/missing"])
def test_dependabot_policy_rejects_invalid_or_missing_directories(
    tmp_path: Path, directory: object
) -> None:
    config = _dependabot_repository(tmp_path)
    policy = deepcopy(EXPECTED_DEPENDABOT_POLICY)
    updates = policy["updates"]
    assert isinstance(updates, list)
    first = updates[0]
    assert isinstance(first, dict)
    first["directory"] = directory

    message = "absolute repository path" if directory is None else "directory does not exist"
    with pytest.raises(DataError, match=message):
        validate_dependabot_policy(policy, config)


def test_dependabot_policy_rejects_symlink_directory(tmp_path: Path) -> None:
    config = _dependabot_repository(tmp_path)
    target = tmp_path / "target"
    target.mkdir()
    (tmp_path / "linked").symlink_to(target)
    policy = deepcopy(EXPECTED_DEPENDABOT_POLICY)
    updates = policy["updates"]
    assert isinstance(updates, list)
    first = updates[0]
    assert isinstance(first, dict)
    first["directory"] = "/linked"

    with pytest.raises(DataError, match="directory traverses a symlink"):
        validate_dependabot_policy(policy, config)


def test_dependabot_policy_rejects_nonlist_updates(tmp_path: Path) -> None:
    config = _dependabot_repository(tmp_path)
    policy = deepcopy(EXPECTED_DEPENDABOT_POLICY)
    policy["updates"] = {"not": "a list"}

    with pytest.raises(DataError, match="updates must be a list"):
        validate_dependabot_policy(policy, config)


def test_dependabot_policy_rejects_missing_actions_manifest(tmp_path: Path) -> None:
    config = _dependabot_repository(tmp_path)
    (tmp_path / ".github" / "workflows" / "ci.yml").unlink()

    with pytest.raises(DataError, match="github-actions requires"):
        validate_dependabot_policy(deepcopy(EXPECTED_DEPENDABOT_POLICY), config)


def test_dependabot_policy_rejects_missing_uv_manifest(tmp_path: Path) -> None:
    config = _dependabot_repository(tmp_path)
    (tmp_path / "uv.lock").unlink()
    policy: dict[str, object] = {"version": 2, "updates": [_uv_update()]}

    with pytest.raises(DataError, match="uv requires"):
        validate_dependabot_policy(policy, config)


def test_dependabot_policy_checks_uv_manifests_before_exact_policy(tmp_path: Path) -> None:
    config = _dependabot_repository(tmp_path)
    policy = deepcopy(EXPECTED_DEPENDABOT_POLICY)
    updates = policy["updates"]
    assert isinstance(updates, list)
    updates.append(_uv_update())

    with pytest.raises(DataError, match="ecosystems or schedules differ"):
        validate_dependabot_policy(policy, config)


def test_dependabot_policy_rejects_symlink_workflow_directory(tmp_path: Path) -> None:
    config = _dependabot_repository(tmp_path)
    workflows = config.parent / "workflows"
    (workflows / "ci.yml").unlink()
    workflows.rmdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "ci.yml").write_text("name: outside\n", encoding="utf-8")
    workflows.symlink_to(outside, target_is_directory=True)

    with pytest.raises(DataError, match="github-actions requires"):
        validate_dependabot_policy(deepcopy(EXPECTED_DEPENDABOT_POLICY), config)


def test_dependabot_policy_normalizes_manifest_filesystem_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = _dependabot_repository(tmp_path)

    def fail_glob(_path: Path, _pattern: str) -> object:
        raise PermissionError("synthetic-private-path")

    monkeypatch.setattr(Path, "glob", fail_glob)
    with pytest.raises(DataError) as captured:
        validate_dependabot_policy(deepcopy(EXPECTED_DEPENDABOT_POLICY), config)

    assert str(captured.value) == "Dependabot manifest inspection failed safely"
    assert "synthetic-private-path" not in str(captured.value)


def test_dependabot_policy_checks_dockerfile_before_exact_policy(tmp_path: Path) -> None:
    config = _dependabot_repository(tmp_path)
    docker = tmp_path / "ops" / "clickhouse"
    docker.mkdir(parents=True)
    (docker / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    policy = deepcopy(EXPECTED_DEPENDABOT_POLICY)
    updates = policy["updates"]
    assert isinstance(updates, list)
    updates.append(
        {
            "package-ecosystem": "docker",
            "directory": "/ops/clickhouse",
            "schedule": {"interval": "weekly"},
        }
    )

    with pytest.raises(DataError, match="ecosystems or schedules differ"):
        validate_dependabot_policy(policy, config)


def test_dependabot_policy_checks_compose_manifest_before_exact_policy(tmp_path: Path) -> None:
    config = _dependabot_repository(tmp_path)
    compose = tmp_path / "ops" / "clickhouse"
    compose.mkdir(parents=True)
    (compose / "docker-compose.yml").write_text(
        "services:\n  clickhouse:\n    image: clickhouse/clickhouse-server:24.8\n",
        encoding="utf-8",
    )
    policy = deepcopy(EXPECTED_DEPENDABOT_POLICY)
    updates = policy["updates"]
    assert isinstance(updates, list)
    updates.append(
        {
            "package-ecosystem": "docker-compose",
            "directory": "/ops/clickhouse",
            "schedule": {"interval": "weekly"},
        }
    )

    with pytest.raises(DataError, match="ecosystems or schedules differ"):
        validate_dependabot_policy(policy, config)


def test_dependabot_policy_rejects_missing_compose_manifest(tmp_path: Path) -> None:
    config = _dependabot_repository(tmp_path)
    compose = tmp_path / "ops" / "clickhouse"
    compose.mkdir(parents=True)
    policy: dict[str, object] = {
        "version": 2,
        "updates": [
            {
                "package-ecosystem": "docker-compose",
                "directory": "/ops/clickhouse",
                "schedule": {"interval": "weekly"},
            }
        ],
    }

    with pytest.raises(DataError, match="docker-compose requires a regular Compose manifest"):
        validate_dependabot_policy(policy, config)


@pytest.mark.parametrize("directory", ["ops/clickhouse", "/ops/../clickhouse", "/ops//clickhouse"])
def test_dependabot_policy_rejects_noncanonical_directories(directory: str) -> None:
    policy = deepcopy(EXPECTED_DEPENDABOT_POLICY)
    updates = policy["updates"]
    assert isinstance(updates, list)
    first = updates[0]
    assert isinstance(first, dict)
    first["directory"] = directory

    with pytest.raises(DataError, match="canonical absolute repository path"):
        validate_dependabot_policy(policy, REPO_ROOT / ".github" / "dependabot.yml")


@pytest.mark.parametrize("mutation", ["pip", "daily", "missing", "extra"])
def test_dependabot_policy_rejects_ecosystem_and_schedule_bypasses(mutation: str) -> None:
    policy = deepcopy(EXPECTED_DEPENDABOT_POLICY)
    updates = policy["updates"]
    assert isinstance(updates, list)
    first = updates[0]
    assert isinstance(first, dict)
    if mutation == "pip":
        first["package-ecosystem"] = "pip"
    elif mutation == "daily":
        schedule = first["schedule"]
        assert isinstance(schedule, dict)
        schedule["interval"] = "daily"
    elif mutation == "missing":
        updates.pop()
    else:
        updates.append(
            {
                "package-ecosystem": "npm",
                "directory": "/",
                "schedule": {"interval": "daily"},
            }
        )

    with pytest.raises(DataError, match="ecosystems or schedules differ"):
        validate_dependabot_policy(policy, REPO_ROOT / ".github" / "dependabot.yml")


def test_config_policy_dispatch_uses_canonical_resolved_paths_not_basenames(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    fixtures = tmp_path / "tests" / "fixtures"
    fixtures.mkdir(parents=True)
    (fixtures / "pyproject.toml").write_text('fixture = "structural only"\n', encoding="utf-8")
    (fixtures / "dependabot.yml").write_text("fixture: structural-only\n", encoding="utf-8")

    assert main([str(fixtures)]) == 0
    assert "2 file(s) passed" in capsys.readouterr().out


def test_repository_policy_mode_requires_both_canonical_files(
    capsys: pytest.CaptureFixture[str],
) -> None:
    pyproject = REPO_ROOT / "pyproject.toml"
    dependabot = REPO_ROOT / ".github" / "dependabot.yml"
    assert (
        main(
            [
                "--require-repository-policy",
                str(pyproject),
                str(dependabot),
            ]
        )
        == 0
    )
    capsys.readouterr()

    with pytest.raises(SystemExit) as caught:
        main(["--require-repository-policy", str(pyproject)])
    assert caught.value.code == 1
    assert "include all canonical policy files" in capsys.readouterr().err
