import runpy
import sys
from copy import deepcopy
from pathlib import Path

import pytest
import yaml

from scripts import validate_workflows as workflow_validation
from scripts.validate_workflows import (
    DEPENDENCY_REVIEW_SETTINGS,
    MAKE_LAUNCHER,
    WorkflowError,
    main,
    validate_workflow,
)

PINNED_ACTION = "actions/checkout@" + "a" * 40
PINNED_DEPENDENCY_REVIEW = "actions/dependency-review-action@" + "b" * 40
AGGREGATE_JOBS = (
    "quality",
    "test",
    "audit",
    "dependency-review",
    "dco",
)
RESULT_ENVIRONMENT = {
    "AUDIT_RESULT": "${{ needs.audit.result }}",
    "DCO_RESULT": "${{ needs.dco.result }}",
    "DEPENDENCY_REVIEW_RESULT": "${{ needs.dependency-review.result }}",
    "QUALITY_RESULT": "${{ needs.quality.result }}",
    "TEST_RESULT": "${{ needs.test.result }}",
}


def _aggregate_command() -> str:
    variables = {
        "quality": "QUALITY_RESULT",
        "test": "TEST_RESULT",
        "audit": "AUDIT_RESULT",
        "dependency-review": "DEPENDENCY_REVIEW_RESULT",
        "dco": "DCO_RESULT",
    }
    arguments = " ".join(
        f'--expected-job {job} --result "{job}=${{{variables[job]}}}"' for job in AGGREGATE_JOBS
    )
    return f"python scripts/required_ci.py {arguments}"


def _baseline() -> dict[str, object]:
    return {
        "name": "Required CI",
        "on": {"pull_request": None},
        "permissions": {"contents": "read"},
        "jobs": {
            "quality": {
                "runs-on": "ubuntu-24.04",
                "steps": [
                    {
                        "uses": PINNED_ACTION,
                        "with": {"persist-credentials": False},
                    },
                    {"run": "python -m pytest tests/unit"},
                ],
            },
            "test": {
                "runs-on": "ubuntu-24.04",
                "steps": [{"run": "python -m pytest tests/security"}],
            },
            "audit": {
                "runs-on": "ubuntu-24.04",
                "steps": [{"run": f"{MAKE_LAUNCHER} license-check"}],
            },
            "dependency-review": {
                "runs-on": "ubuntu-24.04",
                "steps": [
                    {
                        "if": "github.event_name == 'pull_request'",
                        "uses": PINNED_DEPENDENCY_REVIEW,
                        "with": dict(DEPENDENCY_REVIEW_SETTINGS),
                    },
                    {
                        "if": "github.event_name != 'pull_request'",
                        "run": "test -f uv.lock",
                    },
                ],
            },
            "dco": {
                "runs-on": "ubuntu-24.04",
                "steps": [
                    {
                        "uses": PINNED_ACTION,
                        "with": {"fetch-depth": 0, "persist-credentials": False},
                    },
                    {
                        "if": "github.event_name == 'pull_request'",
                        "env": {
                            "BASE_SHA": "${{ github.event.pull_request.base.sha }}",
                            "HEAD_SHA": "${{ github.event.pull_request.head.sha }}",
                        },
                        "run": ('python scripts/check_dco.py --range "${BASE_SHA}..${HEAD_SHA}"'),
                    },
                    {
                        "if": "github.event_name == 'push'",
                        "env": {
                            "BEFORE_SHA": "${{ github.event.before }}",
                            "AFTER_SHA": "${{ github.event.after }}",
                        },
                        "run": (
                            'python scripts/check_dco.py --range "${BEFORE_SHA}..${AFTER_SHA}"'
                        ),
                    },
                    {
                        "if": (
                            "github.event_name == 'schedule' || "
                            "github.event_name == 'workflow_dispatch'"
                        ),
                        "run": 'python scripts/check_dco.py --range "HEAD^..HEAD"',
                    },
                ],
            },
            "required-ci": {
                "needs": ["quality", "test", "audit", "dependency-review", "dco"],
                "if": "${{ always() }}",
                "permissions": {"contents": "read"},
                "runs-on": "ubuntu-24.04",
                "steps": [
                    {
                        "env": dict(RESULT_ENVIRONMENT),
                        "run": _aggregate_command(),
                    }
                ],
            },
        },
    }


def _write(repo: Path, document: dict[str, object]) -> Path:
    path = repo / ".github" / "workflows" / "ci.yml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    return path


def _mutate(case: str) -> dict[str, object]:
    workflow = deepcopy(_baseline())
    jobs = workflow["jobs"]
    assert isinstance(jobs, dict)
    quality = jobs["quality"]
    aggregate = jobs["required-ci"]
    assert isinstance(quality, dict)
    assert isinstance(aggregate, dict)
    quality_steps = quality["steps"]
    aggregate_steps = aggregate["steps"]
    assert isinstance(quality_steps, list)
    assert isinstance(aggregate_steps, list)

    if case == "missing aggregate dependency":
        aggregate["needs"] = ["quality"]
    elif case == "skippable aggregate":
        aggregate["if"] = "${{ success() }}"
    elif case == "conditional evaluator":
        evaluator = aggregate_steps[0]
        assert isinstance(evaluator, dict)
        evaluator["if"] = "${{ success() }}"
    elif case == "conditional mandatory step":
        step = quality_steps[1]
        assert isinstance(step, dict)
        step["if"] = "${{ false }}"
    elif case == "conditional mandatory job":
        quality["if"] = "${{ false }}"
    elif case == "dependency review pull request condition changed":
        dependency_review = jobs["dependency-review"]
        assert isinstance(dependency_review, dict)
        steps = dependency_review["steps"]
        assert isinstance(steps, list)
        action = steps[0]
        assert isinstance(action, dict)
        action["if"] = "${{ false }}"
    elif case == "dependency review fallback condition changed":
        dependency_review = jobs["dependency-review"]
        assert isinstance(dependency_review, dict)
        steps = dependency_review["steps"]
        assert isinstance(steps, list)
        fallback = steps[1]
        assert isinstance(fallback, dict)
        fallback["if"] = "${{ false }}"
    elif case == "masked command":
        step = quality_steps[1]
        assert isinstance(step, dict)
        step["run"] = "python -m pytest || true"
    elif case == "direct make invocation":
        step = quality_steps[1]
        assert isinstance(step, dict)
        step["run"] = "make quality"
    elif case == "continue on error":
        quality["continue-on-error"] = True
    elif case == "step continue on error":
        step = quality_steps[1]
        assert isinstance(step, dict)
        step["continue-on-error"] = True
    elif case == "unpinned action":
        step = quality_steps[0]
        assert isinstance(step, dict)
        step["uses"] = "actions/checkout@v4"
    elif case == "missing permissions":
        workflow.pop("permissions")
    elif case == "write permissions":
        workflow["permissions"] = {"contents": "write"}
    elif case == "unknown top key":
        workflow["unknown"] = True
    elif case == "secret expression":
        workflow["env"] = {"VALUE": "${{ secrets.VALUE }}"}
    elif case == "missing trigger":
        workflow.pop("on")
    elif case == "prohibited trigger":
        workflow["on"] = {"pull_request_target": None}
    elif case == "invalid trigger":
        workflow["on"] = 3
    elif case == "unknown permission":
        workflow["permissions"] = {"unknown": "read"}
    elif case == "invalid permission level":
        workflow["permissions"] = {"contents": "maybe"}
    elif case == "job write permission":
        quality["permissions"] = {"contents": "write"}
    elif case == "invalid job id":
        jobs["invalid job"] = jobs.pop("quality")
        aggregate["needs"] = ["invalid job", "test"]
    elif case == "unknown job key":
        quality["unknown"] = True
    elif case == "job continue false allowed":
        quality["continue-on-error"] = "false"
    elif case == "invalid timeout":
        quality["timeout-minutes"] = 0
    elif case == "boolean timeout":
        quality["timeout-minutes"] = True
    elif case == "inherited secrets":
        quality["secrets"] = "inherit"
    elif case == "mixed reusable job":
        quality["uses"] = PINNED_ACTION
    elif case == "unpinned reusable job":
        quality.pop("runs-on")
        quality.pop("steps")
        quality["uses"] = "example/action@v1"
    elif case == "latest runner":
        quality["runs-on"] = "ubuntu-latest"
    elif case == "missing runs on":
        quality.pop("runs-on")
    elif case == "missing steps":
        quality.pop("steps")
    elif case == "empty steps":
        quality["steps"] = []
    elif case == "unknown step key":
        step = quality_steps[1]
        assert isinstance(step, dict)
        step["unknown"] = True
    elif case == "both uses and run":
        step = quality_steps[0]
        assert isinstance(step, dict)
        step["run"] = "python -m pytest"
    elif case == "neither uses nor run":
        step = quality_steps[1]
        assert isinstance(step, dict)
        step.pop("run")
    elif case == "checkout persists credentials":
        step = quality_steps[0]
        assert isinstance(step, dict)
        step["with"] = {"persist-credentials": True}
    elif case == "dco synthetic merge ref":
        dco = jobs["dco"]
        assert isinstance(dco, dict)
        dco_steps = dco["steps"]
        assert isinstance(dco_steps, list)
        pull_request_step = dco_steps[1]
        assert isinstance(pull_request_step, dict)
        pull_request_step["run"] = 'python scripts/check_dco.py --range "${BASE_SHA}..HEAD"'
    elif case == "dco missing head binding":
        dco = jobs["dco"]
        assert isinstance(dco, dict)
        dco_steps = dco["steps"]
        assert isinstance(dco_steps, list)
        pull_request_step = dco_steps[1]
        assert isinstance(pull_request_step, dict)
        environment = pull_request_step["env"]
        assert isinstance(environment, dict)
        environment.pop("HEAD_SHA")
    elif case == "dco push checks only head":
        dco = jobs["dco"]
        assert isinstance(dco, dict)
        dco_steps = dco["steps"]
        assert isinstance(dco_steps, list)
        push_step = dco_steps[2]
        assert isinstance(push_step, dict)
        push_step["run"] = 'python scripts/check_dco.py --range "HEAD^..HEAD"'
    elif case == "dco push missing before binding":
        dco = jobs["dco"]
        assert isinstance(dco, dict)
        dco_steps = dco["steps"]
        assert isinstance(dco_steps, list)
        push_step = dco_steps[2]
        assert isinstance(push_step, dict)
        environment = push_step["env"]
        assert isinstance(environment, dict)
        environment.pop("BEFORE_SHA")
    elif case == "conditional dco checkout":
        dco = jobs["dco"]
        assert isinstance(dco, dict)
        dco_steps = dco["steps"]
        assert isinstance(dco_steps, list)
        checkout = dco_steps[0]
        assert isinstance(checkout, dict)
        checkout["if"] = "github.event_name == 'pull_request'"
    elif case == "dco shallow checkout":
        dco = jobs["dco"]
        assert isinstance(dco, dict)
        dco_steps = dco["steps"]
        assert isinstance(dco_steps, list)
        checkout = dco_steps[0]
        assert isinstance(checkout, dict)
        checkout_options = checkout["with"]
        assert isinstance(checkout_options, dict)
        checkout_options["fetch-depth"] = 1
    elif case == "duplicate needs":
        aggregate["needs"] = ["quality", "quality"]
    elif case == "unknown need":
        quality["needs"] = "absent"
    elif case == "dependency cycle":
        quality["needs"] = "required-ci"
    elif case == "unsupported aggregate trigger":
        workflow["on"] = {"pull_request": None, "issues": None}
    elif case == "aggregate path filter":
        workflow["on"] = {"pull_request": {"paths": ["src/**"]}}
    elif case == "aggregate write permission":
        aggregate["permissions"] = {"security-events": "write"}
    elif case == "empty evaluator steps":
        aggregate["steps"] = []
    elif case == "missing evaluator":
        aggregate["steps"] = [{"run": "python -m pytest"}]
    elif case == "multiple evaluators":
        aggregate["steps"] = [aggregate_steps[0], deepcopy(aggregate_steps[0])]
    elif case == "malformed evaluator command":
        evaluator = aggregate_steps[0]
        assert isinstance(evaluator, dict)
        evaluator["run"] = "python scripts/required_ci.py '"
    elif case == "hardcoded aggregate result":
        evaluator = aggregate_steps[0]
        assert isinstance(evaluator, dict)
        run = evaluator["run"]
        assert isinstance(run, str)
        evaluator["run"] = run.replace("quality=${QUALITY_RESULT}", "quality=success")
    elif case == "swapped aggregate results":
        evaluator = aggregate_steps[0]
        assert isinstance(evaluator, dict)
        run = evaluator["run"]
        assert isinstance(run, str)
        evaluator["run"] = (
            run.replace("quality=${QUALITY_RESULT}", "quality=${TEMP_RESULT}")
            .replace("test=${TEST_RESULT}", "test=${QUALITY_RESULT}")
            .replace("quality=${TEMP_RESULT}", "quality=${TEST_RESULT}")
        )
    elif case == "duplicate aggregate binding":
        evaluator = aggregate_steps[0]
        assert isinstance(evaluator, dict)
        run = evaluator["run"]
        assert isinstance(run, str)
        evaluator["run"] = f'{run} --expected-job quality --result "quality=${{QUALITY_RESULT}}"'
    elif case == "unused aggregate environment":
        evaluator = aggregate_steps[0]
        assert isinstance(evaluator, dict)
        environment = evaluator["env"]
        assert isinstance(environment, dict)
        environment["BASE_SHA"] = "${{ github.event.pull_request.base.sha }}"
    elif case == "extra aggregate binding":
        evaluator = aggregate_steps[0]
        assert isinstance(evaluator, dict)
        run = evaluator["run"]
        assert isinstance(run, str)
        evaluator["run"] = f'{run} --expected-job extra --result "extra=${{QUALITY_RESULT}}"'
    elif case == "missing aggregate binding":
        evaluator = aggregate_steps[0]
        assert isinstance(evaluator, dict)
        run = evaluator["run"]
        assert isinstance(run, str)
        evaluator["run"] = run.replace(' --expected-job dco --result "dco=${DCO_RESULT}"', "")
    else:  # pragma: no cover - test-table programming error
        raise AssertionError(case)
    return workflow


def test_workflow_validator_accepts_a_complete_fail_closed_aggregate(tmp_path: Path) -> None:
    path = _write(tmp_path, _baseline())

    assert validate_workflow(path, tmp_path.resolve(), set(), set()) is True


def test_workflow_validator_accepts_only_reviewed_environment_bindings(tmp_path: Path) -> None:
    workflow = _baseline()
    workflow["env"] = {"UV_VERSION": "0.11.29"}
    jobs = workflow["jobs"]
    assert isinstance(jobs, dict)
    quality = jobs["quality"]
    assert isinstance(quality, dict)
    steps = quality["steps"]
    assert isinstance(steps, list)
    run_step = steps[1]
    assert isinstance(run_step, dict)
    run_step["env"] = {"BASE_SHA": "${{ github.event.pull_request.base.sha }}"}
    path = _write(tmp_path, workflow)

    assert validate_workflow(path, tmp_path.resolve(), set(), set()) is True


@pytest.mark.parametrize(
    ("scope", "key"),
    [
        ("workflow", "PYTEST_ADDOPTS"),
        ("workflow", "COVERAGE_RCFILE"),
        ("workflow", "COV_CORE_SOURCE"),
        ("job", "MYPYPATH"),
        ("job", "MYPY_CACHE_DIR"),
        ("job", "HYPOTHESIS_PROFILE"),
        ("step", "PYTHONPATH"),
        ("step", "PYTHONHOME"),
        ("step", "VIRTUAL_ENV"),
        ("step", "CONDA_PREFIX"),
        ("step", "UV_PROJECT"),
        ("step", "UV_CONFIG_FILE"),
    ],
)
def test_workflow_validator_rejects_gate_altering_environment_at_every_scope(
    tmp_path: Path,
    scope: str,
    key: str,
) -> None:
    workflow = _baseline()
    jobs = workflow["jobs"]
    assert isinstance(jobs, dict)
    quality = jobs["quality"]
    assert isinstance(quality, dict)
    steps = quality["steps"]
    assert isinstance(steps, list)
    run_step = steps[1]
    assert isinstance(run_step, dict)
    if scope == "workflow":
        workflow["env"] = {key: "hostile"}
    elif scope == "job":
        quality["env"] = {key: "hostile"}
    else:
        run_step["env"] = {key: "hostile"}
    path = _write(tmp_path, workflow)

    with pytest.raises(WorkflowError, match=rf"environment key {key!r} is not allowlisted"):
        validate_workflow(path, tmp_path.resolve(), set(), set())


def test_workflow_validator_rejects_unreviewed_uv_version_value(tmp_path: Path) -> None:
    workflow = _baseline()
    workflow["env"] = {"UV_VERSION": "newer"}
    path = _write(tmp_path, workflow)

    with pytest.raises(WorkflowError, match=r"UV_VERSION.*unreviewed value"):
        validate_workflow(path, tmp_path.resolve(), set(), set())


@pytest.mark.parametrize(
    ("key", "value"),
    [
        (
            "allow-dependencies-licenses",
            "pkg:pypi/chardet@5.2.0, pkg:pypi/docutils@0.23",
        ),
        ("deny-licenses", "GPL-3.0-only"),
        ("fail-on-severity", "critical"),
        ("license-check", False),
        ("allow-ghsas", "GHSA-synthetic-placeholder"),
    ],
)
def test_dependency_review_settings_are_exact_and_cannot_exempt_vulnerabilities(
    tmp_path: Path,
    key: str,
    value: object,
) -> None:
    workflow = _baseline()
    jobs = workflow["jobs"]
    assert isinstance(jobs, dict)
    dependency_review = jobs["dependency-review"]
    assert isinstance(dependency_review, dict)
    steps = dependency_review["steps"]
    assert isinstance(steps, list)
    action = steps[0]
    assert isinstance(action, dict)
    settings = action["with"]
    assert isinstance(settings, dict)
    settings[key] = value
    path = _write(tmp_path, workflow)

    with pytest.raises(WorkflowError, match="settings differ from the reviewed"):
        validate_workflow(path, tmp_path.resolve(), set(), set())


@pytest.mark.parametrize("missing_control", ["hosted", "local"])
def test_dependency_review_requires_hosted_and_exact_local_license_proof(
    tmp_path: Path,
    missing_control: str,
) -> None:
    workflow = _baseline()
    jobs = workflow["jobs"]
    assert isinstance(jobs, dict)
    if missing_control == "hosted":
        dependency_review = jobs["dependency-review"]
        assert isinstance(dependency_review, dict)
        dependency_review["steps"] = [{"run": "test -f uv.lock"}]
    else:
        audit = jobs["audit"]
        assert isinstance(audit, dict)
        audit["steps"] = [{"run": f"{MAKE_LAUNCHER} audit"}]
    path = _write(tmp_path, workflow)

    with pytest.raises(WorkflowError, match=r"dependency-review|run_make.py license-check"):
        validate_workflow(path, tmp_path.resolve(), set(), set())


@pytest.mark.parametrize(
    ("case", "message"),
    [
        ("missing aggregate dependency", "dependency graph is incomplete"),
        ("skippable aggregate", "must use if: always"),
        ("conditional evaluator", "evaluator must be unconditional"),
        ("conditional mandatory step", "mandatory steps must be unconditional"),
        ("conditional mandatory job", "mandatory jobs must be unconditional"),
        (
            "dependency review pull request condition changed",
            "dependency-review pull-request condition differs",
        ),
        (
            "dependency review fallback condition changed",
            "dependency-review fallback condition differs",
        ),
        ("masked command", "error-masking construct"),
        ("direct make invocation", "Make gates must use.*run_make.py"),
        ("continue on error", "continue-on-error must be absent or literal false"),
        ("step continue on error", "continue-on-error must be absent or literal false"),
        ("unpinned action", "external actions require.*full 40-byte SHA"),
        ("missing permissions", "explicit workflow permissions are required"),
        ("write permissions", "workflow-level write permission is prohibited"),
        ("unknown top key", "unknown key"),
        ("secret expression", "secret expressions are prohibited"),
        ("missing trigger", "missing on trigger"),
        ("prohibited trigger", "pull_request_target is prohibited"),
        ("invalid trigger", "on must be a string, list, or mapping"),
        ("unknown permission", "unknown permission scope"),
        ("invalid permission level", "must be read, write, or none"),
        ("job write permission", "write permission is not explicitly allowlisted"),
        ("invalid job id", "invalid job id"),
        ("unknown job key", "unknown key"),
        ("job continue false allowed", "continue-on-error must be absent or literal false"),
        ("invalid timeout", "timeout-minutes must be between"),
        ("boolean timeout", "timeout-minutes must be between"),
        ("inherited secrets", "secrets: inherit is prohibited"),
        ("mixed reusable job", "reusable-workflow jobs cannot define steps"),
        ("unpinned reusable job", "external actions require.*full 40-byte SHA"),
        ("latest runner", "mutable latest runner labels are prohibited"),
        ("missing runs on", "normal jobs require runs-on and steps"),
        ("missing steps", "normal jobs require runs-on and steps"),
        ("empty steps", "steps must be a nonempty list"),
        ("unknown step key", "unknown key"),
        ("both uses and run", "exactly one of uses or run"),
        ("neither uses nor run", "exactly one of uses or run"),
        ("checkout persists credentials", "checkout must disable credential persistence"),
        ("dco synthetic merge ref", "range must end at the actual head SHA"),
        ("dco missing head binding", "range must bind base and actual head SHAs"),
        ("dco push checks only head", "push range must cover the complete pushed range"),
        ("dco push missing before binding", "push range must bind before and after SHAs"),
        ("conditional dco checkout", "mandatory steps must be unconditional"),
        ("dco shallow checkout", "checkout must fetch complete history"),
        ("duplicate needs", "duplicate needs dependencies"),
        ("unknown need", "needs unknown job"),
        ("dependency cycle", "dependency cycle"),
        ("unsupported aggregate trigger", "unsupported trigger"),
        ("aggregate path filter", "cannot use pull-request path filters"),
        ("aggregate write permission", "write permission is not explicitly allowlisted"),
        ("empty evaluator steps", "steps must be a nonempty list"),
        ("missing evaluator", "exactly one evaluator step"),
        ("multiple evaluators", "exactly one evaluator step"),
        ("malformed evaluator command", "evaluator command is malformed"),
        ("hardcoded aggregate result", "must use its exact needs-result binding"),
        ("swapped aggregate results", "must use its exact needs-result binding"),
        ("duplicate aggregate binding", "duplicate aggregate job binding"),
        ("unused aggregate environment", "evaluator environment differs"),
        ("extra aggregate binding", "unexpected aggregate job binding"),
        ("missing aggregate binding", "aggregate evaluator job list is incomplete"),
    ],
)
def test_workflow_validator_rejects_fail_open_mutations(
    tmp_path: Path,
    case: str,
    message: str,
) -> None:
    path = _write(tmp_path, _mutate(case))

    with pytest.raises(WorkflowError, match=message):
        validate_workflow(path, tmp_path.resolve(), set(), set())


@pytest.mark.parametrize("trigger", ["pull_request", ["pull_request"]])
def test_aggregate_accepts_string_and_list_trigger_forms(
    tmp_path: Path,
    trigger: object,
) -> None:
    workflow = _baseline()
    workflow["on"] = trigger
    path = _write(tmp_path, workflow)

    assert validate_workflow(path, tmp_path.resolve(), set(), set()) is True


def test_optional_job_and_allowlisted_write_permissions_are_explicit(
    tmp_path: Path,
) -> None:
    workflow = _baseline()
    jobs = workflow["jobs"]
    assert isinstance(jobs, dict)
    jobs["codeql"] = {
        "permissions": {"security-events": "write"},
        "runs-on": "ubuntu-24.04",
        "steps": [{"run": "python -m pytest"}],
    }
    path = _write(tmp_path, workflow)

    assert validate_workflow(
        path,
        tmp_path.resolve(),
        {"codeql"},
        {("codeql", "security-events")},
    )

    with pytest.raises(WorkflowError, match=r"optional job.*not found"):
        validate_workflow(
            path,
            tmp_path.resolve(),
            {"absent"},
            {("codeql", "security-events")},
        )


def test_workflow_path_must_be_inside_repository(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    path = _write(tmp_path, _baseline())

    with pytest.raises(WorkflowError, match="escapes the repository root"):
        validate_workflow(path, repo.resolve(), set(), set())


def test_workflow_main_requires_exactly_one_aggregate(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = _write(tmp_path, _baseline())
    assert main(["--repo-root", str(tmp_path), "--require-aggregate", str(path)]) == 0
    assert "1 workflow(s) passed" in capsys.readouterr().out

    nonaggregate = _baseline()
    jobs = nonaggregate["jobs"]
    assert isinstance(jobs, dict)
    jobs.pop("required-ci")
    path.write_text(yaml.safe_dump(nonaggregate, sort_keys=False), encoding="utf-8")
    with pytest.raises(SystemExit) as caught:
        main(["--repo-root", str(tmp_path), "--require-aggregate", str(path)])
    assert caught.value.code == 1


def test_workflow_discovery_rejects_symlinks_and_non_workflow_files(tmp_path: Path) -> None:
    target = tmp_path / "target.yml"
    target.write_text("name: target\n", encoding="utf-8")
    symlink = tmp_path / "linked.yml"
    symlink.symlink_to(target)

    with pytest.raises(WorkflowError, match="symlink workflows are prohibited"):
        workflow_validation._discover([symlink])

    text_file = tmp_path / "notes.txt"
    text_file.write_text("not a workflow\n", encoding="utf-8")
    with pytest.raises(WorkflowError, match=r"workflow must use \.yml or \.yaml"):
        workflow_validation._discover([text_file])


def test_workflow_discovery_scans_directories_and_fails_closed_on_empty_inputs(
    tmp_path: Path,
) -> None:
    workflows = tmp_path / "workflows"
    workflows.mkdir()
    ignored = workflows / "README.txt"
    ignored.write_text("not selected\n", encoding="utf-8")

    with pytest.raises(WorkflowError, match="no workflow files selected"):
        workflow_validation._discover([workflows])

    selected = workflows / "ci.yaml"
    selected.write_text("name: selected\n", encoding="utf-8")
    assert workflow_validation._discover([workflows]) == (selected,)

    with pytest.raises(WorkflowError, match="workflow input does not exist"):
        workflow_validation._discover([tmp_path / "missing"])


def test_workflow_discovery_rejects_nested_workflow_symlinks(tmp_path: Path) -> None:
    workflows = tmp_path / "workflows"
    workflows.mkdir()
    target = tmp_path / "target.yml"
    target.write_text("name: target\n", encoding="utf-8")
    (workflows / "linked.yml").symlink_to(target)

    with pytest.raises(WorkflowError, match="symlink workflows are prohibited"):
        workflow_validation._discover([workflows])


def test_workflow_string_walk_ignores_non_string_mapping_keys() -> None:
    assert tuple(workflow_validation._walk_strings({1: ["value"]})) == ("value",)


def test_workflow_action_references_cover_local_and_container_trust_boundaries(
    tmp_path: Path,
) -> None:
    local_action = tmp_path / "action.yml"
    local_action.write_text("name: local\n", encoding="utf-8")

    workflow_validation._validate_uses("./action.yml", "local", tmp_path)
    workflow_validation._validate_uses(
        "docker://example.invalid/tool@sha256:" + "a" * 64,
        "container",
        tmp_path,
    )

    with pytest.raises(WorkflowError, match="uses must be a string"):
        workflow_validation._validate_uses(1, "invalid", tmp_path)
    with pytest.raises(WorkflowError, match="local action escapes or is missing"):
        workflow_validation._validate_uses("./missing.yml", "missing", tmp_path)
    with pytest.raises(WorkflowError, match="immutable sha256 digest"):
        workflow_validation._validate_uses("docker://example.invalid/tool:latest", "tag", tmp_path)


def test_workflow_validator_accepts_literal_false_error_controls_and_bounded_timeout(
    tmp_path: Path,
) -> None:
    workflow = _baseline()
    jobs = workflow["jobs"]
    assert isinstance(jobs, dict)
    quality = jobs["quality"]
    assert isinstance(quality, dict)
    quality["continue-on-error"] = False
    quality["timeout-minutes"] = 30
    steps = quality["steps"]
    assert isinstance(steps, list)
    run_step = steps[1]
    assert isinstance(run_step, dict)
    run_step["continue-on-error"] = False

    path = _write(tmp_path, workflow)
    assert validate_workflow(path, tmp_path.resolve(), set(), set()) is True


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("empty run", "run must be a nonempty string"),
        ("invalid needs item", "needs must be a job name or list"),
        ("unknown aggregate policy job", "no reviewed result binding"),
        ("wrong evaluator executable", "must invoke the reviewed script exactly"),
        ("incomplete evaluator pair", "evaluator command is incomplete"),
        ("wrong evaluator flags", "must use exact expected-job/result pairs"),
        ("non-string aggregate condition", "must use if: always"),
        ("unreviewed aggregate permissions", "permissions must be empty or exactly contents"),
        ("empty jobs", "jobs must not be empty"),
        ("dependency action in wrong job", "dependency review must run in the dependency-review"),
        ("aggregate without pull request", "aggregate workflow must run on pull_request"),
    ],
)
def test_workflow_validator_rejects_additional_adversarial_shapes(
    tmp_path: Path,
    mutation: str,
    message: str,
) -> None:
    workflow = _baseline()
    jobs = workflow["jobs"]
    assert isinstance(jobs, dict)
    quality = jobs["quality"]
    aggregate = jobs["required-ci"]
    assert isinstance(quality, dict)
    assert isinstance(aggregate, dict)
    quality_steps = quality["steps"]
    aggregate_steps = aggregate["steps"]
    assert isinstance(quality_steps, list)
    assert isinstance(aggregate_steps, list)
    evaluator = aggregate_steps[0]
    assert isinstance(evaluator, dict)

    if mutation == "empty run":
        run_step = quality_steps[1]
        assert isinstance(run_step, dict)
        run_step["run"] = ""
    elif mutation == "invalid needs item":
        aggregate["needs"] = ["quality", 1]
    elif mutation == "unknown aggregate policy job":
        jobs["unreviewed"] = {
            "runs-on": "ubuntu-24.04",
            "steps": [{"run": "python -m pytest"}],
        }
        needs = aggregate["needs"]
        assert isinstance(needs, list)
        needs.append("unreviewed")
    elif mutation == "wrong evaluator executable":
        evaluator["run"] = "python scripts/required_ci.py.extra"
    elif mutation == "incomplete evaluator pair":
        evaluator["run"] = f"{_aggregate_command()} --expected-job"
    elif mutation == "wrong evaluator flags":
        evaluator["run"] = _aggregate_command().replace("--result", "--value", 1)
    elif mutation == "non-string aggregate condition":
        aggregate["if"] = True
    elif mutation == "unreviewed aggregate permissions":
        aggregate["permissions"] = {"contents": "none"}
    elif mutation == "empty jobs":
        workflow["jobs"] = {}
    elif mutation == "dependency action in wrong job":
        quality_steps.append(
            {
                "uses": PINNED_DEPENDENCY_REVIEW,
                "with": dict(DEPENDENCY_REVIEW_SETTINGS),
            }
        )
    elif mutation == "aggregate without pull request":
        workflow["on"] = {"push": None}
    else:  # pragma: no cover - test-table programming error
        raise AssertionError(mutation)

    path = _write(tmp_path, workflow)
    with pytest.raises(WorkflowError, match=message):
        validate_workflow(path, tmp_path.resolve(), set(), set())


def test_aggregate_rejects_optional_dependency_still_wired_as_mandatory(tmp_path: Path) -> None:
    path = _write(tmp_path, _baseline())

    with pytest.raises(WorkflowError, match=r"unexpected test"):
        validate_workflow(path, tmp_path.resolve(), {"test"}, set())


def test_aggregate_rejects_an_empty_mandatory_policy_set(tmp_path: Path) -> None:
    jobs = _baseline()["jobs"]
    assert isinstance(jobs, dict)
    graph = {
        job_id: tuple(job.get("needs", ())) if isinstance(job, dict) else ()
        for job_id, job in jobs.items()
    }

    with pytest.raises(WorkflowError, match="has no mandatory dependencies"):
        workflow_validation._validate_aggregate(
            tmp_path / "ci.yml",
            jobs,
            graph,
            set(jobs) - {"required-ci"},
        )


def test_aggregate_rejects_non_list_evaluator_steps(tmp_path: Path) -> None:
    jobs = _baseline()["jobs"]
    assert isinstance(jobs, dict)
    aggregate = jobs["required-ci"]
    assert isinstance(aggregate, dict)
    aggregate["steps"] = "python scripts/required_ci.py"
    graph = {
        job_id: tuple(job.get("needs", ())) if isinstance(job, dict) else ()
        for job_id, job in jobs.items()
    }

    with pytest.raises(WorkflowError, match="must contain evaluator steps"):
        workflow_validation._validate_aggregate(tmp_path / "ci.yml", jobs, graph, set())


def test_specialized_jobs_reject_malformed_step_collections(tmp_path: Path) -> None:
    jobs = _baseline()["jobs"]
    assert isinstance(jobs, dict)
    dependency_review = jobs["dependency-review"]
    dco = jobs["dco"]
    assert isinstance(dependency_review, dict)
    assert isinstance(dco, dict)
    dependency_review["steps"] = [{"run": "test -f uv.lock"}]
    with pytest.raises(WorkflowError, match="exact hosted and non-pull-request branches"):
        workflow_validation._validate_dependency_review_job(tmp_path / "ci.yml", jobs)

    dependency_review["steps"] = "not-a-list"
    dco["steps"] = "not-a-list"

    with pytest.raises(WorkflowError, match="dependency-review steps must be a list"):
        workflow_validation._validate_dependency_review_job(tmp_path / "ci.yml", jobs)
    with pytest.raises(WorkflowError, match="dco steps must be a list"):
        workflow_validation._validate_dco_job(tmp_path / "ci.yml", jobs)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("checkout count", "exactly one checkout step"),
        ("dco check count", "requires exact pull-request, push, and audit checks"),
        ("event condition", "event conditions differ from policy"),
        ("other environment", "schedule/dispatch audit range differs from policy"),
    ],
)
def test_dco_job_rejects_incomplete_or_ambiguous_control_paths(
    tmp_path: Path,
    mutation: str,
    message: str,
) -> None:
    jobs = _baseline()["jobs"]
    assert isinstance(jobs, dict)
    dco = jobs["dco"]
    assert isinstance(dco, dict)
    steps = dco["steps"]
    assert isinstance(steps, list)

    if mutation == "checkout count":
        steps.pop(0)
    elif mutation == "dco check count":
        steps.pop()
    elif mutation == "event condition":
        push_step = steps[2]
        assert isinstance(push_step, dict)
        push_step["if"] = "github.event_name == 'workflow_dispatch'"
    elif mutation == "other environment":
        other_step = steps[3]
        assert isinstance(other_step, dict)
        other_step["env"] = {}
    else:  # pragma: no cover - test-table programming error
        raise AssertionError(mutation)

    with pytest.raises(WorkflowError, match=message):
        workflow_validation._validate_dco_job(tmp_path / "ci.yml", jobs)


def test_nonaggregate_workflow_and_safe_pull_request_filter_are_accepted(tmp_path: Path) -> None:
    nonaggregate = {
        "name": "Single gate",
        "on": "push",
        "permissions": {"contents": "read"},
        "jobs": {
            "quality": {
                "runs-on": "ubuntu-24.04",
                "steps": [{"run": "python -m pytest"}],
            }
        },
    }
    path = _write(tmp_path, nonaggregate)
    assert validate_workflow(path, tmp_path.resolve(), set(), set()) is False

    aggregate = _baseline()
    aggregate["on"] = {"pull_request": {"types": ["opened"]}}
    path = _write(tmp_path, aggregate)
    assert validate_workflow(path, tmp_path.resolve(), set(), set()) is True


@pytest.mark.parametrize(
    ("value", "message"),
    [
        ("missing-separator", "must use JOB:SCOPE"),
        ("invalid job:contents", "invalid allowlisted job id"),
        ("quality:unknown", "invalid allowlisted permission scope"),
    ],
)
def test_write_allowlist_cli_rejects_malformed_scopes(value: str, message: str) -> None:
    with pytest.raises(workflow_validation.argparse.ArgumentTypeError, match=message):
        workflow_validation._job_scope(value)


def test_write_allowlist_cli_accepts_a_known_job_and_scope() -> None:
    assert workflow_validation._job_scope("codeql:security-events") == (
        "codeql",
        "security-events",
    )


def test_workflow_script_entrypoint_validates_a_complete_workflow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = _write(tmp_path, _baseline())
    monkeypatch.syspath_prepend(str(Path(workflow_validation.__file__).parent))
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "validate_workflows.py",
            "--repo-root",
            str(tmp_path),
            "--require-aggregate",
            str(path),
        ],
    )

    with pytest.raises(SystemExit) as caught:
        runpy.run_path(workflow_validation.__file__, run_name="__main__")
    assert caught.value.code == 0
