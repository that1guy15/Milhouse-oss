#!/usr/bin/env python3
"""Validate GitHub Actions workflows against Milhouse's fail-closed policy."""

from __future__ import annotations

import argparse
import re
import shlex
import sys
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import NoReturn, cast

if __package__:
    from .milhouse_tools.strict_data import DataError, load_data, require_mapping
else:
    from milhouse_tools.strict_data import (  # type: ignore[import-not-found, no-redef]
        DataError,
        load_data,
        require_mapping,
    )


ACTION_REFERENCE = re.compile(
    r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.\-/]+)?@[0-9a-f]{40}$"
)
DOCKER_REFERENCE = re.compile(r"^docker://[^\s@]+@sha256:[0-9a-f]{64}$")
DEPENDENCY_REVIEW_ACTION = "actions/dependency-review-action@"
MAKE_LAUNCHER = "./scripts/run_make.py"
DCO_PULL_REQUEST_CONDITION = "github.event_name == 'pull_request'"
DCO_PUSH_CONDITION = "github.event_name == 'push'"
DCO_OTHER_CONDITION = "github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'"
DCO_PR_COMMAND = 'python scripts/check_dco.py --range "${BASE_SHA}..${HEAD_SHA}"'
DCO_PUSH_COMMAND = 'python scripts/check_dco.py --range "${BEFORE_SHA}..${AFTER_SHA}"'
DCO_OTHER_COMMAND = 'python scripts/check_dco.py --range "HEAD^..HEAD"'
DEPENDENCY_REVIEW_PR_CONDITION = "github.event_name == 'pull_request'"
DEPENDENCY_REVIEW_OTHER_CONDITION = "github.event_name != 'pull_request'"
DEPENDENCY_REVIEW_FALLBACK_COMMAND = "test -f uv.lock"
DEPENDENCY_REVIEW_SETTINGS = {
    "allow-dependencies-licenses": "pkg:pypi/chardet, pkg:pypi/docutils",
    "deny-licenses": (
        "AGPL-1.0, AGPL-1.0-only, AGPL-1.0-or-later, "
        "AGPL-3.0, AGPL-3.0-only, AGPL-3.0-or-later, "
        "GPL-1.0, GPL-1.0-only, GPL-1.0-or-later, "
        "GPL-2.0, GPL-2.0-only, GPL-2.0-or-later, "
        "GPL-3.0, GPL-3.0-only, GPL-3.0-or-later, "
        "LGPL-2.0, LGPL-2.0-only, LGPL-2.0-or-later, "
        "LGPL-2.1, LGPL-2.1-only, LGPL-2.1-or-later, "
        "LGPL-3.0, LGPL-3.0-only, LGPL-3.0-or-later"
    ),
    "fail-on-severity": "moderate",
    "license-check": True,
}
SECRET_EXPRESSION = re.compile(r"\$\{\{[^}]*\bsecrets\s*\.", re.IGNORECASE)
ERROR_MASKING = (
    re.compile(r"\|\|"),
    re.compile(r"&&\s*(?:true|:)\b"),
    re.compile(r";\s*(?:true|:)\s*(?:$|[;\n])"),
    re.compile(r"\bset\s+\+e\b"),
    re.compile(r"\bexit\s+0\b"),
    re.compile(r"\bif\s+!\s+"),
)
DIRECT_MAKE_INVOCATION = re.compile(r"(?:^|[\s;&|('`\"])(?:[A-Za-z0-9_.-]+/)*(?:g?make)(?=\s|$)")
AGGREGATE_RESULT_ENVIRONMENT = {
    "artifact-smoke": ("ARTIFACT_SMOKE_RESULT", "${{ needs.artifact-smoke.result }}"),
    "audit": ("AUDIT_RESULT", "${{ needs.audit.result }}"),
    "codeql": ("CODEQL_RESULT", "${{ needs.codeql.result }}"),
    "compatibility": ("COMPATIBILITY_RESULT", "${{ needs.compatibility.result }}"),
    "dco": ("DCO_RESULT", "${{ needs.dco.result }}"),
    "dependency-review": (
        "DEPENDENCY_REVIEW_RESULT",
        "${{ needs.dependency-review.result }}",
    ),
    "gitleaks": ("GITLEAKS_RESULT", "${{ needs.gitleaks.result }}"),
    "package": ("PACKAGE_RESULT", "${{ needs.package.result }}"),
    "quality": ("QUALITY_RESULT", "${{ needs.quality.result }}"),
    "test": ("TEST_RESULT", "${{ needs.test.result }}"),
}
PERMISSION_SCOPES = {
    "actions",
    "attestations",
    "checks",
    "contents",
    "deployments",
    "discussions",
    "id-token",
    "issues",
    "models",
    "packages",
    "pages",
    "pull-requests",
    "security-events",
    "statuses",
}
TOP_LEVEL_KEYS = {
    "concurrency",
    "defaults",
    "env",
    "jobs",
    "name",
    "on",
    "permissions",
    "run-name",
}
JOB_KEYS = {
    "concurrency",
    "container",
    "continue-on-error",
    "defaults",
    "environment",
    "env",
    "if",
    "name",
    "needs",
    "outputs",
    "permissions",
    "runs-on",
    "secrets",
    "services",
    "steps",
    "strategy",
    "timeout-minutes",
    "uses",
    "with",
}
STEP_KEYS = {
    "continue-on-error",
    "env",
    "id",
    "if",
    "name",
    "run",
    "shell",
    "timeout-minutes",
    "uses",
    "with",
    "working-directory",
}
ALLOWED_ENVIRONMENT = {
    "workflow": {"UV_VERSION": "0.11.29"},
    "job": {},
    "step": {
        **{variable: expression for variable, expression in AGGREGATE_RESULT_ENVIRONMENT.values()},
        "AFTER_SHA": "${{ github.event.after }}",
        "BASE_SHA": "${{ github.event.pull_request.base.sha }}",
        "BEFORE_SHA": "${{ github.event.before }}",
        "HEAD_SHA": "${{ github.event.pull_request.head.sha }}",
    },
}


class WorkflowError(ValueError):
    """Raised when workflow policy is incomplete or fail-open."""


def fail(message: str) -> NoReturn:
    print(f"workflow-validation: {message}", file=sys.stderr)
    raise SystemExit(1)


def _discover(inputs: Iterable[Path]) -> tuple[Path, ...]:
    paths: set[Path] = set()
    for input_path in inputs:
        if input_path.is_symlink():
            raise WorkflowError(f"{input_path}: symlink workflows are prohibited")
        if input_path.is_file():
            if input_path.suffix.lower() not in {".yaml", ".yml"}:
                raise WorkflowError(f"{input_path}: workflow must use .yml or .yaml")
            paths.add(input_path)
        elif input_path.is_dir():
            for candidate in input_path.rglob("*"):
                if candidate.is_symlink() and candidate.suffix.lower() in {".yaml", ".yml"}:
                    raise WorkflowError(f"{candidate}: symlink workflows are prohibited")
                if candidate.is_file() and candidate.suffix.lower() in {".yaml", ".yml"}:
                    paths.add(candidate)
        else:
            raise WorkflowError(f"{input_path}: workflow input does not exist")
    if not paths:
        raise WorkflowError("no workflow files selected")
    return tuple(sorted(paths))


def _reject_unknown_keys(mapping: dict[str, object], allowed: set[str], label: str) -> None:
    unknown = sorted(set(mapping) - allowed)
    if unknown:
        raise WorkflowError(f"{label}: unknown key(s): {', '.join(unknown)}")


def _validate_environment(raw: object, label: str, scope: str) -> None:
    environment = require_mapping(raw, label)
    allowed = ALLOWED_ENVIRONMENT[scope]
    for key, value in environment.items():
        if key not in allowed:
            raise WorkflowError(f"{label}: environment key {key!r} is not allowlisted")
        if value != allowed[key]:
            raise WorkflowError(f"{label}: environment key {key!r} has an unreviewed value")


def _walk_strings(value: object) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, child in value.items():
            if isinstance(key, str):
                yield key
            yield from _walk_strings(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_strings(child)


def _validate_permissions(
    raw: object,
    label: str,
    *,
    top_level: bool,
    job_id: str | None = None,
    allowed_writes: set[tuple[str, str]],
) -> dict[str, str]:
    permissions = require_mapping(raw, label)
    result: dict[str, str] = {}
    for scope, raw_level in permissions.items():
        if scope not in PERMISSION_SCOPES:
            raise WorkflowError(f"{label}: unknown permission scope {scope!r}")
        if not isinstance(raw_level, str) or raw_level not in {"read", "write", "none"}:
            raise WorkflowError(f"{label}.{scope} must be read, write, or none")
        if raw_level == "write":
            if top_level:
                raise WorkflowError(
                    f"{label}.{scope}: workflow-level write permission is prohibited"
                )
            if job_id is None or (job_id, scope) not in allowed_writes:
                raise WorkflowError(
                    f"{label}.{scope}: write permission is not explicitly allowlisted"
                )
        result[scope] = raw_level
    return result


def _validate_uses(value: object, label: str, repo_root: Path) -> None:
    if not isinstance(value, str):
        raise WorkflowError(f"{label}: uses must be a string")
    if value.startswith("./"):
        target = repo_root / value[2:]
        try:
            resolved = target.resolve(strict=True)
            resolved.relative_to(repo_root)
        except (OSError, ValueError) as exc:
            raise WorkflowError(f"{label}: local action escapes or is missing") from exc
        return
    if value.startswith("docker://"):
        if not DOCKER_REFERENCE.fullmatch(value):
            raise WorkflowError(f"{label}: container actions require an immutable sha256 digest")
        return
    if not ACTION_REFERENCE.fullmatch(value):
        raise WorkflowError(f"{label}: external actions require a lowercase full 40-byte SHA")


def _continue_on_error(value: object, label: str) -> None:
    if value is not False:
        raise WorkflowError(f"{label}: continue-on-error must be absent or literal false")


def _validate_run(value: object, label: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise WorkflowError(f"{label}: run must be a nonempty string")
    for pattern in ERROR_MASKING:
        if pattern.search(value):
            raise WorkflowError(f"{label}: shell error-masking construct is prohibited")
    if DIRECT_MAKE_INVOCATION.search(value):
        raise WorkflowError(f"{label}: Make gates must use {MAKE_LAUNCHER}")


def _needs(value: object, label: str) -> tuple[str, ...]:
    if isinstance(value, str):
        result: tuple[str, ...] = (value,)
    elif isinstance(value, list) and all(isinstance(item, str) for item in value):
        result = tuple(cast(list[str], value))
    else:
        raise WorkflowError(f"{label}: needs must be a job name or list of job names")
    if len(set(result)) != len(result):
        raise WorkflowError(f"{label}: duplicate needs dependencies are prohibited")
    return result


def _validate_graph(jobs: dict[str, object], path: Path) -> dict[str, tuple[str, ...]]:
    graph: dict[str, tuple[str, ...]] = {}
    for job_id, raw_job in jobs.items():
        job = require_mapping(raw_job, f"{path}:{job_id}")
        dependencies = _needs(job["needs"], f"{path}:{job_id}.needs") if "needs" in job else ()
        missing = sorted(set(dependencies) - jobs.keys())
        if missing:
            raise WorkflowError(f"{path}:{job_id}: needs unknown job(s): {', '.join(missing)}")
        graph[job_id] = dependencies

    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(job_id: str) -> None:
        if job_id in visiting:
            raise WorkflowError(f"{path}: dependency cycle includes {job_id!r}")
        if job_id in visited:
            return
        visiting.add(job_id)
        for dependency in graph[job_id]:
            visit(dependency)
        visiting.remove(job_id)
        visited.add(job_id)

    for job_id in graph:
        visit(job_id)
    return graph


def _trigger_names(raw: object, path: Path) -> tuple[set[str], dict[str, object] | None]:
    if isinstance(raw, str):
        return {raw}, None
    if isinstance(raw, list) and all(isinstance(item, str) for item in raw):
        return set(cast(list[str], raw)), None
    if isinstance(raw, dict):
        mapping = require_mapping(raw, f"{path}:on")
        return set(mapping), mapping
    raise WorkflowError(f"{path}:on must be a string, list, or mapping")


def _validate_aggregate_evaluator(
    path: Path,
    evaluator: dict[str, object],
    expected: set[str],
) -> None:
    """Require exact job-to-environment result bindings for the aggregate."""

    unknown_policy = sorted(expected - AGGREGATE_RESULT_ENVIRONMENT.keys())
    if unknown_policy:
        raise WorkflowError(
            f"{path}:required-ci has no reviewed result binding for {', '.join(unknown_policy)}"
        )
    expected_environment = {
        AGGREGATE_RESULT_ENVIRONMENT[job][0]: AGGREGATE_RESULT_ENVIRONMENT[job][1]
        for job in expected
    }
    environment = require_mapping(evaluator.get("env"), f"{path}:required-ci evaluator environment")
    if environment != expected_environment:
        raise WorkflowError(f"{path}:required-ci evaluator environment differs from exact policy")

    run = cast(str, evaluator["run"])
    try:
        tokens = shlex.split(run)
    except ValueError as exc:
        raise WorkflowError(f"{path}:required-ci evaluator command is malformed") from exc
    if tokens[:2] != ["python", "scripts/required_ci.py"]:
        raise WorkflowError(f"{path}:required-ci evaluator must invoke the reviewed script exactly")

    bindings: dict[str, str] = {}
    index = 2
    while index < len(tokens):
        if index + 3 >= len(tokens):
            raise WorkflowError(f"{path}:required-ci evaluator command is incomplete")
        if tokens[index] != "--expected-job" or tokens[index + 2] != "--result":
            raise WorkflowError(
                f"{path}:required-ci evaluator must use exact expected-job/result pairs"
            )
        job = tokens[index + 1]
        result = tokens[index + 3]
        if job in bindings:
            raise WorkflowError(f"{path}:required-ci duplicate aggregate job binding {job!r}")
        if job not in expected:
            raise WorkflowError(f"{path}:required-ci unexpected aggregate job binding {job!r}")
        variable = AGGREGATE_RESULT_ENVIRONMENT[job][0]
        required_result = f"{job}=${{{variable}}}"
        if result != required_result:
            raise WorkflowError(
                f"{path}:required-ci job {job!r} must use its exact needs-result binding"
            )
        bindings[job] = result
        index += 4

    missing = sorted(expected - bindings.keys())
    if missing:
        raise WorkflowError(
            f"{path}:required-ci aggregate evaluator job list is incomplete "
            f"(missing {', '.join(missing)})"
        )


def _validate_aggregate(
    path: Path,
    jobs: dict[str, object],
    graph: dict[str, tuple[str, ...]],
    optional_jobs: set[str],
) -> None:
    aggregate = require_mapping(jobs["required-ci"], f"{path}:required-ci")
    expected = set(jobs) - {"required-ci"} - optional_jobs
    if not expected:
        raise WorkflowError(f"{path}: required-ci has no mandatory dependencies")
    observed = set(graph["required-ci"])
    if observed != expected:
        missing = sorted(expected - observed)
        extra = sorted(observed - expected)
        details: list[str] = []
        if missing:
            details.append(f"missing {', '.join(missing)}")
        if extra:
            details.append(f"unexpected {', '.join(extra)}")
        raise WorkflowError(
            f"{path}: required-ci dependency graph is incomplete ({'; '.join(details)})"
        )

    condition = aggregate.get("if")
    if not isinstance(condition, str):
        raise WorkflowError(f"{path}:required-ci must use if: always()")
    normalized = condition.replace("${{", "").replace("}}", "").strip()
    if normalized != "always()":
        raise WorkflowError(f"{path}:required-ci must use if: always()")

    permissions = aggregate.get("permissions")
    if permissions not in (None, {}, {"contents": "read"}):
        raise WorkflowError(
            f"{path}:required-ci permissions must be empty or exactly contents: read"
        )
    steps = aggregate.get("steps")
    if not isinstance(steps, list) or not steps:
        raise WorkflowError(f"{path}:required-ci must contain evaluator steps")
    evaluator_steps: list[dict[str, object]] = []
    for index, raw_step in enumerate(steps, 1):
        step = require_mapping(raw_step, f"{path}:required-ci.steps[{index}]")
        run = step.get("run")
        if isinstance(run, str) and "scripts/required_ci.py" in run:
            if "if" in step:
                raise WorkflowError(f"{path}:required-ci evaluator must be unconditional")
            evaluator_steps.append(step)
    if len(evaluator_steps) != 1:
        raise WorkflowError(f"{path}:required-ci must contain exactly one evaluator step")
    _validate_aggregate_evaluator(path, evaluator_steps[0], expected)


def _reject_unreviewed_conditioned_steps(
    path: Path,
    job_id: str,
    steps: list[dict[str, object]],
    reviewed: Sequence[dict[str, object]],
) -> None:
    for step in steps:
        if "if" in step and not any(step is candidate for candidate in reviewed):
            raise WorkflowError(
                f"{path}:{job_id}: mandatory steps must be unconditional except exact "
                "reviewed event branches"
            )


def _validate_dependency_review_job(path: Path, jobs: dict[str, object]) -> None:
    """Require complementary hosted and non-PR dependency-review branches."""

    job = require_mapping(jobs["dependency-review"], f"{path}:dependency-review")
    raw_steps = job.get("steps")
    if not isinstance(raw_steps, list):
        raise WorkflowError(f"{path}:dependency-review steps must be a list")
    steps = [require_mapping(step, f"{path}:dependency-review step") for step in raw_steps]
    action_steps = [
        step for step in steps if str(step.get("uses", "")).startswith(DEPENDENCY_REVIEW_ACTION)
    ]
    fallback_steps = [
        step
        for step in steps
        if str(step.get("run", "")).strip() == DEPENDENCY_REVIEW_FALLBACK_COMMAND
    ]
    if len(action_steps) != 1 or len(fallback_steps) != 1:
        raise WorkflowError(
            f"{path}:dependency-review requires exact hosted and non-pull-request branches"
        )
    action_step = action_steps[0]
    fallback_step = fallback_steps[0]
    if action_step.get("if") != DEPENDENCY_REVIEW_PR_CONDITION:
        raise WorkflowError(f"{path}:dependency-review pull-request condition differs from policy")
    if fallback_step.get("if") != DEPENDENCY_REVIEW_OTHER_CONDITION:
        raise WorkflowError(f"{path}:dependency-review fallback condition differs from policy")
    _reject_unreviewed_conditioned_steps(
        path,
        "dependency-review",
        steps,
        (action_step, fallback_step),
    )


def _validate_dco_job(path: Path, jobs: dict[str, object]) -> None:
    """Require exact PR, complete-push, and non-push DCO ranges."""

    job = require_mapping(jobs["dco"], f"{path}:dco")
    raw_steps = job.get("steps")
    if not isinstance(raw_steps, list):
        raise WorkflowError(f"{path}:dco steps must be a list")
    steps = [require_mapping(step, f"{path}:dco step") for step in raw_steps]
    checkouts = [
        step for step in steps if str(step.get("uses", "")).startswith("actions/checkout@")
    ]
    if len(checkouts) != 1:
        raise WorkflowError(f"{path}:dco requires exactly one checkout step")
    checkout_options = require_mapping(checkouts[0].get("with"), f"{path}:dco checkout.with")
    if checkout_options.get("fetch-depth") not in {0, "0"}:
        raise WorkflowError(f"{path}:dco checkout must fetch complete history")

    dco_steps = [step for step in steps if "scripts/check_dco.py" in str(step.get("run", ""))]
    if len(dco_steps) != 3:
        raise WorkflowError(f"{path}:dco requires exact pull-request, push, and audit checks")
    pull_request_steps = [
        step for step in dco_steps if step.get("if") == DCO_PULL_REQUEST_CONDITION
    ]
    push_steps = [step for step in dco_steps if step.get("if") == DCO_PUSH_CONDITION]
    other_steps = [step for step in dco_steps if step.get("if") == DCO_OTHER_CONDITION]
    if len(pull_request_steps) != 1 or len(push_steps) != 1 or len(other_steps) != 1:
        raise WorkflowError(f"{path}:dco event conditions differ from policy")
    pull_request_step = pull_request_steps[0]
    push_step = push_steps[0]
    other_step = other_steps[0]
    _reject_unreviewed_conditioned_steps(
        path,
        "dco",
        steps,
        (pull_request_step, push_step, other_step),
    )
    expected_pull_request_environment = {
        "BASE_SHA": "${{ github.event.pull_request.base.sha }}",
        "HEAD_SHA": "${{ github.event.pull_request.head.sha }}",
    }
    if pull_request_step.get("env") != expected_pull_request_environment:
        raise WorkflowError(f"{path}:dco pull-request range must bind base and actual head SHAs")
    if pull_request_step.get("run") != DCO_PR_COMMAND:
        raise WorkflowError(f"{path}:dco pull-request range must end at the actual head SHA")
    expected_push_environment = {
        "AFTER_SHA": "${{ github.event.after }}",
        "BEFORE_SHA": "${{ github.event.before }}",
    }
    if push_step.get("env") != expected_push_environment:
        raise WorkflowError(f"{path}:dco push range must bind before and after SHAs")
    if push_step.get("run") != DCO_PUSH_COMMAND:
        raise WorkflowError(f"{path}:dco push range must cover the complete pushed range")
    if "env" in other_step or other_step.get("run") != DCO_OTHER_COMMAND:
        raise WorkflowError(f"{path}:dco schedule/dispatch audit range differs from policy")


def validate_workflow(
    path: Path,
    repo_root: Path,
    optional_jobs: set[str],
    allowed_writes: set[tuple[str, str]],
) -> bool:
    """Validate one workflow and return whether it defines required-ci."""

    try:
        path.resolve(strict=True).relative_to(repo_root)
    except (OSError, ValueError) as exc:
        raise WorkflowError(f"{path}: workflow escapes the repository root") from exc
    try:
        workflow = require_mapping(load_data(path), str(path))
    except DataError as exc:
        raise WorkflowError(f"{path}: {exc}") from exc
    _reject_unknown_keys(workflow, TOP_LEVEL_KEYS, str(path))
    for string in _walk_strings(workflow):
        if SECRET_EXPRESSION.search(string):
            raise WorkflowError(f"{path}: secret expressions are prohibited in repository CI")
    if "env" in workflow:
        _validate_environment(workflow["env"], f"{path}:env", "workflow")
    if "on" not in workflow:
        raise WorkflowError(f"{path}: missing on trigger")
    trigger_names, trigger_mapping = _trigger_names(workflow["on"], path)
    if "pull_request_target" in trigger_names:
        raise WorkflowError(f"{path}: pull_request_target is prohibited")
    if "permissions" not in workflow:
        raise WorkflowError(f"{path}: explicit workflow permissions are required")
    _validate_permissions(
        workflow["permissions"],
        f"{path}:permissions",
        top_level=True,
        allowed_writes=allowed_writes,
    )
    jobs = require_mapping(workflow.get("jobs"), f"{path}:jobs")
    if not jobs:
        raise WorkflowError(f"{path}:jobs must not be empty")

    dependency_review_steps = 0
    license_check_steps = 0
    for job_id, raw_job in jobs.items():
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]{0,99}", job_id):
            raise WorkflowError(f"{path}: invalid job id {job_id!r}")
        job = require_mapping(raw_job, f"{path}:{job_id}")
        _reject_unknown_keys(job, JOB_KEYS, f"{path}:{job_id}")
        if "if" in job and job_id != "required-ci":
            raise WorkflowError(f"{path}:{job_id}: mandatory jobs must be unconditional")
        if "env" in job:
            _validate_environment(job["env"], f"{path}:{job_id}.env", "job")
        if "continue-on-error" in job:
            _continue_on_error(job["continue-on-error"], f"{path}:{job_id}")
        if "permissions" in job:
            _validate_permissions(
                job["permissions"],
                f"{path}:{job_id}.permissions",
                top_level=False,
                job_id=job_id,
                allowed_writes=allowed_writes,
            )
        if job.get("secrets") == "inherit":
            raise WorkflowError(f"{path}:{job_id}: secrets: inherit is prohibited")
        if "timeout-minutes" in job:
            timeout = job["timeout-minutes"]
            if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 120:
                raise WorkflowError(f"{path}:{job_id}: timeout-minutes must be between 1 and 120")

        if "uses" in job:
            if "steps" in job or "runs-on" in job:
                raise WorkflowError(f"{path}:{job_id}: reusable-workflow jobs cannot define steps")
            _validate_uses(job["uses"], f"{path}:{job_id}.uses", repo_root)
            continue
        if "runs-on" not in job or "steps" not in job:
            raise WorkflowError(f"{path}:{job_id}: normal jobs require runs-on and steps")
        runner = job["runs-on"]
        if isinstance(runner, str) and runner.endswith("-latest"):
            raise WorkflowError(f"{path}:{job_id}: mutable latest runner labels are prohibited")
        steps = job["steps"]
        if not isinstance(steps, list) or not steps:
            raise WorkflowError(f"{path}:{job_id}: steps must be a nonempty list")
        for index, raw_step in enumerate(steps, 1):
            step = require_mapping(raw_step, f"{path}:{job_id}.steps[{index}]")
            _reject_unknown_keys(step, STEP_KEYS, f"{path}:{job_id}.steps[{index}]")
            if "env" in step:
                _validate_environment(step["env"], f"{path}:{job_id}.steps[{index}].env", "step")
            if "continue-on-error" in step:
                _continue_on_error(step["continue-on-error"], f"{path}:{job_id}.steps[{index}]")
            has_uses = "uses" in step
            has_run = "run" in step
            if has_uses == has_run:
                raise WorkflowError(
                    f"{path}:{job_id}.steps[{index}] must contain exactly one of uses or run"
                )
            if "if" in step and job_id not in {"dco", "dependency-review"}:
                is_aggregate_evaluator = (
                    job_id == "required-ci"
                    and has_run
                    and "scripts/required_ci.py" in str(step.get("run", ""))
                )
                if not is_aggregate_evaluator:
                    raise WorkflowError(
                        f"{path}:{job_id}.steps[{index}]: mandatory steps must be unconditional"
                    )
            if has_uses:
                _validate_uses(step["uses"], f"{path}:{job_id}.steps[{index}].uses", repo_root)
                uses = cast(str, step["uses"])
                if uses.startswith(DEPENDENCY_REVIEW_ACTION):
                    dependency_review_steps += 1
                    if job_id != "dependency-review":
                        raise WorkflowError(
                            f"{path}:{job_id}.steps[{index}]: dependency review must run in "
                            "the dependency-review job"
                        )
                    values = require_mapping(
                        step.get("with"), f"{path}:{job_id}.steps[{index}].with"
                    )
                    if values != DEPENDENCY_REVIEW_SETTINGS:
                        raise WorkflowError(
                            f"{path}:{job_id}.steps[{index}]: dependency-review settings "
                            "differ from the reviewed license and vulnerability policy"
                        )
                if uses.startswith("actions/checkout@"):
                    values = require_mapping(
                        step.get("with"), f"{path}:{job_id}.steps[{index}].with"
                    )
                    if values.get("persist-credentials") not in {False, "false"}:
                        raise WorkflowError(
                            f"{path}:{job_id}.steps[{index}]: checkout must disable "
                            "credential persistence"
                        )
            else:
                _validate_run(step["run"], f"{path}:{job_id}.steps[{index}].run")
                if (
                    job_id == "audit"
                    and cast(str, step["run"]).strip() == f"{MAKE_LAUNCHER} license-check"
                ):
                    license_check_steps += 1

    if "required-ci" in jobs:
        if dependency_review_steps != 1:
            raise WorkflowError(
                f"{path}: aggregate workflow requires exactly one hosted dependency-review step"
            )
        if license_check_steps != 1:
            raise WorkflowError(
                f"{path}: dependency-review license exceptions require exactly one "
                f"{MAKE_LAUNCHER} license-check step in the audit job"
            )
    if "dco" in jobs:
        _validate_dco_job(path, jobs)
    if "dependency-review" in jobs:
        _validate_dependency_review_job(path, jobs)

    graph = _validate_graph(jobs, path)
    has_aggregate = "required-ci" in jobs
    if has_aggregate:
        if "pull_request" not in trigger_names:
            raise WorkflowError(f"{path}: aggregate workflow must run on pull_request")
        unexpected_triggers = trigger_names - {
            "pull_request",
            "push",
            "schedule",
            "workflow_dispatch",
        }
        if unexpected_triggers:
            raise WorkflowError(
                f"{path}: aggregate workflow has unsupported trigger(s): "
                f"{', '.join(sorted(unexpected_triggers))}"
            )
        if trigger_mapping is not None:
            pull_request = trigger_mapping.get("pull_request")
            if isinstance(pull_request, dict):
                filters = require_mapping(pull_request, f"{path}:on.pull_request")
                if "paths" in filters or "paths-ignore" in filters:
                    raise WorkflowError(
                        f"{path}: required workflow cannot use pull-request path filters"
                    )
        unknown_optional = optional_jobs - jobs.keys()
        if unknown_optional:
            raise WorkflowError(
                f"{path}: optional job(s) not found: {', '.join(sorted(unknown_optional))}"
            )
        _validate_aggregate(path, jobs, graph, optional_jobs)
    return has_aggregate


def _job_scope(value: str) -> tuple[str, str]:
    if ":" not in value:
        raise argparse.ArgumentTypeError("write allowlists must use JOB:SCOPE")
    job, scope = value.split(":", 1)
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]{0,99}", job):
        raise argparse.ArgumentTypeError("invalid allowlisted job id")
    if scope not in PERMISSION_SCOPES:
        raise argparse.ArgumentTypeError("invalid allowlisted permission scope")
    return job, scope


def parse_args(arguments: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*", type=Path, default=[Path(".github/workflows")])
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--require-aggregate", action="store_true")
    parser.add_argument("--optional-job", action="append", default=[])
    parser.add_argument(
        "--allow-job-write",
        action="append",
        type=_job_scope,
        default=[("codeql", "security-events")],
        metavar="JOB:SCOPE",
    )
    return parser.parse_args(arguments)


def main(arguments: Sequence[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if arguments is None else arguments)
    try:
        repo_root = args.repo_root.resolve(strict=True)
        paths = _discover(args.paths)
        aggregates = 0
        for path in paths:
            aggregates += int(
                validate_workflow(
                    path,
                    repo_root,
                    set(args.optional_job),
                    set(args.allow_job_write),
                )
            )
        if args.require_aggregate and aggregates != 1:
            raise WorkflowError(f"expected exactly one required-ci aggregate, found {aggregates}")
    except (DataError, OSError, WorkflowError) as exc:
        fail(str(exc))
    print(f"workflow-validation: {len(paths)} workflow(s) passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
