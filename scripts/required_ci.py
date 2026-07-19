#!/usr/bin/env python3
"""Fail unless every explicitly expected required-CI result is exactly success."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Sequence
from typing import NoReturn, cast

JOB_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]{0,99}$")
KNOWN_RESULTS = {"success", "failure", "cancelled", "skipped"}


class ResultError(ValueError):
    """Raised for incomplete, inconsistent, or unsuccessful CI results."""


def fail(message: str) -> NoReturn:
    print(f"required-ci: {message}", file=sys.stderr)
    raise SystemExit(1)


def _job_name(value: str) -> str:
    if not JOB_NAME.fullmatch(value):
        raise argparse.ArgumentTypeError(
            "job names must use letters, digits, underscore, or hyphen"
        )
    return value


def evaluate(expected_values: Sequence[str], result_values: Sequence[str]) -> tuple[str, ...]:
    """Return sorted passing jobs, rejecting all other result graphs."""

    expected: set[str] = set()
    for job in expected_values:
        if job in expected:
            raise ResultError(f"duplicate expected job {job!r}")
        expected.add(job)
    if not expected:
        raise ResultError("at least one expected job is required")

    observed: dict[str, str] = {}
    for item in result_values:
        if "=" not in item:
            raise ResultError("results must use JOB=RESULT syntax")
        job, result = item.split("=", 1)
        if not JOB_NAME.fullmatch(job):
            raise ResultError(f"invalid result job name {job!r}")
        if job in observed:
            raise ResultError(f"duplicate result for job {job!r}")
        normalized = result.strip().lower()
        if normalized not in KNOWN_RESULTS:
            raise ResultError(f"job {job!r} has missing or unknown result {result!r}")
        observed[job] = normalized

    missing = sorted(expected - observed.keys())
    unknown = sorted(observed.keys() - expected)
    if missing:
        raise ResultError(f"missing result(s): {', '.join(missing)}")
    if unknown:
        raise ResultError(f"unexpected result(s): {', '.join(unknown)}")
    unsuccessful = sorted(job for job, result in observed.items() if result != "success")
    if unsuccessful:
        descriptions = ", ".join(f"{job}={observed[job]}" for job in unsuccessful)
        raise ResultError(f"required job(s) did not succeed: {descriptions}")
    return tuple(sorted(expected))


def results_from_needs_json(raw: str) -> list[str]:
    """Convert GitHub's toJSON(needs) object to explicit evaluator inputs."""

    if len(raw.encode("utf-8")) > 1024 * 1024:
        raise ResultError("needs JSON exceeds the 1 MiB safety bound")
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ResultError(f"invalid needs JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise ResultError("needs JSON root must be an object")
    results: list[str] = []
    for raw_job, raw_details in cast(dict[object, object], value).items():
        if not isinstance(raw_job, str) or not JOB_NAME.fullmatch(raw_job):
            raise ResultError("needs JSON contains an invalid job name")
        if not isinstance(raw_details, dict):
            raise ResultError(f"needs JSON job {raw_job!r} must be an object")
        details = cast(dict[object, object], raw_details)
        raw_result = details.get("result")
        if not isinstance(raw_result, str):
            raise ResultError(f"needs JSON job {raw_job!r} has no string result")
        results.append(f"{raw_job}={raw_result}")
    return results


def parse_args(arguments: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--expected-job",
        action="append",
        type=_job_name,
        default=[],
        help="required dependency job name; repeat for every required job",
    )
    parser.add_argument(
        "--result",
        action="append",
        default=[],
        metavar="JOB=RESULT",
        help="observed GitHub needs result; repeat for every dependency",
    )
    parser.add_argument(
        "--needs-json",
        help="GitHub toJSON(needs) value; mutually exclusive with --result",
    )
    parser.add_argument(
        "--required",
        nargs="+",
        type=_job_name,
        default=[],
        help="expected jobs for --needs-json; each name must be explicit",
    )
    return parser.parse_args(arguments)


def main(arguments: Sequence[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if arguments is None else arguments)
    try:
        pair_mode = bool(args.expected_job or args.result)
        json_mode = args.needs_json is not None or bool(args.required)
        if pair_mode == json_mode:
            raise ResultError(
                "use exactly one interface: --expected-job/--result or --required/--needs-json"
            )
        if pair_mode:
            passing = evaluate(args.expected_job, args.result)
        else:
            if args.needs_json is None:
                raise ResultError("--needs-json is required with --required")
            passing = evaluate(args.required, results_from_needs_json(args.needs_json))
    except ResultError as exc:
        fail(str(exc))
    print(f"required-ci: {len(passing)} required job(s) succeeded")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
