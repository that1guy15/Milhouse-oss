#!/usr/bin/env python3
"""Enforce Milhouse line and branch thresholds from coverage.py JSON."""

from __future__ import annotations

import argparse
import fnmatch
import json
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import NoReturn, cast

MAX_JSON_BYTES = 64 * 1024 * 1024


class CoverageError(ValueError):
    """Raised when coverage evidence is missing, malformed, or below policy."""


@dataclass(frozen=True)
class Counts:
    covered: int
    total: int

    def percentage(self) -> float:
        if self.total <= 0:
            raise CoverageError("coverage evidence has no measurable items")
        return self.covered * 100.0 / self.total

    def meets(self, threshold: float) -> bool:
        if self.total <= 0:
            raise CoverageError("coverage evidence has no measurable items")
        return self.covered * 100 >= threshold * self.total


def fail(message: str) -> NoReturn:
    print(f"coverage: {message}", file=sys.stderr)
    raise SystemExit(1)


def _read_json(path: Path) -> dict[str, object]:
    if path.is_symlink() or not path.is_file():
        raise CoverageError("coverage JSON must be a regular, non-symlink file")
    if path.stat().st_size > MAX_JSON_BYTES:
        raise CoverageError("coverage JSON exceeds the 64 MiB safety bound")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CoverageError(f"cannot parse coverage JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise CoverageError("coverage JSON root must be an object")
    return cast(dict[str, object], value)


def _mapping(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise CoverageError(f"{label} must be an object")
    return cast(dict[str, object], value)


def _count(mapping: dict[str, object], key: str, label: str) -> int:
    value = mapping.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise CoverageError(f"{label}.{key} must be a non-negative integer")
    return value


def _counts(summary: dict[str, object], kind: str, label: str) -> Counts:
    if kind == "line":
        covered_key, total_key = "covered_lines", "num_statements"
    else:
        covered_key, total_key = "covered_branches", "num_branches"
    counts = Counts(
        covered=_count(summary, covered_key, label),
        total=_count(summary, total_key, label),
    )
    if counts.covered > counts.total:
        raise CoverageError(f"{label} reports more covered than total {kind} items")
    return counts


def _matches(path: str, patterns: Sequence[str]) -> bool:
    normalized = path.replace("\\", "/")
    return any(fnmatch.fnmatchcase(normalized, pattern) for pattern in patterns)


def validate_coverage(
    path: Path,
    line_threshold: float,
    branch_threshold: float,
    critical_patterns: Sequence[str],
    critical_branch_threshold: float,
) -> tuple[float, float, tuple[tuple[str, float], ...]]:
    """Validate coverage evidence and return display-safe summaries."""

    document = _read_json(path)
    totals = _mapping(document.get("totals"), "totals")
    lines = _counts(totals, "line", "totals")
    branches = _counts(totals, "branch", "totals")
    if not lines.meets(line_threshold):
        raise CoverageError(
            f"line coverage {lines.percentage():.2f}% is below {line_threshold:.2f}%"
        )
    if not branches.meets(branch_threshold):
        raise CoverageError(
            f"branch coverage {branches.percentage():.2f}% is below {branch_threshold:.2f}%"
        )

    critical_results: list[tuple[str, float]] = []
    if critical_patterns:
        files = _mapping(document.get("files"), "files")
        matched_patterns: set[str] = set()
        for file_name, raw_details in sorted(files.items()):
            matching_patterns = tuple(
                pattern for pattern in critical_patterns if _matches(file_name, (pattern,))
            )
            if not matching_patterns:
                continue
            details = _mapping(raw_details, f"files[{file_name!r}]")
            summary = _mapping(details.get("summary"), f"files[{file_name!r}].summary")
            file_branches = _counts(summary, "branch", f"files[{file_name!r}].summary")
            percentage = file_branches.percentage()
            if not file_branches.meets(critical_branch_threshold):
                raise CoverageError(
                    f"critical file {file_name} branch coverage {percentage:.2f}% is below "
                    f"{critical_branch_threshold:.2f}%"
                )
            critical_results.append((file_name, percentage))
            matched_patterns.update(matching_patterns)
        unmatched_patterns = tuple(
            pattern for pattern in critical_patterns if pattern not in matched_patterns
        )
        if unmatched_patterns:
            rendered = ", ".join(repr(pattern) for pattern in unmatched_patterns)
            raise CoverageError(
                "each critical coverage pattern must match a measurable file; "
                f"unmatched pattern(s): {rendered}"
            )

    return lines.percentage(), branches.percentage(), tuple(critical_results)


def _threshold(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("threshold must be numeric") from exc
    if not 0.0 <= parsed <= 100.0:
        raise argparse.ArgumentTypeError("threshold must be between 0 and 100")
    return parsed


def parse_args(arguments: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("coverage_json", type=Path)
    parser.add_argument("--line", type=_threshold, default=90.0)
    parser.add_argument("--branch", type=_threshold, default=85.0)
    parser.add_argument(
        "--critical",
        action="append",
        default=[],
        metavar="GLOB",
        help="require the critical branch threshold for every matched file",
    )
    parser.add_argument("--critical-branch", type=_threshold, default=95.0)
    return parser.parse_args(arguments)


def main(arguments: Sequence[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if arguments is None else arguments)
    try:
        line, branch, critical = validate_coverage(
            args.coverage_json,
            args.line,
            args.branch,
            args.critical,
            args.critical_branch,
        )
    except CoverageError as exc:
        fail(str(exc))
    print(f"coverage: line={line:.2f}% branch={branch:.2f}% critical_files={len(critical)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
