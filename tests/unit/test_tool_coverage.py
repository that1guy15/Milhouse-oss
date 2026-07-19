import json
import re
import tomllib
from pathlib import Path

import pytest

from scripts import check_coverage
from scripts.check_coverage import CoverageError, validate_coverage


def test_coverage_py_delegates_independent_thresholds_to_repository_checker() -> None:
    project = Path(__file__).resolve().parents[2] / "pyproject.toml"
    configuration = tomllib.loads(project.read_text(encoding="utf-8"))

    assert configuration["tool"]["coverage"]["report"]["fail_under"] == 0


def _coverage_file(
    tmp_path: Path,
    *,
    covered_lines: int = 90,
    statements: int = 100,
    covered_branches: int = 85,
    branches: int = 100,
    files: dict[str, object] | None = None,
) -> Path:
    path = tmp_path / "coverage.json"
    path.write_text(
        json.dumps(
            {
                "totals": {
                    "covered_lines": covered_lines,
                    "num_statements": statements,
                    "covered_branches": covered_branches,
                    "num_branches": branches,
                },
                "files": files or {},
            }
        ),
        encoding="utf-8",
    )
    return path


def test_coverage_enforces_line_and_branch_thresholds_independently(tmp_path: Path) -> None:
    passing = _coverage_file(tmp_path)
    line, branch, critical = validate_coverage(passing, 90, 85, (), 95)

    assert (line, branch, critical) == (90.0, 85.0, ())

    below_line = _coverage_file(tmp_path, covered_lines=89, covered_branches=100)
    with pytest.raises(CoverageError, match="line coverage"):
        validate_coverage(below_line, 90, 85, (), 95)

    below_branch = _coverage_file(tmp_path, covered_lines=100, covered_branches=84)
    with pytest.raises(CoverageError, match="branch coverage"):
        validate_coverage(below_branch, 90, 85, (), 95)


def test_coverage_enforces_critical_file_branch_threshold(tmp_path: Path) -> None:
    path = _coverage_file(
        tmp_path,
        covered_lines=100,
        covered_branches=100,
        files={
            "src/milhouse/privacy/policy.py": {
                "summary": {
                    "covered_lines": 10,
                    "num_statements": 10,
                    "covered_branches": 18,
                    "num_branches": 20,
                }
            }
        },
    )

    with pytest.raises(CoverageError, match=r"critical file.*90.00%.*95.00%"):
        validate_coverage(path, 90, 85, ("src/milhouse/privacy/*.py",), 95)


def test_coverage_rejects_unmatched_critical_patterns(tmp_path: Path) -> None:
    path = _coverage_file(tmp_path, covered_lines=100, covered_branches=100)

    with pytest.raises(CoverageError, match="must match a measurable file"):
        validate_coverage(path, 90, 85, ("src/milhouse/privacy/*.py",), 95)


@pytest.mark.parametrize(
    "missing_pattern",
    (
        "src/milhouse/privacy/polciy.py",
        "src/milhouse/privacy/deleted.py",
    ),
)
def test_each_critical_pattern_must_independently_match_a_measurable_file(
    tmp_path: Path,
    missing_pattern: str,
) -> None:
    summary = {
        "covered_lines": 10,
        "num_statements": 10,
        "covered_branches": 20,
        "num_branches": 20,
    }
    path = _coverage_file(
        tmp_path,
        covered_lines=100,
        covered_branches=100,
        files={"src/milhouse/privacy/policy.py": {"summary": summary}},
    )

    with pytest.raises(CoverageError, match=re.escape(missing_pattern)):
        validate_coverage(
            path,
            90,
            85,
            ("src/milhouse/privacy/*.py", missing_pattern),
            95,
        )


def test_critical_pattern_rejects_a_matching_file_without_measurable_branches(
    tmp_path: Path,
) -> None:
    summary = {
        "covered_lines": 1,
        "num_statements": 1,
        "covered_branches": 0,
        "num_branches": 0,
    }
    path = _coverage_file(
        tmp_path,
        covered_lines=100,
        covered_branches=100,
        files={"src/milhouse/privacy/policy.py": {"summary": summary}},
    )

    with pytest.raises(CoverageError, match="no measurable items"):
        validate_coverage(path, 90, 85, ("src/milhouse/privacy/*.py",), 95)


@pytest.mark.parametrize(
    ("covered", "total", "message"),
    [
        (1, 0, "more covered than total"),
        (0, 0, "no measurable items"),
        (-1, 10, "non-negative integer"),
    ],
)
def test_coverage_rejects_impossible_or_empty_counts(
    tmp_path: Path,
    covered: int,
    total: int,
    message: str,
) -> None:
    path = _coverage_file(
        tmp_path,
        covered_lines=covered,
        statements=total,
        covered_branches=10,
        branches=10,
    )

    with pytest.raises(CoverageError, match=message):
        validate_coverage(path, 0, 0, (), 95)


def test_coverage_rejects_symlink_evidence(tmp_path: Path) -> None:
    evidence = _coverage_file(tmp_path)
    symlink = tmp_path / "linked-coverage.json"
    symlink.symlink_to(evidence)

    with pytest.raises(CoverageError, match="non-symlink"):
        validate_coverage(symlink, 90, 85, (), 95)


def test_coverage_rejects_malformed_root_and_summary_shapes(tmp_path: Path) -> None:
    path = tmp_path / "coverage.json"
    path.write_text("[]", encoding="utf-8")
    with pytest.raises(CoverageError, match="root must be an object"):
        validate_coverage(path, 90, 85, (), 95)

    path.write_text("{", encoding="utf-8")
    with pytest.raises(CoverageError, match="cannot parse"):
        validate_coverage(path, 90, 85, (), 95)

    path.write_text(json.dumps({"totals": []}), encoding="utf-8")
    with pytest.raises(CoverageError, match="totals must be an object"):
        validate_coverage(path, 90, 85, (), 95)


def test_coverage_rejects_boolean_noninteger_and_overlarge_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = _coverage_file(tmp_path)
    document = json.loads(path.read_text(encoding="utf-8"))
    document["totals"]["covered_lines"] = True
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(CoverageError, match="non-negative integer"):
        validate_coverage(path, 90, 85, (), 95)

    monkeypatch.setattr(check_coverage, "MAX_JSON_BYTES", 1)
    with pytest.raises(CoverageError, match="64 MiB safety bound"):
        validate_coverage(path, 90, 85, (), 95)


def test_coverage_rejects_noninteger_counts(tmp_path: Path) -> None:
    path = _coverage_file(tmp_path)
    document = json.loads(path.read_text(encoding="utf-8"))
    document["totals"]["covered_lines"] = "90"
    path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(CoverageError, match="non-negative integer"):
        validate_coverage(path, 90, 85, (), 95)


def test_critical_coverage_accepts_every_matching_file_and_normalizes_windows_paths(
    tmp_path: Path,
) -> None:
    summary = {
        "covered_lines": 10,
        "num_statements": 10,
        "covered_branches": 19,
        "num_branches": 20,
    }
    path = _coverage_file(
        tmp_path,
        covered_lines=100,
        covered_branches=100,
        files={
            "src\\milhouse\\privacy\\one.py": {"summary": summary},
            "src/milhouse/privacy/two.py": {"summary": summary},
            "src/milhouse/cli/root.py": {"summary": summary},
        },
    )

    _line, _branch, critical = validate_coverage(
        path,
        90,
        85,
        ("src/milhouse/privacy/*.py",),
        95,
    )
    assert len(critical) == 2


def test_coverage_main_reports_success_and_failure(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = _coverage_file(tmp_path, covered_lines=100, covered_branches=100)
    assert check_coverage.main([str(path), "--line", "90", "--branch", "85"]) == 0
    assert "line=100.00%" in capsys.readouterr().out

    with pytest.raises(SystemExit) as caught:
        check_coverage.main([str(path), "--line", "101"])
    assert caught.value.code == 2

    with pytest.raises(SystemExit) as caught:
        check_coverage.main([str(path), "--line", "not-a-number"])
    assert caught.value.code == 2

    below = _coverage_file(tmp_path, covered_lines=10, covered_branches=10)
    with pytest.raises(SystemExit) as caught:
        check_coverage.main([str(below)])
    assert caught.value.code == 1
