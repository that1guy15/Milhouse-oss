import runpy
import subprocess
import sys
from pathlib import Path

import pytest

from scripts import check_dco
from scripts.check_dco import DCOError, verify_range


def _git(repository: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", *arguments],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    return completed.stdout.strip()


def _repository(tmp_path: Path) -> tuple[Path, str]:
    repository = tmp_path / "repository"
    repository.mkdir()
    _git(repository, "init", "--quiet")
    _git(repository, "config", "user.name", "Example Maintainer")
    _git(repository, "config", "user.email", "maintainer@example.invalid")
    _git(repository, "config", "commit.gpgsign", "false")
    _git(repository, "commit", "--quiet", "--allow-empty", "-m", "Base")
    return repository, _git(repository, "rev-parse", "HEAD")


def test_dco_accepts_an_author_matching_signoff(tmp_path: Path) -> None:
    repository, base = _repository(tmp_path)
    _git(
        repository,
        "commit",
        "--quiet",
        "--allow-empty",
        "-m",
        "Signed change\n\nSigned-off-by: Example Maintainer <maintainer@example.invalid>",
    )
    head = _git(repository, "rev-parse", "HEAD")

    assert verify_range(repository, f"{base}..{head}") == (head,)


def test_dco_rejects_a_missing_author_matching_signoff(tmp_path: Path) -> None:
    repository, base = _repository(tmp_path)
    _git(
        repository,
        "commit",
        "--quiet",
        "--allow-empty",
        "-m",
        "Unsigned change\n\nSigned-off-by: Another Person <another@example.invalid>",
    )
    head = _git(repository, "rev-parse", "HEAD")

    with pytest.raises(DCOError, match="lack an author-matching"):
        verify_range(repository, f"{base}..{head}")


def test_dco_rejects_empty_or_ambiguous_ranges(tmp_path: Path) -> None:
    repository, base = _repository(tmp_path)

    with pytest.raises(DCOError, match="contains no commits"):
        verify_range(repository, f"{base}..{base}")
    with pytest.raises(DCOError, match=r"exact BASE\.\.HEAD"):
        verify_range(repository, f"{base}...{base}")


def test_dco_checks_every_commit_in_range_and_normalizes_author_identity(tmp_path: Path) -> None:
    repository, base = _repository(tmp_path)
    for index in range(2):
        _git(
            repository,
            "commit",
            "--quiet",
            "--allow-empty",
            "-m",
            f"Change {index}\n\nSigned-off-by:  example   maintainer  <MAINTAINER@example.invalid>",
        )
    head = _git(repository, "rev-parse", "HEAD")

    commits = verify_range(repository, f"{base}..{head}")

    assert len(commits) == 2


def test_dco_pull_request_range_excludes_the_unsigned_synthetic_merge(tmp_path: Path) -> None:
    repository, base = _repository(tmp_path)
    _git(
        repository,
        "commit",
        "--quiet",
        "--allow-empty",
        "-m",
        "Signed contribution\n\nSigned-off-by: Example Maintainer <maintainer@example.invalid>",
    )
    head = _git(repository, "rev-parse", "HEAD")
    tree = _git(repository, "rev-parse", f"{head}^{{tree}}")
    synthetic_merge = _git(
        repository,
        "commit-tree",
        tree,
        "-p",
        base,
        "-p",
        head,
        "-m",
        "Synthetic pull request merge",
    )

    assert verify_range(repository, f"{base}..{head}") == (head,)
    with pytest.raises(DCOError, match="lack an author-matching"):
        verify_range(repository, f"{base}..{synthetic_merge}")


def test_dco_push_range_checks_every_pushed_commit(tmp_path: Path) -> None:
    repository, before = _repository(tmp_path)
    _git(repository, "commit", "--quiet", "--allow-empty", "-m", "Unsigned first commit")
    _git(
        repository,
        "commit",
        "--quiet",
        "--allow-empty",
        "-m",
        "Signed final commit\n\nSigned-off-by: Example Maintainer <maintainer@example.invalid>",
    )
    after = _git(repository, "rev-parse", "HEAD")

    with pytest.raises(DCOError, match="lack an author-matching"):
        verify_range(repository, f"{before}..{after}")


def test_dco_push_range_accepts_multiple_signed_commits(tmp_path: Path) -> None:
    repository, before = _repository(tmp_path)
    for index in range(2):
        _git(
            repository,
            "commit",
            "--quiet",
            "--allow-empty",
            "-m",
            f"Signed change {index}\n\n"
            "Signed-off-by: Example Maintainer <maintainer@example.invalid>",
        )
    after = _git(repository, "rev-parse", "HEAD")

    assert len(verify_range(repository, f"{before}..{after}")) == 2


def test_dco_rejects_unsafe_or_unknown_references(tmp_path: Path) -> None:
    repository, base = _repository(tmp_path)
    with pytest.raises(DCOError, match="unsafe Git reference"):
        verify_range(repository, f"--help..{base}")
    with pytest.raises(DCOError):
        verify_range(repository, f"missing..{base}")


def test_dco_git_wrapper_normalizes_timeout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def timeout(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired("git", 1)

    monkeypatch.setattr(check_dco.subprocess, "run", timeout)
    with pytest.raises(DCOError, match="cannot execute Git"):
        check_dco._git(tmp_path, ("status",))


def test_dco_rejects_a_reference_that_does_not_resolve_to_a_commit_hash(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(check_dco, "_git", lambda *_args, **_kwargs: "not-a-commit\n")

    with pytest.raises(DCOError, match="did not resolve to a commit"):
        check_dco._resolve(tmp_path, "HEAD")


def test_dco_rejects_unparseable_commit_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    commit = "a" * 40

    def malformed_git(
        _repository: Path,
        arguments: tuple[str, ...] | list[str],
        input_text: str | None = None,
    ) -> str:
        del input_text
        if arguments[0] == "rev-parse":
            return commit
        if arguments[0] == "rev-list":
            return commit
        if arguments[0] == "show":
            return "missing-nul-delimiters"
        raise AssertionError(arguments)

    monkeypatch.setattr(check_dco, "_git", malformed_git)

    with pytest.raises(DCOError, match="cannot parse commit metadata"):
        verify_range(tmp_path, "base..head")


def test_dco_ignores_non_signoff_trailers(tmp_path: Path) -> None:
    repository, base = _repository(tmp_path)
    _git(
        repository,
        "commit",
        "--quiet",
        "--allow-empty",
        "-m",
        "Unsigned change\n\nCo-authored-by: Another Person <another@example.invalid>",
    )
    head = _git(repository, "rev-parse", "HEAD")

    with pytest.raises(DCOError, match="lack an author-matching"):
        verify_range(repository, f"{base}..{head}")


def test_dco_main_reports_success_and_failure(tmp_path: Path) -> None:
    repository, base = _repository(tmp_path)
    _git(
        repository,
        "commit",
        "--quiet",
        "--allow-empty",
        "-m",
        "Change\n\nSigned-off-by: Example Maintainer <maintainer@example.invalid>",
    )
    head = _git(repository, "rev-parse", "HEAD")
    assert check_dco.main(["--repository", str(repository), "--range", f"{base}..{head}"]) == 0

    with pytest.raises(SystemExit) as caught:
        check_dco.main(["--repository", str(repository), "--range", f"{base}..{base}"])
    assert caught.value.code == 1


def test_dco_script_entrypoint_checks_the_explicit_range(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, base = _repository(tmp_path)
    _git(
        repository,
        "commit",
        "--quiet",
        "--allow-empty",
        "-m",
        "Signed change\n\nSigned-off-by: Example Maintainer <maintainer@example.invalid>",
    )
    head = _git(repository, "rev-parse", "HEAD")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "check_dco.py",
            "--repository",
            str(repository),
            "--range",
            f"{base}..{head}",
        ],
    )

    with pytest.raises(SystemExit) as caught:
        runpy.run_path(check_dco.__file__, run_name="__main__")
    assert caught.value.code == 0
