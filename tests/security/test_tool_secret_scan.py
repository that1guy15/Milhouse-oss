import runpy
import subprocess
from pathlib import Path

import pytest

from scripts import secret_scan
from scripts.gitleaks import GitleaksError
from scripts.secret_scan import ScanError


def _completed(code: int, stdout: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(["scanner"], code, stdout=stdout, stderr="")


def test_secret_scan_command_builders_are_redacted_and_fail_closed(tmp_path: Path) -> None:
    binary = tmp_path / "gitleaks"
    tree = secret_scan.tree_command(binary, tmp_path)
    history = secret_scan.history_command(binary, tmp_path)

    assert tree == (
        str(binary),
        "dir",
        "--no-banner",
        "--redact=100",
        f"--exit-code={secret_scan.DETECTED_EXIT}",
        str(tmp_path),
    )
    assert history[-2:] == ("--log-opts=--all", str(tmp_path))
    assert "--redact=100" in history


def test_secret_scan_supports_standalone_script_imports(monkeypatch: pytest.MonkeyPatch) -> None:
    root = Path(__file__).resolve().parents[2]
    monkeypatch.syspath_prepend(str(root / "scripts"))

    namespace = runpy.run_path(
        str(root / "scripts" / "secret_scan.py"),
        run_name="milhouse_secret_scan_standalone_probe",
    )

    assert namespace["DETECTED_EXIT"] == secret_scan.DETECTED_EXIT


@pytest.mark.parametrize(
    ("code", "message"),
    [
        (secret_scan.DETECTED_EXIT, "found a potential secret"),
        (7, "failed with scanner exit 7"),
    ],
)
def test_clean_scan_rejects_detection_and_scanner_failure(
    monkeypatch: pytest.MonkeyPatch,
    code: int,
    message: str,
) -> None:
    monkeypatch.setattr(secret_scan, "_run", lambda _command, capture: _completed(code))

    with pytest.raises(ScanError, match=message):
        secret_scan.scan_clean(("scanner",), "tree")


def test_clean_scan_accepts_zero(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(secret_scan, "_run", lambda _command, capture: _completed(0))

    secret_scan.scan_clean(("scanner",), "tree")


@pytest.mark.parametrize(
    ("code", "message"),
    [
        (0, "missed the disposable planted secret"),
        (7, "failed with scanner exit 7"),
    ],
)
def test_detection_proof_rejects_clean_or_broken_scanner_results(
    monkeypatch: pytest.MonkeyPatch,
    code: int,
    message: str,
) -> None:
    monkeypatch.setattr(secret_scan, "_run", lambda _command, capture: _completed(code))

    with pytest.raises(ScanError, match=message):
        secret_scan.require_detection(("scanner",), "negative")


def test_detection_proof_accepts_only_the_configured_detection_exit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        secret_scan,
        "_run",
        lambda _command, capture: _completed(secret_scan.DETECTED_EXIT),
    )

    secret_scan.require_detection(("scanner",), "negative")


def test_scan_tree_requires_a_directory_and_uses_the_resolved_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binary = tmp_path / "gitleaks"
    source_file = tmp_path / "source.txt"
    source_file.write_text("synthetic\n", encoding="utf-8")
    with pytest.raises(ScanError, match="must be a directory"):
        secret_scan.scan_tree(binary, source_file)

    calls: list[tuple[tuple[str, ...], str]] = []
    monkeypatch.setattr(
        secret_scan,
        "scan_clean",
        lambda command, label: calls.append((tuple(command), label)),
    )
    secret_scan.scan_tree(binary, tmp_path)
    assert calls == [(secret_scan.tree_command(binary, tmp_path.resolve()), "current-tree scan")]


def test_scan_history_rejects_non_git_and_shallow_repositories(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binary = tmp_path / "gitleaks"
    responses = iter(("false",))
    monkeypatch.setattr(secret_scan, "_git", lambda _repo, _args: next(responses))
    with pytest.raises(ScanError, match="not a Git work tree"):
        secret_scan.scan_history(binary, tmp_path)

    responses = iter(("true", "true"))
    monkeypatch.setattr(secret_scan, "_git", lambda _repo, _args: next(responses))
    with pytest.raises(ScanError, match="refuses a shallow"):
        secret_scan.scan_history(binary, tmp_path)


def test_scan_history_runs_full_history_command(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binary = tmp_path / "gitleaks"
    responses = iter(("true", "false"))
    calls: list[tuple[tuple[str, ...], str]] = []
    monkeypatch.setattr(secret_scan, "_git", lambda _repo, _args: next(responses))
    monkeypatch.setattr(
        secret_scan,
        "scan_clean",
        lambda command, label: calls.append((tuple(command), label)),
    )

    secret_scan.scan_history(binary, tmp_path)

    assert calls == [(secret_scan.history_command(binary, tmp_path.resolve()), "full-history scan")]


def test_scanner_subprocess_and_git_failures_are_normalized(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def timeout(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired("scanner", 1)

    monkeypatch.setattr(secret_scan.subprocess, "run", timeout)
    with pytest.raises(ScanError, match="scanner execution failed"):
        secret_scan._run(("scanner",), capture=True)

    monkeypatch.setattr(secret_scan, "_run", lambda _command, capture: _completed(2))
    with pytest.raises(ScanError, match="Git prerequisite failed"):
        secret_scan._git(tmp_path, ("status",))

    monkeypatch.setattr(
        secret_scan,
        "_run",
        lambda _command, capture: _completed(0, stdout=" true \n"),
    )
    assert secret_scan._git(tmp_path, ("status",)) == "true"


def test_self_test_uses_disposable_tree_and_history_paths_without_a_live_scanner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    detections: list[tuple[tuple[str, ...], str]] = []
    git_calls: list[tuple[str, ...]] = []
    monkeypatch.setattr(secret_scan, "_plant_value", lambda: "benign-runtime-fixture")
    monkeypatch.setattr(
        secret_scan,
        "require_detection",
        lambda command, label: detections.append((tuple(command), label)),
    )
    monkeypatch.setattr(
        secret_scan,
        "_git",
        lambda _repository, arguments: git_calls.append(tuple(arguments)) or "",
    )

    secret_scan.self_test(tmp_path / "gitleaks")

    assert [label for _command, label in detections] == [
        "current-tree negative test",
        "full-history negative test",
    ]
    assert ("commit", "--quiet", "-m", "synthetic scanner proof") in git_calls


@pytest.mark.parametrize(
    ("mode", "expected"),
    [
        ("tree", ["tree"]),
        ("history", ["history"]),
        ("self-test", ["self-test"]),
        ("all", ["tree", "history", "self-test"]),
    ],
)
def test_secret_scan_main_dispatches_modes_offline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
    expected: list[str],
) -> None:
    calls: list[str] = []
    binary = tmp_path / "gitleaks"
    monkeypatch.setattr(secret_scan, "ensure_gitleaks", lambda _cache: binary)
    monkeypatch.setattr(secret_scan, "scan_tree", lambda _binary, _source: calls.append("tree"))
    monkeypatch.setattr(
        secret_scan,
        "scan_history",
        lambda _binary, _source: calls.append("history"),
    )
    monkeypatch.setattr(secret_scan, "self_test", lambda _binary: calls.append("self-test"))

    assert secret_scan.main([mode, "--source", str(tmp_path)]) == 0
    assert calls == expected


def test_secret_scan_main_fails_closed_when_bootstrap_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unavailable(_cache: Path | None) -> Path:
        raise GitleaksError("offline")

    monkeypatch.setattr(secret_scan, "ensure_gitleaks", unavailable)
    with pytest.raises(SystemExit) as caught:
        secret_scan.main(["tree"])
    assert caught.value.code == 1
