import json
import os
import runpy
import sys
from pathlib import Path

import pytest

from scripts import run_uv


def _fake_uv(path: Path, version: str, forwarded_exit: int = 0) -> Path:
    path.write_text(
        "\n".join(
            (
                f"#!{sys.executable}",
                "import sys",
                "if sys.argv[1:] == ['--version']:",
                f"    print({version!r})",
                "    raise SystemExit(0)",
                f"raise SystemExit({forwarded_exit})",
                "",
            )
        ),
        encoding="utf-8",
    )
    path.chmod(0o700)
    return path


def _capturing_uv(path: Path, capture: Path) -> Path:
    path.write_text(
        "\n".join(
            (
                f"#!{sys.executable}",
                "import json",
                "import os",
                "import pathlib",
                "import sys",
                "if sys.argv[1:] == ['--version']:",
                f"    print('uv {run_uv.UV_VERSION}')",
                "    raise SystemExit(0)",
                f"pathlib.Path({os.fspath(capture)!r}).write_text(",
                "    json.dumps({'arguments': sys.argv[1:], 'cwd': os.getcwd(), "
                "'uv_project': os.environ.get('UV_PROJECT'), "
                "'pythonpath': os.environ.get('PYTHONPATH'), "
                "'pytest_addopts': os.environ.get('PYTEST_ADDOPTS'), "
                "'coverage_rcfile': os.environ.get('COVERAGE_RCFILE'), "
                "'mypypath': os.environ.get('MYPYPATH'), "
                "'hypothesis_profile': os.environ.get('HYPOTHESIS_PROFILE')}),",
                "    encoding='utf-8',",
                ")",
                "",
            )
        ),
        encoding="utf-8",
    )
    path.chmod(0o700)
    return path


def test_run_uv_rejects_an_ambient_executable_with_the_wrong_version(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    untrusted_output = "uv unexpected-local-detail"
    ambient = _fake_uv(tmp_path / "uv", untrusted_output)
    monkeypatch.delenv(run_uv.UV_ENVIRONMENT_OVERRIDE, raising=False)
    monkeypatch.setenv("PATH", str(ambient.parent))

    with pytest.raises(SystemExit) as caught:
        run_uv.run_uv([])

    assert caught.value.code == 2
    diagnostic = capsys.readouterr().err
    assert f"expected uv {run_uv.UV_VERSION}" in diagnostic
    assert untrusted_output not in diagnostic


def test_explicit_exact_uv_wins_over_a_poisoned_ambient_path_and_forwards_exit_code(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ambient_dir = tmp_path / "ambient"
    exact_dir = tmp_path / "exact"
    ambient_dir.mkdir()
    exact_dir.mkdir()
    _fake_uv(ambient_dir / "uv", "uv 0.0.1", forwarded_exit=71)
    exact = _fake_uv(exact_dir / "uv", f"uv {run_uv.UV_VERSION}", forwarded_exit=23)
    monkeypatch.setenv("PATH", str(ambient_dir))
    monkeypatch.setenv(run_uv.UV_ENVIRONMENT_OVERRIDE, os.fspath(exact))

    assert run_uv.candidate_uv() == exact.resolve()
    assert run_uv.run_uv(["sync", "--locked"]) == 23


def test_run_uv_rejects_a_non_executable_override(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = tmp_path / "uv"
    candidate.write_text("not executable\n", encoding="utf-8")
    candidate.chmod(0o600)
    monkeypatch.setenv(run_uv.UV_ENVIRONMENT_OVERRIDE, os.fspath(candidate))

    with pytest.raises(SystemExit) as caught:
        run_uv.candidate_uv()

    assert caught.value.code == 2


def test_run_uv_rejects_a_missing_exact_executable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(run_uv.UV_ENVIRONMENT_OVERRIDE, raising=False)
    monkeypatch.setenv("PATH", "")

    with pytest.raises(SystemExit) as caught:
        run_uv.candidate_uv()

    assert caught.value.code == 2


def test_run_uv_reports_readiness_without_forwarding_a_command(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    exact = _fake_uv(tmp_path / "uv", f"uv {run_uv.UV_VERSION}")
    monkeypatch.setenv(run_uv.UV_ENVIRONMENT_OVERRIDE, os.fspath(exact))

    assert run_uv.run_uv(()) == 0
    assert capsys.readouterr().out == f"uv {run_uv.UV_VERSION} ready\n"


def test_run_uv_rejects_a_repository_without_both_lock_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    exact = _fake_uv(tmp_path / "uv", f"uv {run_uv.UV_VERSION}")
    monkeypatch.setenv(run_uv.UV_ENVIRONMENT_OVERRIDE, os.fspath(exact))
    monkeypatch.setattr(run_uv, "REPOSITORY_ROOT", tmp_path)

    with pytest.raises(SystemExit) as caught:
        run_uv.run_uv(("sync", "--locked"))

    assert caught.value.code == 2


def test_run_uv_binds_the_repository_and_scrubs_behavior_changing_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    capture = tmp_path / "capture.json"
    exact = _capturing_uv(tmp_path / "uv", capture)
    monkeypatch.setenv(run_uv.UV_ENVIRONMENT_OVERRIDE, os.fspath(exact))
    monkeypatch.setenv("UV_PROJECT", os.fspath(tmp_path / "redirected-project"))
    monkeypatch.setenv("UV_WORKING_DIR", os.fspath(tmp_path / "redirected-directory"))
    monkeypatch.setenv("UV_NO_SYNC", "1")
    monkeypatch.setenv("PYTHONPATH", os.fspath(tmp_path / "ambient-imports"))
    monkeypatch.setenv("PYTEST_ADDOPTS", "-k one_test")
    monkeypatch.setenv("COVERAGE_RCFILE", os.fspath(tmp_path / "false-coverage-config"))
    monkeypatch.setenv("MYPYPATH", os.fspath(tmp_path / "false-types"))
    monkeypatch.setenv("HYPOTHESIS_PROFILE", "false-profile")

    assert run_uv.run_uv(["run", "--locked", "ruff", "check"]) == 0

    observed = json.loads(capture.read_text(encoding="utf-8"))
    expected_root = os.fspath(run_uv.REPOSITORY_ROOT)
    assert observed == {
        "arguments": [
            "--directory",
            expected_root,
            "--project",
            expected_root,
            "--no-config",
            "run",
            "--locked",
            "ruff",
            "check",
        ],
        "cwd": expected_root,
        "coverage_rcfile": None,
        "hypothesis_profile": None,
        "mypypath": None,
        "uv_project": None,
        "pythonpath": None,
        "pytest_addopts": None,
    }


def test_run_uv_main_prints_the_verified_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    exact = _fake_uv(tmp_path / "uv", f"uv {run_uv.UV_VERSION}")
    monkeypatch.setenv(run_uv.UV_ENVIRONMENT_OVERRIDE, os.fspath(exact))

    assert run_uv.main(("--print-path",)) == 0
    assert capsys.readouterr().out == f"{exact.resolve()}\n"


@pytest.mark.parametrize("arguments", [("sync",), ("--", "sync")])
def test_run_uv_main_forwards_arguments_with_or_without_separator(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    arguments: tuple[str, ...],
) -> None:
    exact = _fake_uv(tmp_path / "uv", f"uv {run_uv.UV_VERSION}", forwarded_exit=19)
    monkeypatch.setenv(run_uv.UV_ENVIRONMENT_OVERRIDE, os.fspath(exact))

    assert run_uv.main(arguments) == 19


def test_run_uv_script_entrypoint_prints_the_verified_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    exact = _fake_uv(tmp_path / "uv", f"uv {run_uv.UV_VERSION}")
    monkeypatch.setenv(run_uv.UV_ENVIRONMENT_OVERRIDE, os.fspath(exact))
    monkeypatch.setattr(sys, "argv", ["run_uv.py", "--print-path"])

    with pytest.raises(SystemExit) as caught:
        runpy.run_path(run_uv.__file__, run_name="__main__")
    assert caught.value.code == 0
