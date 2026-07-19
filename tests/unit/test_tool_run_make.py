from __future__ import annotations

import os
import runpy
import sys

import pytest

from scripts import run_make


class _ExecObserved(RuntimeError):
    pass


def test_make_launcher_preserves_arguments_and_scrubs_parent_controls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, object] = {}
    poisoned = {
        "BASHOPTS": "xtrace",
        "BASH_ENV": "startup-file",
        "BASH_FUNC_python3%%": "() { :; }",
        "ENV": "startup-file",
        "GNUMAKEFLAGS": "--silent",
        "MAKEFILES": "preload.mk",
        "MAKEFLAGS": "--ignore-errors",
        "MAKELEVEL": "4",
        "MAKEOVERRIDES": "GATE=/usr/bin/true",
        "MAKE_RESTARTS": "3",
        "MFLAGS": "-i",
        "SHELLOPTS": "noexec",
    }
    for key, value in poisoned.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv("MILHOUSE_TEST_MARKER", "preserved")

    def observe(file: str, arguments: list[str], environment: dict[str, str]) -> None:
        observed.update(file=file, arguments=arguments, environment=environment)
        raise _ExecObserved

    monkeypatch.setattr(os, "execvpe", observe)

    with pytest.raises(_ExecObserved):
        run_make.main(("-s", "test"))

    assert observed["file"] == "make"
    assert observed["arguments"] == ["make", "-s", "test"]
    environment = observed["environment"]
    assert isinstance(environment, dict)
    assert environment["MILHOUSE_TEST_MARKER"] == "preserved"
    assert poisoned.keys().isdisjoint(environment)


def test_make_launcher_fails_closed_without_echoing_an_untrusted_path(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    private_path = "/private/synthetic/make"

    def unavailable(file: str, arguments: list[str], environment: dict[str, str]) -> None:
        del file, arguments, environment
        raise FileNotFoundError(private_path)

    monkeypatch.setattr(os, "execvpe", unavailable)

    assert run_make.main(("test",)) == 127
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "make-launcher: platform make is unavailable\n"
    assert private_path not in captured.err


def test_make_launcher_uses_process_arguments_by_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sys, "argv", ["run_make.py", "quality"])

    def observe(file: str, arguments: list[str], environment: dict[str, str]) -> None:
        del file, environment
        assert arguments == ["make", "quality"]
        raise _ExecObserved

    monkeypatch.setattr(os, "execvpe", observe)

    with pytest.raises(_ExecObserved):
        run_make.main()


def test_make_launcher_script_entrypoint_executes_make(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sys, "argv", ["run_make.py", "quality"])

    def observe(file: str, arguments: list[str], environment: dict[str, str]) -> None:
        del file, environment
        assert arguments == ["make", "quality"]
        raise _ExecObserved

    monkeypatch.setattr(os, "execvpe", observe)

    with pytest.raises(_ExecObserved):
        runpy.run_path(run_make.__file__, run_name="__main__")
