import runpy

import pytest
from click.testing import CliRunner

from milhouse import __version__
from milhouse.cli import main


def test_help_is_real_and_truthful() -> None:
    result = CliRunner().invoke(main, ["--help"])

    assert result.exit_code == 0
    assert "Usage: milhouse" in result.output
    assert "Local-first observability and verified feedback loops" in result.output
    assert "pre-alpha" in result.output
    assert "starter repo" not in result.output


def test_version_uses_the_package_version() -> None:
    result = CliRunner().invoke(main, ["--version"])

    assert result.exit_code == 0
    assert result.output == f"milhouse, version {__version__}\n"


@pytest.mark.parametrize("module_name", ["milhouse.__main__", "milhouse.cli.__main__"])
def test_module_entrypoints_dispatch_to_the_click_command(
    monkeypatch: pytest.MonkeyPatch,
    module_name: str,
) -> None:
    calls: list[dict[str, str]] = []

    def fake_main(**kwargs: str) -> None:
        calls.append(kwargs)

    monkeypatch.setattr("milhouse.cli.main", fake_main)
    runpy.run_module(module_name, run_name="__main__")

    assert calls == [{"prog_name": "milhouse"}]
