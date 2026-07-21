from pathlib import Path

import pytest
from click.testing import CliRunner

from milhouse.cli import main
from milhouse.config import generate_json_schema_bytes

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
EXAMPLE_CONFIG = REPOSITORY_ROOT / "config/example.toml"


def test_root_help_exposes_config_commands_and_global_path_option() -> None:
    result = CliRunner().invoke(main, ["--help"])

    assert result.exit_code == 0
    assert "--config PATH" in result.output
    assert "config" in result.output


def test_config_schema_writes_the_exact_deterministic_schema_bytes() -> None:
    result = CliRunner().invoke(main, ["config", "schema"])

    assert result.exit_code == 0
    assert result.stdout_bytes == generate_json_schema_bytes()
    assert result.stderr_bytes == b""


def test_config_validate_accepts_an_explicit_checked_in_example() -> None:
    result = CliRunner().invoke(
        main,
        ["--config", str(EXAMPLE_CONFIG), "config", "validate"],
    )

    assert result.exit_code == 0
    assert result.output == "configuration is valid\n"


def test_config_validate_uses_milhouse_config_environment_precedence() -> None:
    result = CliRunner().invoke(
        main,
        ["config", "validate"],
        env={"MILHOUSE_CONFIG": str(EXAMPLE_CONFIG)},
    )

    assert result.exit_code == 0
    assert result.output == "configuration is valid\n"


def test_config_validate_uses_the_platform_default_without_cwd_search(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    default_root = tmp_path / "platform"
    default_root.mkdir()
    default_config = default_root / "config.toml"
    default_config.write_text(EXAMPLE_CONFIG.read_text(encoding="utf-8"), encoding="utf-8")
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    (cwd / "milhouse.toml").write_text("config_version = 999\n", encoding="utf-8")
    monkeypatch.chdir(cwd)
    monkeypatch.setattr(
        "milhouse.cli.root.user_config_path",
        lambda *_args, **_kwargs: default_root,
    )

    result = CliRunner().invoke(main, ["config", "validate"], env={})

    assert result.exit_code == 0
    assert result.output == "configuration is valid\n"


def test_config_validate_failure_is_stable_and_value_safe(tmp_path: Path) -> None:
    secret_looking_value = "secret_token_0123456789abcdef"
    broken = EXAMPLE_CONFIG.read_text(encoding="utf-8").replace(
        "max_batch_records = 500",
        f'max_batch_records = "{secret_looking_value}"',
    )
    config_path = tmp_path / "broken.toml"
    config_path.write_text(broken, encoding="utf-8")

    result = CliRunner().invoke(
        main,
        ["--config", str(config_path), "config", "validate"],
    )

    assert result.exit_code == 1
    assert "config.schema.invalid" in result.stderr
    assert secret_looking_value not in result.output
    assert secret_looking_value not in result.stderr
