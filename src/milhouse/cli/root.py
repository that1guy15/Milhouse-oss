"""Root Click command for the Milhouse CLI."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import click
from platformdirs import user_config_path, user_data_path

from milhouse import __version__
from milhouse.config import (
    ConfigError,
    generate_json_schema_bytes,
    load_config,
    resolve_runtime_paths,
)


@dataclass(frozen=True, slots=True, repr=False)
class CliState:
    """Value-safe root options shared by Milhouse command groups."""

    config_path: str | None
    env_file: str | None

    def __repr__(self) -> str:
        return (
            "CliState("
            f"config_path_set={self.config_path is not None}, "
            f"env_file_set={self.env_file is not None})"
        )

    __str__ = __repr__


class ConfigCommandError(click.ClickException):
    """A stable invalid-config failure using the CLI contract's exit code 2."""

    exit_code = 2

    def __init__(self, error: ConfigError) -> None:
        self.code = error.code
        self.error_message = error.message
        super().__init__(str(error))


def _platform_config_file() -> Path:
    return user_config_path("milhouse", appauthor=False) / "config.toml"


def _platform_data_root() -> Path:
    return user_data_path("milhouse", appauthor=False)


@click.group(
    name="milhouse",
    context_settings={"help_option_names": ["-h", "--help"]},
    no_args_is_help=True,
)
@click.version_option(version=__version__, prog_name="milhouse")
@click.option(
    "--config",
    "config_path",
    metavar="PATH",
    help="Use this config file before MILHOUSE_CONFIG or the platform default.",
)
@click.option(
    "--env-file",
    metavar="PATH",
    help="Use this explicit env file before configured env files; never auto-discovers .env.",
)
@click.pass_context
def main(context: click.Context, config_path: str | None, env_file: str | None) -> None:
    """Local-first observability and verified feedback loops (pre-alpha)."""

    context.obj = CliState(config_path=config_path, env_file=env_file)


@main.group(name="config")
def config_group() -> None:
    """Validate configuration or export its machine schema."""


@config_group.command(name="validate")
@click.pass_obj
def validate_config_command(state: CliState) -> None:
    """Validate one config without network access or secret resolution."""

    try:
        config, config_path = load_config(
            state.config_path, platform_default=_platform_config_file()
        )
        resolve_runtime_paths(
            config,
            config_path=config_path,
            platform_data_root=_platform_data_root(),
        )
    except ConfigError as error:
        raise ConfigCommandError(error) from None
    click.echo("configuration is valid")


@config_group.command(name="schema")
def config_schema_command() -> None:
    """Write the deterministic Draft 2020-12 config schema to stdout."""

    output = click.get_binary_stream("stdout")
    output.write(generate_json_schema_bytes())
    output.flush()
