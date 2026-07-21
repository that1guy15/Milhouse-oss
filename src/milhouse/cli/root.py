"""Root Click command for the Milhouse CLI."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import click
from platformdirs import user_config_path

from milhouse import __version__
from milhouse.config import ConfigError, generate_json_schema_bytes, load_config


@dataclass(frozen=True, slots=True)
class CliState:
    """Value-safe root options shared by Milhouse command groups."""

    config_path: str | None


def _platform_config_file() -> Path:
    return user_config_path("milhouse", appauthor=False) / "config.toml"


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
@click.pass_context
def main(context: click.Context, config_path: str | None) -> None:
    """Local-first observability and verified feedback loops (pre-alpha)."""

    context.obj = CliState(config_path=config_path)


@main.group(name="config")
def config_group() -> None:
    """Validate configuration or export its machine schema."""


@config_group.command(name="validate")
@click.pass_obj
def validate_config_command(state: CliState) -> None:
    """Validate one config without network access or secret resolution."""

    try:
        load_config(state.config_path, platform_default=_platform_config_file())
    except ConfigError as error:
        raise click.ClickException(str(error)) from None
    click.echo("configuration is valid")


@config_group.command(name="schema")
def config_schema_command() -> None:
    """Write the deterministic Draft 2020-12 config schema to stdout."""

    output = click.get_binary_stream("stdout")
    output.write(generate_json_schema_bytes())
    output.flush()
