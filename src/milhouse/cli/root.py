"""Root Click command for the Milhouse CLI."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import click
from platformdirs import user_config_path, user_data_path

from milhouse import __version__
from milhouse.cli import bootstrap, demo
from milhouse.config import (
    ConfigError,
    RuntimePaths,
    generate_json_schema_bytes,
    load_config,
    resolve_runtime_paths,
)
from milhouse.core.clock import SystemClock


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


def _resolve_paths(state: CliState) -> RuntimePaths:
    """Load the config and resolve runtime paths, mapping config failure to the exit-2 CLI error."""

    try:
        config, config_path = load_config(
            state.config_path, platform_default=_platform_config_file()
        )
        return resolve_runtime_paths(
            config,
            config_path=config_path,
            platform_data_root=_platform_data_root(),
        )
    except ConfigError as error:
        raise ConfigCommandError(error) from None


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

    _resolve_paths(state)
    click.echo("configuration is valid")


@config_group.command(name="schema")
def config_schema_command() -> None:
    """Write the deterministic Draft 2020-12 config schema to stdout."""

    output = click.get_binary_stream("stdout")
    output.write(generate_json_schema_bytes())
    output.flush()


class BootstrapCommandError(click.ClickException):
    """A stable bootstrap failure using the CLI contract's exit code 1."""

    exit_code = 1

    def __init__(self, error: bootstrap.BootstrapError) -> None:
        self.code = error.code
        super().__init__(str(error))


@main.command(name="init")
@click.option("--json", "as_json", is_flag=True, help="Emit the result as stable JSON.")
@click.pass_obj
def init_command(state: CliState, as_json: bool) -> None:
    """Initialize the state root, control database, and installation identity (idempotent)."""

    paths = _resolve_paths(state)
    try:
        report = bootstrap.initialize(paths, now=SystemClock().now())
    except bootstrap.BootstrapError as error:
        raise BootstrapCommandError(error) from None
    if as_json:
        click.echo(
            json.dumps(
                {
                    "created_directories": list(report.created_directories),
                    "schema_version": report.schema_version,
                    "installation_id_created": report.installation_id_created,
                    "already_initialized": report.already_initialized,
                },
                sort_keys=True,
            )
        )
        return
    if report.already_initialized:
        click.echo(f"already initialized (schema {report.schema_version})")
        return
    created = ", ".join(report.created_directories) or "none"
    identity = "created" if report.installation_id_created else "present"
    click.echo(
        f"initialized: directories={created}; schema {report.schema_version}; "
        f"installation id {identity}"
    )


@main.command(name="health")
@click.option("--json", "as_json", is_flag=True, help="Emit the report as stable JSON.")
@click.pass_context
def health_command(context: click.Context, as_json: bool) -> None:
    """Report whether the local install is usable; exit non-zero when unhealthy."""

    state = context.ensure_object(CliState)
    paths = _resolve_paths(state)
    report = bootstrap.health(paths, now=SystemClock().now())
    if as_json:
        click.echo(
            json.dumps(
                {
                    "status": report.status,
                    "checks": [
                        {"name": check.name, "ok": check.ok, "detail": check.detail}
                        for check in report.checks
                    ],
                },
                sort_keys=True,
            )
        )
    else:
        for check in report.checks:
            click.echo(f"[{'ok' if check.ok else 'FAIL'}] {check.name}: {check.detail}")
        click.echo(f"status: {report.status}")
    if not report.healthy:
        context.exit(1)


@main.command(name="demo")
@click.option("--json", "as_json", is_flag=True, help="Emit the result as stable JSON.")
@click.pass_context
def demo_command(context: click.Context, as_json: bool) -> None:
    """Run a credential-free, spool-only end-to-end data-flow demo."""

    state = context.ensure_object(CliState)
    paths = _resolve_paths(state)
    try:
        report = demo.run_demo(paths, now=SystemClock().now())
    except bootstrap.BootstrapError as error:
        raise BootstrapCommandError(error) from None
    if as_json:
        click.echo(
            json.dumps(
                {
                    "batch_id": report.batch_id,
                    "day": report.day,
                    "records_spooled": report.records_spooled,
                    "read_back_ok": report.read_back_ok,
                },
                sort_keys=True,
            )
        )
    else:
        outcome = "ok" if report.read_back_ok else "FAILED"
        click.echo(
            f"demo: spooled {report.records_spooled} record(s) to "
            f"{report.day}/{report.batch_id}; read-back {outcome}"
        )
    if not report.read_back_ok:
        context.exit(1)
