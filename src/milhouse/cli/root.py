"""Root Click command for the Milhouse CLI."""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path

import click
from platformdirs import user_config_path, user_data_path

from milhouse import __version__, storage
from milhouse.cli import bootstrap, demo, views
from milhouse.config import (
    ConfigError,
    RuntimePaths,
    generate_json_schema_bytes,
    load_config,
    load_secret_environment,
    resolve_runtime_paths,
)
from milhouse.config._models import MilhouseConfig
from milhouse.core.clock import SystemClock
from milhouse.spooling import SpoolError, replay_segments
from milhouse.spooling.ledger import list_segment_records
from milhouse.state import GlobalCommitBarrier, open_control_database


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


def _resolve_config(state: CliState) -> tuple[MilhouseConfig, RuntimePaths]:
    """Load the config and resolve runtime paths, mapping config failure to the exit-2 CLI error."""

    try:
        config, config_path = load_config(
            state.config_path, platform_default=_platform_config_file()
        )
        paths = resolve_runtime_paths(
            config,
            config_path=config_path,
            platform_data_root=_platform_data_root(),
        )
        return config, paths
    except ConfigError as error:
        raise ConfigCommandError(error) from None


def _resolve_paths(state: CliState) -> RuntimePaths:
    """Resolve runtime paths only (config discarded)."""

    return _resolve_config(state)[1]


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


def _require_installation_id(paths: RuntimePaths) -> str:
    installation_id = bootstrap.read_installation_id(paths)
    if installation_id is None:
        raise BootstrapCommandError(
            bootstrap.BootstrapError("MH_NOT_INITIALIZED", "run milhouse init first")
        )
    return installation_id


@main.group(name="spool")
def spool_group() -> None:
    """Inspect committed spool segments (read-only)."""


@spool_group.command(name="list")
@click.option("--json", "as_json", is_flag=True, help="Emit the listing as stable JSON.")
@click.pass_obj
def spool_list_command(state: CliState, as_json: bool) -> None:
    """List every committed spool segment with privacy-safe metadata."""

    paths = _resolve_paths(state)
    segments = views.list_segments(paths)
    if as_json:
        click.echo(json.dumps([asdict(segment) for segment in segments], sort_keys=True))
        return
    if not segments:
        click.echo("no committed segments")
        return
    for segment in segments:
        click.echo(
            f"{segment.day}/{segment.batch_id}  records={segment.record_count} "
            f"bytes={segment.byte_size} class={segment.privacy_class} "
            f"origin={segment.origin} delivered={segment.delivered}"
        )


@spool_group.command(name="show")
@click.argument("batch_id")
@click.option("--json", "as_json", is_flag=True, help="Emit the detail as stable JSON.")
@click.pass_context
def spool_show_command(context: click.Context, batch_id: str, as_json: bool) -> None:
    """Show one segment's header summary and per-record metadata."""

    state = context.ensure_object(CliState)
    paths = _resolve_paths(state)
    installation_id = _require_installation_id(paths)
    detail = views.show_segment(paths, batch_id, installation_id)
    if detail is None:
        click.echo(f"no segment {batch_id}")
        context.exit(1)
    if as_json:
        click.echo(
            json.dumps(
                {
                    "summary": asdict(detail.summary),
                    "readable": detail.readable,
                    "events": [asdict(event) for event in detail.events],
                },
                sort_keys=True,
            )
        )
        return
    summary = detail.summary
    click.echo(
        f"segment {summary.day}/{summary.batch_id}: records={summary.record_count} "
        f"bytes={summary.byte_size} class={summary.privacy_class} origin={summary.origin} "
        f"delivered={summary.delivered} readable={detail.readable}"
    )
    for event in detail.events:
        click.echo(
            f"  {event.record_id} {event.record_type}/{event.name} "
            f"occurred={event.occurred_at} expires={event.expires_at} "
            f"target={event.target_id} severity={event.severity}"
        )


@main.command(name="events")
@click.option("--json", "as_json", is_flag=True, help="Emit the events as stable JSON.")
@click.pass_context
def events_command(context: click.Context, as_json: bool) -> None:
    """Read spooled records back and list their privacy-safe metadata."""

    state = context.ensure_object(CliState)
    paths = _resolve_paths(state)
    installation_id = _require_installation_id(paths)
    events = views.read_events(paths, installation_id)
    if as_json:
        click.echo(json.dumps([asdict(event) for event in events], sort_keys=True))
        return
    if not events:
        click.echo("no spooled records")
        return
    for event in events:
        click.echo(
            f"{event.record_id} {event.record_type}/{event.name} "
            f"occurred={event.occurred_at} expires={event.expires_at} "
            f"target={event.target_id} class={event.privacy_class} severity={event.severity}"
        )


@main.command(name="doctor")
@click.option("--json", "as_json", is_flag=True, help="Emit the diagnostic as stable JSON.")
@click.pass_context
def doctor_command(context: click.Context, as_json: bool) -> None:
    """Run a richer redacted diagnostic (health plus spool totals); exit non-zero on a problem."""

    state = context.ensure_object(CliState)
    paths = _resolve_paths(state)
    report = views.doctor(paths, now=SystemClock().now())
    if as_json:
        click.echo(
            json.dumps(
                {
                    "ok": report.ok,
                    "health": {
                        "status": report.health.status,
                        "checks": [asdict(check) for check in report.health.checks],
                    },
                    "segment_count": report.segment_count,
                    "record_count": report.record_count,
                    "spool_readable": report.spool_readable,
                },
                sort_keys=True,
            )
        )
    else:
        for check in report.health.checks:
            click.echo(f"[{'ok' if check.ok else 'FAIL'}] {check.name}: {check.detail}")
        click.echo(
            f"spool: segments={report.segment_count} records={report.record_count} "
            f"readable={report.spool_readable}"
        )
        click.echo(f"status: {'ok' if report.ok else 'problem'}")
    if not report.ok:
        context.exit(1)


class StorageCommandError(click.ClickException):
    """A stable ClickHouse-storage failure using the CLI contract's exit code 1."""

    exit_code = 1

    def __init__(self, error: storage.StorageError) -> None:
        self.code = error.code
        super().__init__(str(error))


class StorageExportError(click.ClickException):
    """A stable ``storage export`` drain failure using the CLI contract's exit code 1.

    The ledger-gated export spans two fail-closed layers — the spool's replay/delivery machine
    (``MH_SPOOL_*``) and the ClickHouse egress (``MH_STORAGE_*``) — so this sibling of
    :class:`StorageCommandError` accepts either coded error and preserves its fixed machine code.
    """

    exit_code = 1

    def __init__(self, error: SpoolError | storage.StorageError) -> None:
        self.code = error.code
        super().__init__(str(error))


def _storage_client(state: CliState) -> tuple[str, storage.ConnectedClickHouseClient]:
    config, paths = _resolve_config(state)
    clickhouse = config.storage.clickhouse
    if not clickhouse.enabled:
        raise StorageCommandError(
            storage.StorageError("MH_STORAGE_CONFIG", "storage.clickhouse is disabled in config")
        )
    try:
        secrets = load_secret_environment(config, paths)
    except ConfigError as error:
        raise ConfigCommandError(error) from None
    try:
        client = storage.build_client(clickhouse, secrets)
    except storage.StorageError as error:
        raise StorageCommandError(error) from None
    return clickhouse.database, client


def _emit_plan(report: storage.StoragePlan, as_json: bool) -> None:
    if as_json:
        click.echo(
            json.dumps(
                {
                    "database": report.database,
                    "current_version": report.current_version,
                    "migrations": [
                        {"version": state.version, "name": state.name, "applied": state.applied}
                        for state in report.states
                    ],
                },
                sort_keys=True,
            )
        )
        return
    for state in report.states:
        marker = "applied" if state.applied else "pending"
        click.echo(f"[{marker}] {state.version:04d}_{state.name}")
    click.echo(
        f"database={report.database} current_version={report.current_version} "
        f"pending={len(report.pending)}"
    )


@main.group(name="storage")
def storage_group() -> None:
    """Manage the ClickHouse analytical store (migration status, plan, and apply)."""


@storage_group.command(name="status")
@click.option("--json", "as_json", is_flag=True, help="Emit the status as stable JSON.")
@click.pass_obj
def storage_status_command(state: CliState, as_json: bool) -> None:
    """Report applied vs pending migrations without mutating anything."""

    database, client = _storage_client(state)
    try:
        report = storage.status(client, database)
    except storage.StorageError as error:
        raise StorageCommandError(error) from None
    finally:
        client.close()
    _emit_plan(report, as_json)


@storage_group.command(name="plan")
@click.option("--json", "as_json", is_flag=True, help="Emit the plan as stable JSON.")
@click.pass_obj
def storage_plan_command(state: CliState, as_json: bool) -> None:
    """Show which migrations a subsequent ``migrate`` would apply, without mutating anything."""

    database, client = _storage_client(state)
    try:
        report = storage.plan(client, database)
    except storage.StorageError as error:
        raise StorageCommandError(error) from None
    finally:
        client.close()
    _emit_plan(report, as_json)


@storage_group.command(name="migrate")
@click.option("--json", "as_json", is_flag=True, help="Emit the result as stable JSON.")
@click.pass_obj
def storage_migrate_command(state: CliState, as_json: bool) -> None:
    """Apply every pending migration in order under the exclusive commit barrier; refuse a tamper.

    The whole apply runs while THIS installation's control-plane commit lock is held EXCLUSIVELY, so
    ``storage export`` — which delivers ClickHouse rows under the *shared* side of the same lock —
    cannot write ClickHouse while a schema change is in flight. A table-rebuild migration (0005's
    copy → swap → drop of ``feedback_transitions``) must have no concurrent ClickHouse writer, or a
    row inserted into the old table between the copy and the swap would be dropped. The exclusive
    acquisition blocks until any in-flight export drains (writer preference), then proceeds. An
    altered applied checksum is still refused. Requires an initialized control plane (the commit
    lock lives under its control dir).

    NOTE: this fence holds only because ``storage export`` is the SOLE production ClickHouse writer
    and it delivers under ``barrier.shared()``. ANY future ClickHouse writer MUST likewise take the
    shared side of this same commit lock, or it could race a migration and lose data.
    """

    paths = _resolve_paths(state)
    _require_installation_id(paths)  # the commit lock lives under an initialized control dir
    database, client = _storage_client(state)
    barrier = GlobalCommitBarrier(
        paths.state_root / bootstrap.CONTROL_DIRNAME / bootstrap.BARRIER_NAME
    )
    try:
        with barrier.exclusive():
            result = storage.migrate(
                client, database, now=SystemClock().now(), milhouse_version=__version__
            )
    except storage.StorageError as error:
        raise StorageCommandError(error) from None
    finally:
        client.close()
    if as_json:
        click.echo(
            json.dumps(
                {
                    "database": result.database,
                    "applied_now": list(result.applied_now),
                    "already_applied": list(result.already_applied),
                    "current_version": result.current_version,
                },
                sort_keys=True,
            )
        )
        return
    click.echo(
        f"migrate: applied {len(result.applied_now)} migration(s) "
        f"({len(result.already_applied)} already applied); "
        f"schema at version {result.current_version}"
    )


@storage_group.command(name="export")
@click.option("--json", "as_json", is_flag=True, help="Emit the result as stable JSON.")
@click.pass_context
def storage_export_command(context: click.Context, as_json: bool) -> None:
    """Deliver committed spool segments to ClickHouse through the exactly-once delivery ledger.

    The export drives the spool's G03-certified :func:`~milhouse.spooling.replay.replay_segments`
    machine — the proven double-replay recovery shape — over the ``clickhouse`` delivery ledger, so
    a run is a full drain of every committed segment. A not-yet-delivered segment (``pending`` OR a
    prior run's ``failed``) is trusted-read, forwarded once through
    :class:`~milhouse.storage.delivery.ClickHouseExporter`, and checkpointed ``delivered`` under one
    compare-and-set; an already-``delivered`` segment is an idempotent no-op — re-read and
    re-verified against its ledger row, but never re-inserted (no duplicate ``records`` row, no
    appended ``feedback_transitions`` row). A re-run therefore recovers a segment whose delivery
    failed during an outage while leaving delivered segments untouched. A segment that still ends
    the pass ``failed`` is not in ClickHouse, so the export is incomplete — surfaced loudly on
    stderr with a non-zero exit rather than reported as a full success. A committed segment with no
    ``clickhouse`` delivery obligation (its ``required_exporters`` omit clickhouse) is likewise not
    in ClickHouse: it is reported as ``unhandled`` and the export is incomplete (non-zero exit) too.
    The reported ``records`` count is CONFIRMED egress only — segments ``delivered`` this pass or
    ``already_delivered`` before — so a ``failed`` / ``expired`` / ``unhandled`` segment (each
    surfaced by its own count) never inflates it.
    """

    state = context.ensure_object(CliState)
    paths = _resolve_paths(state)
    installation_id = _require_installation_id(paths)
    control = open_control_database(bootstrap.database_path(paths))
    try:
        database, client = _storage_client(state)
        try:
            barrier = GlobalCommitBarrier(
                paths.state_root / bootstrap.CONTROL_DIRNAME / bootstrap.BARRIER_NAME
            )
            report = replay_segments(
                control,
                barrier,
                spool_root=paths.spool,
                installation_id=installation_id,
                exporters={
                    storage.CLICKHOUSE_EXPORTER_ID: storage.ClickHouseExporter(client, database)
                },
                now=SystemClock().now(),
                # Drain ALL committed segments, not only ``pending``: the delivery ledger's CAS
                # makes an already-``delivered`` segment an idempotent no-op, and this is the only
                # scope that ALSO retries a segment left ``failed`` by an earlier ClickHouse outage
                # — the core G04b recovery property. This is the proven G03 double-replay shape.
                # Cost: delivered-but-unpruned segments are re-read each run; it is bounded because
                # retention prunes delivered segments, and a future "not-delivered" (pending OR
                # failed) ledger filter could avoid the re-read (follow-up optimization).
                delivery_status=None,
            )
            # A committed segment with no ``clickhouse`` delivery attempt (its required_exporters
            # omit clickhouse, e.g. an empty set or only a different destination) is drained but
            # never forwarded here — it is not in ClickHouse. Identify those, and scope the reported
            # record count to CONFIRMED egress only. Read per-segment counts while control is open.
            clickhouse_attempts = [
                attempt
                for attempt in report.delivery_attempts
                if attempt.exporter_id == storage.CLICKHOUSE_EXPORTER_ID
            ]
            handled_batches = {attempt.batch_id for attempt in clickhouse_attempts}
            unhandled_batches = tuple(
                batch_id for batch_id in report.segments if batch_id not in handled_batches
            )
            # ``records`` counts only segments whose clickhouse delivery is CONFIRMED in the store —
            # ``delivered`` this pass or ``already_delivered`` on a prior one. A ``failed`` (retry-
            # eligible, not yet written), ``expired`` (withheld), or ``unhandled`` segment is NOT
            # confirmed egress and is excluded, so the count never overstates the store. Those
            # segments are surfaced by their own separate counts and stderr notes.
            confirmed_batches = {
                attempt.batch_id
                for attempt in clickhouse_attempts
                if attempt.outcome in ("delivered", "already_delivered")
            }
            record_counts = {
                record.batch_id: record.record_count for record in list_segment_records(control)
            }
            confirmed_records = sum(
                record_counts.get(batch_id, 0)
                for batch_id in report.segments
                if batch_id in confirmed_batches
            )
        except (storage.StorageError, SpoolError) as error:
            raise StorageExportError(error) from None
        finally:
            client.close()
    finally:
        control.close()

    outcomes = Counter(attempt.outcome for attempt in report.delivery_attempts)
    delivered = outcomes["delivered"]
    already_delivered = outcomes["already_delivered"]
    failed = outcomes["failed"]
    expired = outcomes["expired"]
    unhandled = len(unhandled_batches)
    if as_json:
        click.echo(
            json.dumps(
                {
                    "already_delivered": already_delivered,
                    "delivered": delivered,
                    "expired": expired,
                    "failed": failed,
                    "records": confirmed_records,
                    "segments": len(report.segments),
                    "unhandled": unhandled,
                },
                sort_keys=True,
            )
        )
    else:
        click.echo(
            f"export: segments={len(report.segments)} records={confirmed_records} "
            f"delivered={delivered} already_delivered={already_delivered} "
            f"failed={failed} expired={expired} unhandled={unhandled}"
        )
    if expired:
        # An expired segment is withheld (privacy-correct — records past their hard privacy expiry
        # must never egress) but is therefore NOT in ClickHouse. That is not an error (only a
        # ``failed`` or ``unhandled`` segment forces a non-zero exit), but it must be observable.
        click.echo(
            f"NOTE: {expired} segment(s) withheld — records reached their privacy expiry "
            "before delivery and were not exported",
            err=True,
        )
    if unhandled:
        # A committed segment with no clickhouse delivery obligation is drained but NOT in
        # ClickHouse, so an export/rebuild over it is INCOMPLETE — surface it and exit non-zero.
        # This blanket non-zero exit is correct while ``clickhouse`` is the ONLY exporter id: an
        # unhandled segment is genuinely missing from the store. FOLLOW-UP: once a second real
        # exporter exists, ``storage export`` should distinguish "no clickhouse obligation"
        # (informational, exit 0 — that segment was never meant for ClickHouse) from "failed
        # clickhouse delivery" (exit 1), rather than treating both as incomplete here.
        click.echo(
            f"NOTE: {unhandled} committed segment(s) had no clickhouse delivery obligation "
            "and were not exported; export incomplete",
            err=True,
        )
    if failed:
        # A segment whose delivery raised is retryable but NOT yet in ClickHouse, so this export is
        # INCOMPLETE — surface it loudly and non-zero rather than imply a full success.
        click.echo(f"WARNING: {failed} segment delivery(ies) failed; export incomplete", err=True)
    if failed or unhandled:
        context.exit(1)


@storage_group.command(name="records")
@click.option("--target", "target_id", default=None, help="Filter to one target id.")
@click.option("--json", "as_json", is_flag=True, help="Emit the records as stable JSON.")
@click.pass_obj
def storage_records_command(state: CliState, target_id: str | None, as_json: bool) -> None:
    """Query the current (deduplicated, non-expired) records from the store."""

    database, client = _storage_client(state)
    try:
        rows = storage.fetch_current_records(client, database, target_id=target_id)
    except storage.StorageError as error:
        raise StorageCommandError(error) from None
    finally:
        client.close()
    if as_json:
        click.echo(json.dumps([asdict(row) for row in rows], sort_keys=True))
        return
    if not rows:
        click.echo("no current records")
        return
    for row in rows:
        click.echo(
            f"{row.record_id} {row.record_type}/{row.name} occurred={row.occurred_at} "
            f"expires={row.expires_at} target={row.target_id} class={row.privacy_class} "
            f"severity={row.severity}"
        )


@storage_group.command(name="feedback")
@click.option("--json", "as_json", is_flag=True, help="Emit the feedback state as stable JSON.")
@click.pass_obj
def storage_feedback_command(state: CliState, as_json: bool) -> None:
    """Query feedback items' transition-derived current state (open-only items show in records)."""

    database, client = _storage_client(state)
    try:
        rows = storage.fetch_current_feedback(client, database)
    except storage.StorageError as error:
        raise StorageCommandError(error) from None
    finally:
        client.close()
    if as_json:
        click.echo(json.dumps([asdict(row) for row in rows], sort_keys=True))
        return
    if not rows:
        click.echo("no feedback items")
        return
    for row in rows:
        click.echo(
            f"{row.item_id} state={row.current_state} revision={row.current_revision} "
            f"last={row.last_transition_at}"
        )
