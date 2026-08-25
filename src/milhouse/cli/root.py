"""Root Click command for the Milhouse CLI."""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Protocol

import click
from platformdirs import user_config_path, user_data_path

from milhouse import __version__, storage
from milhouse.cli import bootstrap, demo, views
from milhouse.collectors.file_outbox import FileOutboxBinding, register_file_outbox
from milhouse.collectors.site_canary import SITE_CANARY_TYPE, register_site_canary
from milhouse.config import (
    ConfigError,
    RuntimePaths,
    generate_json_schema_bytes,
    load_config,
    load_secret_environment,
    resolve_config_source_path,
    resolve_runtime_paths,
)
from milhouse.config._models import (
    CollectorConfig,
    FileOutboxCollector,
    MilhouseConfig,
    TargetConfig,
)
from milhouse.core.clock import SystemClock
from milhouse.privacy.keys import load_pseudonym_key
from milhouse.privacy.pseudonym import PrivacyError
from milhouse.privacy.redact import LayeredRedactor
from milhouse.runtime import (
    CollectorRegistry,
    PipelineError,
    PipelineRunSummary,
    RuntimeMode,
    RuntimePipeline,
)
from milhouse.spooling import SpoolError, replay_segments
from milhouse.spooling.exporter import Exporter
from milhouse.spooling.ledger import list_segment_records
from milhouse.state import (
    ControlDatabase,
    GlobalCommitBarrier,
    StateError,
    open_control_database,
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


class _CodedError(Protocol):
    """Structural type for an underlying failure that carries a fixed machine ``.code``."""

    @property
    def code(self) -> str: ...


class _CodedCommandError(click.ClickException):
    """Base for CLI failures that surface an underlying coded error's fixed machine code.

    Carries the common body every exit-1 command error shares: it records the fixed ``.code`` of an
    underlying coded failure (a bootstrap, spool, state, pipeline, privacy, or storage error) and
    renders that error's bounded, value-safe string. Those errors expose only fixed strings — never
    key material, a secret, a path, a URL, or a payload — so rendering the code and message here
    leaks nothing. Subclasses set only their ``exit_code``; behaviour (exit code and rendering) is
    identical to the per-class bodies this base replaces.
    """

    def __init__(self, error: _CodedError) -> None:
        self.code = error.code
        super().__init__(str(error))


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


class BootstrapCommandError(_CodedCommandError):
    """A stable bootstrap failure using the CLI contract's exit code 1."""

    exit_code = 1


@main.command(name="init")
@click.option("--json", "as_json", is_flag=True, help="Emit the result as stable JSON.")
@click.pass_obj
def init_command(state: CliState, as_json: bool) -> None:
    """Initialize the state root, control database, installation identity, and pseudonym key.

    Fully idempotent: a re-run creates only what is missing and NEVER rotates the pseudonym key the
    runtime redactor requires. Reports only whether each artifact was created — never any key
    material. Exit 0 on success, 1 on a bootstrap failure, 2 on an invalid configuration.
    """

    config, paths = _resolve_config(state)
    try:
        report = bootstrap.initialize(paths, now=SystemClock().now(), config=config)
    except bootstrap.BootstrapError as error:
        raise BootstrapCommandError(error) from None
    if as_json:
        click.echo(
            json.dumps(
                {
                    "created_directories": list(report.created_directories),
                    "schema_version": report.schema_version,
                    "installation_id_created": report.installation_id_created,
                    "pseudonym_key_created": report.pseudonym_key_created,
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
    key = "created" if report.pseudonym_key_created else "present"
    click.echo(
        f"initialized: directories={created}; schema {report.schema_version}; "
        f"installation id {identity}; pseudonym key {key}"
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


class CollectCommandError(_CodedCommandError):
    """A stable ``collect`` failure using the CLI contract's exit code 1.

    Carries the fixed machine code of an underlying coded failure — a privacy, spool, state, or
    pipeline error (all :class:`~milhouse.core.errors.MilhouseError` subclasses with a ``.code``).
    Those errors expose only bounded, fixed strings — never key material, a secret, a path, a URL,
    or a payload — so rendering the code and message here leaks nothing.
    """

    exit_code = 1


def _new_collect_registry(config: MilhouseConfig, paths: RuntimePaths) -> CollectorRegistry:
    """Build the production first-party collector registry (real HTTP-backed site_canary + outbox).

    A module-level seam so a network-free test can substitute a registry holding a fake collector;
    production ``collect`` always calls it with the real registry. The ``file_outbox`` factory is
    PATH-BOUND: each configured ``file_outbox`` collector's relative outbox path is resolved here
    (symlink-free, from the config directory) into an absolute file, and its parent is the
    owner-only ``.milhouse`` acknowledgement directory — so the collector, like site_canary with its
    URL, is bound to a resolved path and never resolves an ambient one. Resolving a path never
    requires the file to exist, so an outbox that has not been written yet still binds cleanly.
    """

    registry = CollectorRegistry()
    register_site_canary(registry)
    outbox_bindings: dict[str, FileOutboxBinding] = {}
    for collector in config.collectors:
        if not isinstance(collector, FileOutboxCollector):
            continue
        outbox_path = resolve_config_source_path(collector.path, config_dir=paths.config_dir)
        outbox_bindings[collector.id] = FileOutboxBinding(
            outbox_path=outbox_path, ack_directory=outbox_path.parent
        )
    if outbox_bindings:
        register_file_outbox(registry, outbox_paths=outbox_bindings)
    return registry


def _build_collect_pipeline(
    config: MilhouseConfig,
    paths: RuntimePaths,
    installation_id: str,
    control: ControlDatabase,
    *,
    mode: RuntimeMode,
    exporters: Mapping[str, Exporter],
    redactor: LayeredRedactor,
) -> RuntimePipeline:
    """Assemble a mode-aware :class:`RuntimePipeline` from validated config and control plane.

    The testable seam the ``collect`` command builds through. It always uses the production
    first-party registry (:func:`_new_collect_registry`, whose site_canary factory builds a live
    HTTP client); a network-free test substitutes it by monkeypatching that module-level factory.
    The caller supplies the already-built :class:`LayeredRedactor` the pipeline hard-requires,
    loaded from the keyed pseudonym key ``init`` provisions BEFORE any client or control handle is
    opened — so a missing/corrupt key fails closed "run milhouse init first" without leaving a
    ClickHouse client or an empty control DB behind. ``config_generation`` is the deterministic
    64-hex digest of the fully validated config, which the pipeline re-checks. The caller supplies
    ``mode`` and the matching ``exporters`` map — empty for ``spool_only``, the ClickHouse exporter
    keyed by its exporter id for ``full`` — and the pipeline ctor enforces that invariant (``full``
    requires a non-empty map, ``spool_only`` an empty one), so the full-mode obligation lives here
    rather than in a separate reject guard.
    """

    registry = _new_collect_registry(config, paths)
    barrier = GlobalCommitBarrier(bootstrap.barrier_path(paths))
    return RuntimePipeline(
        mode=mode,
        # Reuse the digest ``_resolve_config`` already computed and bound into the runtime paths:
        # the loader sets ``config_selection.config_digest = validated_config_digest(config)`` for
        # this exact config, and ``verify_config_generation`` enforces their equality as a runtime
        # invariant, so it is byte-identical to recomputing it here (a unit test locks this).
        config_generation=paths.config_selection.config_digest,
        registry=registry,
        redactor=redactor,
        control=control,
        barrier=barrier,
        spool_root=paths.spool,
        installation_id=installation_id,
        clock=SystemClock(),
        retention=config.retention,
        exporters=exporters,
        alert_rules=config.alert_rules,
        notifications=config.notifications,
    )


def _collect_run_payload(summary: PipelineRunSummary) -> dict[str, object]:
    """Project a run summary into the privacy-safe JSON payload (counts, codes, config ids)."""

    return {
        "mode": summary.mode,
        "alerts_fired": summary.alerts_fired,
        "alerts_resolved": summary.alerts_resolved,
        "alerts_error_code": summary.alerts_error_code,
        "intents_emitted": summary.intents_emitted,
        "intents_error_code": summary.intents_error_code,
        "export_error_code": summary.export_error_code,
        "records_committed": summary.records_committed,
        "records_delivered": summary.records_delivered,
        "records_failed": summary.records_failed,
        "collectors": [
            {
                "collector_id": collector.collector_id,
                "status": collector.status,
                "error_code": collector.error_code,
                "drafts_produced": collector.drafts_produced,
                "records_committed": collector.records_committed,
                "records_delivered": collector.records_delivered,
                "records_failed": collector.records_failed,
                "batch_id": collector.batch_id,
            }
            for collector in summary.collectors
        ],
    }


def _collect_run_failed(summary: PipelineRunSummary) -> bool:
    """The exit-1 predicate: any stage error code, a failed record, or a failed/error collector."""

    return (
        summary.export_error_code is not None
        or summary.alerts_error_code is not None
        or summary.intents_error_code is not None
        or summary.records_failed > 0
        or any(collector.status in ("failed", "error") for collector in summary.collectors)
    )


def _run_collect(
    context: click.Context,
    state: CliState,
    config: MilhouseConfig,
    paths: RuntimePaths,
    collectors: Sequence[CollectorConfig],
    targets: Sequence[TargetConfig],
    *,
    as_json: bool,
) -> None:
    """Run the already-filtered ``collectors`` once through the runtime pipeline, then exit.

    The shared body ``collect run`` and the ``canary`` shorthand both call after doing their own
    collector selection. It takes the ALREADY-FILTERED ``collectors`` plus the full ``targets`` set
    (passed to the pipeline for lookup) and performs everything from the pseudonym-key/redactor load
    through the exit: the fail-closed key guard BEFORE any handle opens, the mode-aware full-mode
    ClickHouse client lifecycle (client closed in ``finally`` on every path), the coded exit-1
    mapping for a whole-run abort, the privacy-safe ``--json``/human summary, the per-stage and
    per-collector stderr WARNINGs, and the exit-code contract (``context.exit(1)`` on failure). The
    behaviour is identical for either caller — the only thing that differs is which collectors were
    selected upstream.
    """

    installation_id = _require_installation_id(paths)
    # Load the pseudonym key and build the redactor the pipeline hard-requires BEFORE opening any
    # ClickHouse client or control handle, so a missing/corrupt key fails closed "run milhouse init
    # first" without wasting a client/DB open — which could otherwise leave an empty control DB
    # behind. The collectors are the primary redaction authority, so no extra known secrets here.
    try:
        pseudonymizer = load_pseudonym_key(config, paths)
    except PrivacyError as error:
        if error.code == "MH_PRIVACY_KEY_NOT_FOUND":
            raise BootstrapCommandError(
                bootstrap.BootstrapError("MH_NOT_INITIALIZED", "run milhouse init first")
            ) from None
        raise CollectCommandError(error) from None
    redactor = LayeredRedactor(pseudonymizer, known_secrets=())

    # Full mode delivers committed segments to ClickHouse via the pipeline's delivery tail, so it
    # needs an authenticated client and the ClickHouse exporter; spool_only needs neither. Open the
    # client BEFORE the control handle so a storage-config failure (clickhouse disabled/unbuildable,
    # or a bad secret env) surfaces its own coded exit without ever acquiring a control handle.
    client: storage.ConnectedClickHouseClient | None = None
    database: str | None = None
    if config.runtime.mode == "full":
        database, client = _storage_client(state)
    control = open_control_database(bootstrap.database_path(paths))
    try:
        exporters: dict[str, Exporter] = {}
        if client is not None and database is not None:
            # Refuse to deliver to a destination this installation does not own (fail closed) — the
            # same read barrier ``storage export`` takes: an UNCLAIMED destination raises
            # ``MH_STORAGE_OWNERSHIP`` with "run storage migrate first", a FOREIGN owner is refused.
            # Placed BEFORE the pipeline commits/exports, so a full run over an unowned ClickHouse
            # strands nothing.
            storage.require_owner(client, database, installation_id=installation_id)
            exporters = {
                storage.CLICKHOUSE_EXPORTER_ID: storage.ClickHouseExporter(client, database)
            }
        pipeline = _build_collect_pipeline(
            config,
            paths,
            installation_id,
            control,
            mode=config.runtime.mode,
            exporters=exporters,
            redactor=redactor,
        )
        # The full target set is passed for lookup; the collector filters above scope the run.
        summary = pipeline.run(tuple(collectors), tuple(targets))
    except ConfigError as error:
        # Building the pipeline resolves each file_outbox collector's outbox path (symlink-free,
        # from the config dir). A symlinked/uninspectable path is a CONFIGURATION fault, so surface
        # it as the exit-2 config-error contract every other config problem uses -- a clean
        # ``error: config.path.*`` rather than a raw traceback. Like the unknown-collector/target
        # guards, a bad configured path is a whole-run config error, not a per-collector isolation.
        raise ConfigCommandError(error) from None
    except (SpoolError, StateError, PipelineError, storage.StorageError) as error:
        # A spool-integrity, control-state, pipeline-construction, or ClickHouse-ownership failure
        # (e.g. DurableSpool reconciliation, a tampered barrier, a crashed-prior-writer orphan, an
        # unclaimed/foreign destination) must surface as the coded exit-1 contract every other
        # command produces -- a clean ``error: MH_...`` rather than a raw traceback. Per-collector
        # faults AND a contained ClickHouse delivery failure are already isolated INTO the summary
        # (records_failed / export_error_code → exit 1 below); this catches only failures that abort
        # the whole run. The key-missing / other PrivacyError mapping ran earlier (before any handle
        # opened), so it never reaches here.
        raise CollectCommandError(error) from None
    finally:
        # Close the ClickHouse client and the control handle on EVERY path (ownership failure,
        # pipeline error, or clean success), so a full run never leaks the client; spool_only opens
        # none, so ``client is None`` and only the control handle is closed.
        if client is not None:
            client.close()
        control.close()

    if as_json:
        click.echo(json.dumps(_collect_run_payload(summary), sort_keys=True))
    else:
        click.echo(
            f"collect: mode={summary.mode} committed={summary.records_committed} "
            f"delivered={summary.records_delivered} failed={summary.records_failed} "
            f"alerts_fired={summary.alerts_fired} alerts_resolved={summary.alerts_resolved} "
            f"intents_emitted={summary.intents_emitted}"
        )
        for collector in summary.collectors:
            code = collector.error_code or "none"
            batch = collector.batch_id or "none"
            click.echo(
                f"  {collector.collector_id}: status={collector.status} error={code} "
                f"drafts={collector.drafts_produced} committed={collector.records_committed} "
                f"delivered={collector.records_delivered} failed={collector.records_failed} "
                f"batch={batch}"
            )
    stage_error_codes: tuple[tuple[str, str | None], ...] = (
        ("export", summary.export_error_code),
        ("alerts", summary.alerts_error_code),
        ("intents", summary.intents_error_code),
    )
    for label, stage_code in stage_error_codes:
        if stage_code is not None:
            click.echo(f"WARNING: the {label} stage reported {stage_code}", err=True)
    # A failed/error collector forces exit 1; emit a uniform per-collector stderr WARNING (the same
    # operator signal the stage errors give), privacy-safe: only the config-declared collector id
    # and its fixed error code -- never a payload, path, URL, or secret.
    for collector in summary.collectors:
        if collector.status in ("failed", "error"):
            click.echo(
                f"WARNING: collector {collector.collector_id} ended {collector.status} "
                f"({collector.error_code or 'none'})",
                err=True,
            )
    if _collect_run_failed(summary):
        context.exit(1)


@main.group(name="collect")
def collect_group() -> None:
    """Run configured collectors once into the local spool (spool-only), or list them."""


@collect_group.command(name="run")
@click.argument("collector_id", required=False)
@click.option(
    "--target",
    "target_id",
    default=None,
    metavar="TARGET_ID",
    help="Run only the collectors bound to this declared target id.",
)
@click.option("--json", "as_json", is_flag=True, help="Emit the run summary as stable JSON.")
@click.pass_context
def collect_run_command(
    context: click.Context,
    collector_id: str | None,
    target_id: str | None,
    as_json: bool,
) -> None:
    """Collect, redact, and spool every configured collector once; in full mode also export.

    Builds the W05 runtime pipeline in the configured ``runtime.mode`` and runs it a single time:
    each collector's drafts are redacted, finalized, and committed to the local spool, and the
    configured canary alert rules and notification-intent records are evaluated inside that run. In
    ``spool_only`` mode nothing is exported. In ``full`` mode the committed segments are delivered
    to ClickHouse through the same exactly-once delivery ledger ``storage export`` drives, so a
    full-mode run additionally requires ClickHouse configured (``storage.clickhouse.enabled``) AND
    the destination already migrated and claimed by THIS installation — run ``storage migrate``
    first. Requires an initialized install (run ``milhouse init`` first): the pipeline's redactor
    needs the keyed pseudonym key that ``init`` provisions.

    An optional ``COLLECTOR_ID`` runs only that configured collector; ``--target`` runs only the
    collectors bound to that declared target. An unknown collector or target id is a configuration
    error. The emitted summary carries ONLY privacy-safe counts, fixed codes, and config-declared
    ids — never a secret, PII, path, payload, URL, or target host.

    Exit codes: 0 clean; 1 if any stage error code is set OR any records failed (including a
    contained ClickHouse delivery failure, which is non-fatal but reported) OR any collector ended
    ``failed``/``error`` OR the run aborts with a coded spool/state/pipeline failure OR (full mode)
    the ClickHouse destination is unclaimed/foreign-owned or ClickHouse is disabled/unbuildable; 2
    for an invalid configuration — an unknown collector or target id, or (full mode) an unresolvable
    ClickHouse secret/config (both surface the same exit-2 config error as ``storage export``).
    """

    state = context.ensure_object(CliState)
    config, paths = _resolve_config(state)

    collectors = list(config.collectors)
    if collector_id is not None:
        collectors = [collector for collector in collectors if collector.id == collector_id]
        if not collectors:
            raise ConfigCommandError(
                ConfigError(
                    "config.collector.unknown", "no collector with the requested id is configured"
                )
            )
    if target_id is not None:
        if target_id not in {target.id for target in config.targets}:
            raise ConfigCommandError(
                ConfigError(
                    "config.target.unknown", "no target with the requested id is configured"
                )
            )
        collectors = [
            collector for collector in collectors if getattr(collector, "target", None) == target_id
        ]
        # A named collector that is not bound to the named target is an operator mistake, not an
        # empty run: fail closed (exit 2) rather than silently doing nothing. (``--target`` alone
        # with no bound collectors stays a legitimate empty run — exit 0 — and is not caught here.)
        if collector_id is not None and not collectors:
            raise ConfigCommandError(
                ConfigError(
                    "config.collector.unbound",
                    f"collector {collector_id} is not bound to target {target_id}",
                )
            )

    # The selected collectors and the full target set (for lookup) drive the shared run body, which
    # owns the key/redactor load, the mode-aware client lifecycle, the summary, and the exit codes.
    _run_collect(context, state, config, paths, collectors, config.targets, as_json=as_json)


@collect_group.command(name="list")
@click.option("--json", "as_json", is_flag=True, help="Emit the listing as stable JSON.")
@click.pass_obj
def collect_list_command(state: CliState, as_json: bool) -> None:
    """List the configured collectors' ids and kinds (privacy-safe; config-declared, not secret)."""

    config, _paths = _resolve_config(state)
    rows = [{"id": collector.id, "type": collector.type} for collector in config.collectors]
    if as_json:
        click.echo(json.dumps({"collectors": rows}, sort_keys=True))
        return
    if not rows:
        click.echo("no configured collectors")
        return
    for row in rows:
        click.echo(f"{row['id']}  type={row['type']}")


@main.command(name="canary")
@click.option(
    "--target",
    "target_id",
    default=None,
    metavar="TARGET_ID",
    help="Run only the site_canary collectors bound to this declared target id.",
)
@click.option("--json", "as_json", is_flag=True, help="Emit the run summary as stable JSON.")
@click.pass_context
def canary_command(context: click.Context, target_id: str | None, as_json: bool) -> None:
    """Run the configured ``site_canary`` collectors once — a shorthand for ``collect run``.

    A convenience wrapper that scopes a single runtime run to the configured ``site_canary``
    collectors (a network probe turned into one availability event each) and drives them through the
    SAME pipeline ``collect run`` uses: collect → redact → spool, plus the configured canary alert
    rules and notification-intent records evaluated in the same run, and — in ``full`` mode — the
    exactly-once ClickHouse delivery tail. Like ``collect run`` it requires an initialized install
    (the pipeline's redactor needs the keyed pseudonym key ``init`` provisions), and what a run does
    follows the required ``runtime.mode``: ``spool_only`` spools locally with no egress, while
    ``full`` additionally delivers to a ClickHouse destination that must already be migrated and
    claimed by THIS installation — run ``storage migrate`` first.

    ``--target`` runs only the canaries bound to that declared target; an unknown target id is a
    configuration error. If no ``site_canary`` collector matches, nothing is run: the command says
    so and exits 0 without opening any handle. The emitted summary carries ONLY privacy-safe counts,
    fixed codes, and config-declared ids — never a secret, PII, path, payload, URL, or target host.

    Exit codes match ``collect run``: 0 clean; 1 if any stage error code is set OR any records fail
    (including a contained ClickHouse delivery failure) OR any collector ended ``failed``/``error``
    OR the run aborts with a coded spool/state/pipeline failure OR (full mode) the ClickHouse
    destination is unclaimed/foreign-owned or ClickHouse is disabled/unbuildable; 2 for an invalid
    configuration — an unknown target id, or (full mode) an unresolvable ClickHouse secret/config.
    """

    state = context.ensure_object(CliState)
    config, paths = _resolve_config(state)

    collectors = [
        collector for collector in config.collectors if collector.type == SITE_CANARY_TYPE
    ]
    if target_id is not None:
        if target_id not in {target.id for target in config.targets}:
            raise ConfigCommandError(
                ConfigError(
                    "config.target.unknown", "no target with the requested id is configured"
                )
            )
        collectors = [
            collector for collector in collectors if getattr(collector, "target", None) == target_id
        ]

    # Nothing to run: report a clear, privacy-safe message (config-declared id only) and exit 0
    # WITHOUT loading the key or opening a control/ClickHouse handle -- there is nothing to spool.
    if not collectors:
        message = (
            f"no site_canary collectors bound to target {target_id}"
            if target_id is not None
            else "no site_canary collectors configured"
        )
        if as_json:
            # Honor the --json contract even on an empty run so a machine consumer always parses:
            # an empty ``collectors`` signals nothing ran.
            click.echo(json.dumps({"collectors": [], "message": message}, sort_keys=True))
        else:
            click.echo(message)
        return

    # The selected canaries and the full target set (for lookup) drive the shared run body, which
    # owns the key/redactor load, the mode-aware client lifecycle, the summary, and the exit codes.
    _run_collect(context, state, config, paths, collectors, config.targets, as_json=as_json)


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


class StorageCommandError(_CodedCommandError):
    """A stable ClickHouse-storage failure using the CLI contract's exit code 1."""

    exit_code = 1


class StorageExportError(_CodedCommandError):
    """A stable ``storage export`` drain failure using the CLI contract's exit code 1.

    The ledger-gated export spans two fail-closed layers — the spool's replay/delivery machine
    (``MH_SPOOL_*``) and the ClickHouse egress (``MH_STORAGE_*``) — so this sibling of
    :class:`StorageCommandError` accepts either coded error and preserves its fixed machine code.
    """

    exit_code = 1


class StorageRestoreError(_CodedCommandError):
    """A stable ``storage restore`` failure using the CLI contract's exit code 1.

    Restore spans two fail-closed layers — the native ClickHouse round-trip/verification
    (``MH_STORAGE_*``) and the cross-store reconciliation over the spool delivery ledger
    (``MH_SPOOL_*`` when a durable segment or the ledger cannot be read) — so, like its
    :class:`StorageExportError` sibling, it accepts either coded error and preserves the machine
    code. A verification or reconciliation mismatch surfaces as ``MH_STORAGE_RESTORE`` and exit 1.
    """

    exit_code = 1


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
@click.option(
    "--reclaim",
    is_flag=True,
    help="Take ownership of a destination currently claimed by another installation.",
)
@click.option("--json", "as_json", is_flag=True, help="Emit the result as stable JSON.")
@click.pass_obj
def storage_migrate_command(state: CliState, reclaim: bool, as_json: bool) -> None:
    """Apply every pending migration in order under the exclusive commit barrier; refuse a tamper.

    The whole apply runs while THIS installation's control-plane commit lock is held EXCLUSIVELY, so
    ``storage export`` — which delivers ClickHouse rows under the *shared* side of the same lock —
    cannot write ClickHouse while a schema change is in flight. A table-rebuild migration (0005's
    copy → swap → drop of ``feedback_transitions``) must have no concurrent ClickHouse writer, or a
    row inserted into the old table between the copy and the swap would be dropped. The exclusive
    acquisition blocks until any in-flight export drains (writer preference), then proceeds. An
    altered applied checksum is still refused. Requires an initialized control plane (the commit
    lock lives under its control dir).

    After the migrations apply (so the ``_installation`` control table exists), this CLAIMS the
    destination for THIS installation: "one ClickHouse per installation" is the supported model, and
    the claim makes the local commit barrier a correct single-writer exclusion. A first migrate
    stamps the local installation as owner; a re-run by the same installation verifies (a no-op). A
    destination already owned by a DIFFERENT installation is refused fail-closed (exit 1) UNLESS
    ``--reclaim`` is given — a deliberate re-point (moving this install to a new ClickHouse host),
    which supersedes the prior owner. On UPGRADE of a pre-existing destination migrated before this
    guard existed (no ``_installation`` row yet), the first install to migrate claims it — ownership
    is attributed to whoever migrates first, not retroactively to the original writer; in the
    supported one-per-destination model that is the sole rightful install, and a destination already
    (incorrectly) shared is taken back by the rightful owner with ``--reclaim``.

    NOTE: this fence holds only because ``storage export`` is the SOLE production ClickHouse writer
    and it delivers under ``barrier.shared()``. ANY future ClickHouse writer MUST likewise take the
    shared side of this same commit lock, or it could race a migration and lose data.
    """

    paths = _resolve_paths(state)
    installation_id = _require_installation_id(paths)  # the commit lock lives under a control dir
    database, client = _storage_client(state)
    barrier = GlobalCommitBarrier(bootstrap.barrier_path(paths))
    try:
        with barrier.exclusive():
            result = storage.migrate(
                client, database, now=SystemClock().now(), milhouse_version=__version__
            )
            # The migrations above provisioned ``_installation``; read the prior owner (to report
            # claimed vs verified vs reclaimed), then stamp/verify this installation's ownership.
            prior_owner = storage.read_owner(client, database)
            storage.claim(
                client,
                database,
                installation_id=installation_id,
                now=SystemClock().now(),
                milhouse_version=__version__,
                reclaim=reclaim,
            )
    except storage.StorageError as error:
        raise StorageCommandError(error) from None
    finally:
        client.close()
    if prior_owner is None:
        ownership = "claimed"
    elif prior_owner == installation_id:
        ownership = "verified"
    else:
        ownership = "reclaimed"
    if as_json:
        click.echo(
            json.dumps(
                {
                    "database": result.database,
                    "applied_now": list(result.applied_now),
                    "already_applied": list(result.already_applied),
                    "current_version": result.current_version,
                    "ownership": ownership,
                },
                sort_keys=True,
            )
        )
        return
    click.echo(
        f"migrate: applied {len(result.applied_now)} migration(s) "
        f"({len(result.already_applied)} already applied); "
        f"schema at version {result.current_version}; ownership {ownership}"
    )


@storage_group.command(name="backup")
@click.argument("destination")
@click.option("--json", "as_json", is_flag=True, help="Emit the result as stable JSON.")
@click.pass_obj
def storage_backup_command(state: CliState, destination: str, as_json: bool) -> None:
    """Create a native ClickHouse backup of the analytical database under the exclusive commit lock.

    The whole operation runs while THIS installation's control-plane commit barrier is held
    EXCLUSIVELY (plan section 10.3: retention, migration, restore, and another backup are blocked
    for its duration), so no ``storage export`` writer can mutate ClickHouse mid-backup — the same
    fence ``storage migrate`` takes. It records the source snapshot (record-id set + migration
    state) that a later restore is verified against, then issues a native ``BACKUP DATABASE`` to the
    configured backup disk. Requires an initialized control plane (the commit lock lives under its
    control dir). Emits the captured fingerprint; exit non-zero with a coded error on failure.

    OFFLINE/LIVE boundary: this increment wires and unit-tests the barrier fence, the validated
    statement, and the fingerprint. The REAL native ``BACKUP`` round-trip and its physical fidelity
    are host-gated (E06) and are not asserted here; the composite SQLite+manifest backup is W16.
    """

    paths = _resolve_paths(state)
    installation_id = _require_installation_id(paths)  # the commit lock lives under a control dir
    database, client = _storage_client(state)
    barrier = GlobalCommitBarrier(bootstrap.barrier_path(paths))
    try:
        with barrier.exclusive():
            # Refuse to back up a destination this installation does not own (fail closed): the
            # supported model is one ClickHouse per installation, and a foreign or unclaimed
            # destination is not this installation's data to snapshot.
            storage.require_owner(client, database, installation_id=installation_id)
            snapshot = storage.snapshot_state(client, database)
            client.command(storage.backup_statement(database, destination))
    except storage.StorageError as error:
        raise StorageCommandError(error) from None
    finally:
        client.close()
    if as_json:
        click.echo(
            json.dumps(
                {
                    "database": database,
                    "destination": destination,
                    "migration_version": snapshot.migration_version,
                    "record_count": len(snapshot.record_ids),
                },
                sort_keys=True,
            )
        )
        return
    click.echo(
        f"backup: database={database} destination={destination} "
        f"schema_version={snapshot.migration_version} records={len(snapshot.record_ids)}"
    )


@storage_group.command(name="restore")
@click.argument("source")
@click.option("--json", "as_json", is_flag=True, help="Emit the result as stable JSON.")
@click.pass_context
def storage_restore_command(context: click.Context, source: str, as_json: bool) -> None:
    """Restore a native ClickHouse backup into an EMPTY analytical database, then reconcile.

    A clean disaster-recovery restore under the EXCLUSIVE commit barrier (plan section 10.3), so
    nothing writes SQLite or ClickHouse during it. A native ``RESTORE DATABASE`` rejects a non-empty
    target, so the analytical database must be EMPTY or absent — lost to a disaster, or a fresh
    state root. If it already holds a schema the restore ABORTS with ``MH_STORAGE_RESTORE`` and
    issues NEITHER a drop NOR a restore — nothing destructive runs. Overwriting an existing database
    (verify source, restore into staging, validate, then cut over with rollback) is deferred to W16;
    there is no in-place overwrite here.

    After the native ``RESTORE`` it fails closed unless BOTH hold: (a) the restored ``_migrations``
    ledger is checksum-consistent and at the current defined schema head (via the read-only
    :func:`~milhouse.storage.runner.status`, which refuses a tampered ledger) — so a restore that
    brought no or a stale schema is rejected; and (b) a BOUNDED cross-store reconcile
    (``reconcile_delivered``) — every spool segment the surviving SQLite ledger marks ``delivered``
    to ``clickhouse`` has all of its record ids PRESENT in the restored store (a subset check, not
    full record-id-set equality — that stricter proof needs the W16 backup manifest).
    Feedback-state parity is deferred to G16. It ALSO fails closed if the restored ``_installation``
    owner row names a DIFFERENT installation (a cross-installation restore is unsupported): the
    foreign data has already materialized into the (proven-empty) target and the clean precondition
    is recovered by a manual ``DROP DATABASE`` (automatic rollback is W16). Requires an initialized
    control plane; any mismatch exits non-zero with the fixed ``MH_STORAGE_RESTORE``.

    OFFLINE/LIVE boundary: this proves the barrier fence, the empty-target guard, the statements,
    the schema-validity + bounded-reconcile wiring, and the exit codes offline against a fake
    client and a real spool ledger. The REAL native ``BACKUP``/``RESTORE`` round-trip, its
    physical/merge/TTL fidelity, and version compatibility are host-gated (E06); this increment does
    not claim G04b passed.
    """

    state = context.ensure_object(CliState)
    paths = _resolve_paths(state)
    installation_id = _require_installation_id(paths)
    control = open_control_database(bootstrap.database_path(paths))
    try:
        database, client = _storage_client(state)
        try:
            barrier = GlobalCommitBarrier(bootstrap.barrier_path(paths))
            with barrier.exclusive():
                # A native RESTORE DATABASE rejects a non-empty target, and this command never drops
                # or overwrites live data (that is W16). A present schema (any applied migration)
                # means the analytical tables exist, so abort before issuing ANY statement.
                if storage.status(client, database).current_version != 0:
                    raise storage.StorageError(
                        "MH_STORAGE_RESTORE",
                        "the analytical database is not empty; restore into a clean database "
                        "(overwriting an existing database is deferred to W16)",
                    )
                client.command(storage.restore_statement(database, source))
                # The restore must have brought a checksum-consistent schema at the current defined
                # head; status() refuses a tampered ledger, and an empty/stale restore fails here.
                restored_plan = storage.status(client, database)
                head = max((entry.version for entry in restored_plan.states), default=0)
                if head == 0 or restored_plan.current_version != head:
                    raise storage.StorageError(
                        "MH_STORAGE_RESTORE",
                        "the restore did not bring the current analytical schema",
                    )
                # The restored database carries the backup's ``_installation`` owner row (migration
                # 0006 is at the current head gated just above, so the row is present). A restore of
                # THIS installation's own backup verifies and proceeds; a restore of ANOTHER
                # installation's backup is refused fail-closed. This deliberately does NOT route
                # through ``require_owner``: that error's "--reclaim on migrate" guidance is WRONG
                # for a restore -- reclaiming would ADOPT the foreign backup, the very comingling
                # this guard prevents. The foreign slice has already materialized into the target
                # proven empty above, and in-place overwrite/rollback is W16, so the clean
                # precondition is recovered by a manual DROP DATABASE (named in the error and
                # ops/clickhouse/README.md), never by an automatic drop here.
                restored_owner = storage.read_owner(client, database)
                if restored_owner != installation_id:
                    raise storage.StorageError(
                        "MH_STORAGE_RESTORE",
                        "the restored backup was taken by a different installation; a "
                        "cross-installation restore is not supported -- DROP this database to "
                        "restore the empty precondition, then restore a backup taken by this "
                        "installation",
                    )
                restored = storage.snapshot_state(client, database)
                storage.reconcile_delivered(
                    control,
                    restored,
                    spool_root=paths.spool,
                    installation_id=installation_id,
                )
        except (storage.StorageError, SpoolError) as error:
            raise StorageRestoreError(error) from None
        finally:
            client.close()
    finally:
        control.close()
    if as_json:
        click.echo(
            json.dumps(
                {
                    "database": database,
                    "migration_version": restored.migration_version,
                    "reconciled": True,
                    "record_count": len(restored.record_ids),
                    "source": source,
                },
                sort_keys=True,
            )
        )
        return
    click.echo(
        f"restore: database={database} source={source} reconciled=True "
        f"schema_version={restored.migration_version} records={len(restored.record_ids)}"
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
            # Refuse to deliver to a destination this installation does not own (fail closed): the
            # supported model is one ClickHouse per installation, so a second install pointed at a
            # claimed destination — or an unclaimed one — must not write it. This read barrier makes
            # the local commit barrier a correct single-writer exclusion.
            #
            # Placed BEFORE the shared commit barrier (which replay_segments takes internally) on
            # purpose: the only actor sharing this per-state-root barrier is THIS install, whose id
            # is our own, so it cannot reclaim the destination away from itself; a DIFFERENT install
            # has its own barrier and is fenced by this op-time check regardless of ordering. So
            # — unlike backup/restore, which check inside their exclusive scope because they hold it
            # the whole operation — the placement here is a correctness no-op vs the barrier.
            storage.require_owner(client, database, installation_id=installation_id)
            barrier = GlobalCommitBarrier(bootstrap.barrier_path(paths))
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
