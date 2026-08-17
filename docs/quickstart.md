# Quickstart (pre-alpha)

> **Pre-alpha.** Milhouse is not released and not ready for production use. This quickstart focuses
> on the local path: it configures a state root, initializes the control database, installation
> identity, and pseudonym key, reports health, and runs the configured collectors into the local
> spool. Collection runs in one of two modes set by the required `runtime.mode` field: `spool_only`
> (local only — no network egress, no credentials, no ClickHouse) or `full` (additionally delivers to
> ClickHouse). The `demo` command is always spool-only. The checked-in `config/example.toml` ships
> `runtime.mode = "full"`; set it to `spool_only` for the local-only path below. Full-mode collection
> and the `storage` commands (which reach ClickHouse when configured) remain gated by later work
> packages (see [implementation-status.md](implementation-status.md)); their live evidence is still
> pending.

## 1. Provide a configuration

Milhouse is config-driven. Start from the checked-in [`config/example.toml`](../config/example.toml)
and edit the `[paths]` and `[[targets]]` sections for your machine. The `[paths] home` value is your
**state root** — every durable file lives beneath it.

Point the CLI at your config with `--config PATH`, the `MILHOUSE_CONFIG` environment variable, or the
platform default config location.

Validate it first (no network, no secret resolution):

```console
$ milhouse --config ./config.toml config validate
configuration is valid
```

## 2. Initialize the local install

`init` is idempotent: it creates the state-root layout (`control/`, `spool/`, `reports/`, `logs/`,
`backups/`) with owner-only permissions, applies the control-plane database schema under the commit
barrier, and generates a durable non-secret installation identity.

```console
$ milhouse --config ./config.toml init
initialized: directories=state_root, control, spool, reports, logs, backups; schema 11; installation id created

$ milhouse --config ./config.toml init
already initialized (schema 11)
```

## 3. Check health

`health` reports whether an initialized install is usable and returns a non-zero exit code when it is
not (so it composes in scripts). Add `--json` for a stable machine-readable report.

```console
$ milhouse --config ./config.toml health
[ok] directory:state_root: present
[ok] directory:control: present
[ok] directory:spool: present
[ok] directory:reports: present
[ok] directory:logs: present
[ok] directory:backups: present
[ok] control_database: schema 11
[ok] installation_identity: established
status: healthy

$ milhouse --config ./config.toml health --json
{"checks": [ ... ], "status": "healthy"}
```

## 4. Run the spool-only demo

`demo` exercises the whole local data path end to end without any network, credentials, or ClickHouse:
it builds one synthetic "site canary healthy" event, classifies it into a canonical record, writes it
to the durable spool through the commit barrier, and reads it back through the trusted reader to
verify it round-trips. It initializes the state root first if needed, and each run spools a fresh
uniquely-named segment (it never mutates or deletes prior spool data).

```console
$ milhouse --config ./config.toml demo
demo: spooled 1 record(s) to 2026-08-03/demo-5897ecb7364a4b3f; read-back ok

$ milhouse --config ./config.toml demo --json
{"batch_id": "demo-...", "day": "2026-08-03", "read_back_ok": true, "records_spooled": 1}
```

The spooled segment is a self-describing JSONL file under `<state root>/spool/pending/<day>/`, with a
header (frame/schema versions, batch id, config-generation digest, privacy/retention class, required
exporters, record count, and the ordered-frame SHA-256) followed by the redacted record frame.

## 5. Run configured collectors

`collect run` runs every configured collector once through the runtime pipeline: each collector's
drafts are redacted, finalized, and committed to the local spool, and the configured canary alert
rules and notification-intent records are evaluated in the same run. It requires an initialized
install — the pipeline's redactor needs the keyed pseudonym key `init` provisions — so a run before
`init`, or one whose key is missing, fails closed with `run milhouse init first` (a corrupt key
surfaces a specific `MH_PRIVACY_KEY_*` error instead, and `init` will not rotate an existing key).

The required `runtime.mode` in your config selects what a run does:

- **`spool_only`**: collect, redact, and spool locally — no network egress and no ClickHouse.
- **`full`**: additionally deliver the committed segments to ClickHouse through the same
  exactly-once delivery ledger `storage export` drives. Full mode requires ClickHouse configured
  (`storage.clickhouse.enabled`) **and** the destination already migrated and claimed by this
  installation, so run `storage migrate` first. This is the one path that reaches ClickHouse.

With `runtime.mode = "spool_only"` in your config, a local run needs no migrate step:

```console
$ milhouse --config ./config.toml init            # once; also provisions the pseudonym key
$ milhouse --config ./config.toml collect run
collect: mode=spool_only committed=1 delivered=0 failed=0 alerts_fired=0 alerts_resolved=0 intents_emitted=0
  example-canary: status=ok error=none drafts=1 committed=1 delivered=0 failed=0 batch=2026-08-16/...

$ milhouse --config ./config.toml collect list    # the configured collectors' ids and kinds
example-canary  type=site_canary
```

An optional `COLLECTOR_ID` runs only that collector, and `--target TARGET_ID` runs only the
collectors bound to that declared target. An unknown collector or target id — or a named collector
that is not bound to the named target — is a configuration error (exit 2). For a **full**-mode flow,
migrate and claim the ClickHouse destination first, then run:

```console
$ milhouse --config ./config.toml storage migrate   # apply schema + claim the destination (full mode)
$ milhouse --config ./config.toml collect run        # runtime.mode = "full": also delivers to ClickHouse
```

The `--json` summary carries only privacy-safe counts, fixed codes, and config-declared ids — never
a secret, payload, path, URL, or target host. `collect run` exits 0 when clean; 1 when any stage
error is set, any records failed (including a contained ClickHouse delivery failure), or any
collector ended `failed`/`error`; and 2 for an invalid configuration.

## 6. Inspect what you spooled

These commands are read-only and report privacy-safe **metadata only** — never the raw record
payload — consistent with the local-query egress policy.

```console
$ milhouse --config ./config.toml spool list
2026-08-03/demo-4eaebcb4...  records=1 bytes=1854 class=internal origin=committed delivered=False

$ milhouse --config ./config.toml events
mh_bkjjxhze...  event/source.event occurred=2026-08-03T21:12:51.732Z expires=... target=demo-target class=internal severity=info

$ milhouse --config ./config.toml spool show demo-4eaebcb4...   # one segment's header + record metadata
$ milhouse --config ./config.toml doctor                        # health + spool totals; nonzero exit on a problem
```

Add `--json` to any of them for a stable machine-readable form.

## Exit codes

| Code | Meaning |
|---:|---|
| `0` | Success; `health`/`doctor` report **healthy**; `demo` spooled and read back its record; `collect run` completed with no failures. |
| `1` | `health`/`doctor` report a problem; `init`/`demo` could not establish or exercise the state root; a `collect run` stage errored, a record failed, or a collector ended `failed`/`error`; or an inspect command was run before `init`. |
| `2` | The configuration is missing or invalid (including an unknown or unbound collector/target id). |

## What this is (and is not)

This is a product vertical built on the accepted W02 (configuration, identity, privacy) and W03
(SQLite control state and durable spool) foundations, now extended with the W04 ClickHouse store and
the W05/W06 runtime and `collect` surface. The offline behaviour is exercised here, but the runtime
and storage gates' **live** evidence is still pending, so treat full-mode ClickHouse delivery as
gated. Additional collectors and richer ClickHouse-backed query follow in later work packages.
