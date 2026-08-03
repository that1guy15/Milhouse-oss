# Quickstart (pre-alpha)

> **Pre-alpha.** Milhouse is not released and not ready for production use. This quickstart exercises
> the local, spool-only foundation only: it configures a state root, initializes the control
> database and installation identity, and reports health. No network, no credentials, no provider
> calls, and no ClickHouse are involved. Capabilities gated by later work packages
> (see [implementation-status.md](implementation-status.md)) are not available yet.

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
initialized: directories=state_root, control, spool, reports, logs, backups; schema 10; installation id created

$ milhouse --config ./config.toml init
already initialized (schema 10)
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
[ok] control_database: schema 10
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

## 5. Inspect what you spooled

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
| `0` | Success; `health`/`doctor` report **healthy**; `demo` spooled and read back its record. |
| `1` | `health`/`doctor` report a problem; `init`/`demo` could not establish or exercise the state root; or an inspect command was run before `init`. |
| `2` | The configuration is missing or invalid. |

## What this is (and is not)

This is a preparatory product vertical built on the accepted W02 (configuration, identity, privacy)
and W03 (SQLite control state and durable spool) foundations. It is tracked as a roadmap feature and
does **not** claim the W05 runtime or W06 initialization gates. The full CLI surface, real collectors,
and ClickHouse-backed query follow in later work packages.
