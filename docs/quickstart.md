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

## Exit codes

| Code | Meaning |
|---:|---|
| `0` | Success; `health` reports **healthy**. |
| `1` | `health` reports **unhealthy**, or `init` could not establish the state root/identity. |
| `2` | The configuration is missing or invalid. |

## What this is (and is not)

This is a preparatory product vertical built on the accepted W02 (configuration, identity, privacy)
and W03 (SQLite control state and durable spool) foundations. It is tracked as a roadmap feature and
does **not** claim the W05 runtime or W06 initialization gates. A spool-only data-flow demo and the
full CLI surface follow in later increments.
