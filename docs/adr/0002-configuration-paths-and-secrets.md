# ADR 0002: Configuration, paths, and secrets

- Status: Accepted (ratification)
- Date: 2026-07-18

## Context

Milhouse must behave identically from a source checkout and an installed artifact without depending on the working directory or silently discovering credentials.

## Decision

Configuration v1 is strict TOML with `config_version = 1`, validated by Pydantic v2 and exportable as JSON Schema. Unknown keys, duplicate IDs, invalid references, unsupported plugin versions, unsafe paths, and unsupported config versions are errors. Migrations are explicit.

Configuration path precedence is global `--config`, then `MILHOUSE_CONFIG`, then the `platformdirs` user-config path. There is no current-directory lookup. Runtime-home precedence is `MILHOUSE_HOME`, then `[paths].home`, then the `platformdirs` user-data path. The canonical result is `STATE_ROOT`, and runtime children remain beneath it.

Relative resolution is class-specific:

- `[paths].home`, configured env files, and standalone file sources resolve from the config directory;
- spool, reports, logs, backups, and the pseudonym key resolve under `STATE_ROOT` and cannot escape it;
- outbox paths are repository-relative and remain beneath the target's canonical `repo_path`;
- repository and agent-session roots are absolute canonical paths.

Secret precedence is process environment, explicit CLI `--env-file`, then configured env files in declaration order. Higher-priority values are not overwritten. `.env` is never auto-discovered. Config stores only credential environment-variable references, never secret values; commands may report a value's source but not its value.

Persisted times are UTC. The validated IANA project timezone is used only for display and calendar scheduling. `config validate` is offline; only `doctor --live` performs live checks.

## Consequences

Every config consumer uses the common loader and strict models. Commands never rely on repository CWD, and setup requires no production credentials. Example configs must validate against the generated schema.

## Plan references

- [Section 4.1: Configuration v1](../implementation-plan.md#41-configuration-v1)
- [Section 5: CLI contract](../implementation-plan.md#5-cli-contract)
- [W02: domain, configuration, identity, trust, and privacy](../implementation-plan.md#w02--domain-configuration-identity-trust-and-privacy)
