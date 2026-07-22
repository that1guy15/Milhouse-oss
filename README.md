# Milhouse

Milhouse is a local-first observability and verified engineering-feedback control plane for small
teams and AI-assisted development workflows.

> **Status: pre-alpha implementation; no public release.** The W01 package and quality-toolchain
> foundation has passed G01; W02 domain, configuration, identity, trust, and privacy implementation
> is in progress. The repository now contains strict configuration/schema validation, deterministic
> record identity and envelopes, privacy/redaction primitives, secure runtime path and explicit
> secret-loading foundations, secure pseudonym-key material primitives, and metadata-only exact
> third-party plugin allowlist validation. Durable storage,
> collection, querying, initialization, and the operational runtime are not implemented yet. Do not
> use this build for production data.

The normative scope, contracts, work order, gates, and Definition of Done are in [the authoritative implementation plan](docs/implementation-plan.md). Progress and validation evidence are tracked in [implementation status](docs/implementation-status.md).

## Planned 1.0 product

Milhouse will:

- collect health, deploy, workflow, error, and privacy-safe agent-session signals;
- normalize and redact every record before durable persistence;
- commit acknowledged records to a local segmented JSONL spool;
- use SQLite for transactional control state and ClickHouse for local analytics;
- continue collection while ClickHouse or a provider is unavailable;
- turn recurring evidence into append-only feedback items;
- mark work verified only after the configured signal is re-observed;
- expose bounded local CLI, MCP, report, and `.milhouse/` brief surfaces;
- create neutral `/doh` postmortems;
- optionally send redacted Telegram summaries and create GitHub Issues.

Milhouse 1.0 will not store raw prompts, responses, agent transcripts, or tool output. It will not require a hosted Milhouse service or send call-home telemetry.

## Current build surface

Implementation follows W00-W18 in the approved plan. Until a work-package gate passes, its
behavior is planned rather than available. In particular, the old starter quickstart, example
configuration, Compose deployment, and MCP example are being replaced and validated against the
1.0 contracts before they are advertised as usable. Product-command guidance in project skills is
added only after the owning command exists.

The current command surface is deliberately small:

```bash
python3 -I scripts/run_uv.py run --locked milhouse --help
python3 -I scripts/run_uv.py run --locked milhouse --version
python3 -I scripts/run_uv.py run --locked milhouse --config config/example.toml config validate
python3 -I scripts/run_uv.py run --locked milhouse config schema
```

Those commands exercise the pre-alpha CLI and offline configuration surface only. `milhouse init`,
collectors, storage, feedback, reports, MCP, and services become available in their owning work
packages. In particular, product initialization is W06 work; contributor setup does not create
Milhouse configuration or runtime state. The current key-material module is a lower-level primitive:
W06 still owns private-directory initialization and stale staging-artifact handling, while W16 owns
backup, restore, identity-continuity, and rotation workflows. When third-party plugins are enabled,
`config validate` checks only explicitly allowlisted, path-backed installed-package metadata and
does not import or execute the plugin. Its direct metadata-file reads are byte-bounded before
parsing, and unsupported metadata backends fail closed. The runtime registry and plugin contract kit
remain W05 work; that registry must revalidate and bind the exact object it will load.

## Contributor quickstart

Contributors need Python 3.11-3.14 and exactly uv 0.11.29. The bootstrap verifies that uv version
and installs the hash-locked development environment:

```bash
./setup.sh
./scripts/run_make.py quality
./scripts/run_make.py test-coverage
```

See [setup](docs/setup.md) for prerequisites and [development](docs/development.md) for the complete
target reference. Dependency purpose and policy are documented in
[dependencies](docs/dependencies.md).

Current repository validation:

```bash
./scripts/run_make.py test
./scripts/run_make.py docs-check
./scripts/run_make.py skill-check
./scripts/run_make.py secret-scan
```

These commands validate the current source tree. W01 has passed, but that does not imply that the
Milhouse runtime or any later work package is complete.

## Source and privacy boundary

This is a fresh public implementation. The private operational repository is read-only donor material, not the codebase. Reuse is limited to the audited, generalized algorithms listed in [provenance](docs/provenance.md); private history, telemetry, configuration, paths, fixtures, reports, and agent content are prohibited.

Never attach credentials, real telemetry, raw agent content, private incident data, ClickHouse data, JSONL spools, or generated reports to an issue or pull request. See [Security](SECURITY.md) and [Privacy](PRIVACY.md).

## Documentation

- [Authoritative implementation plan](docs/implementation-plan.md)
- [Implementation status](docs/implementation-status.md)
- [Architecture](docs/architecture.md)
- [Contributor setup](docs/setup.md)
- [Development workflow](docs/development.md)
- [Dependency policy](docs/dependencies.md)
- [Privacy](PRIVACY.md)
- [Threat model](docs/threat-model.md)
- [Contributing](CONTRIBUTING.md)
- [Security reporting](SECURITY.md)
- [Governance](GOVERNANCE.md)
- [Support](SUPPORT.md)

## License

Milhouse is licensed under Apache License 2.0. Contributions require Developer Certificate of Origin sign-off. See [LICENSE](LICENSE) and [CONTRIBUTING.md](CONTRIBUTING.md).
