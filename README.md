# Milhouse

Milhouse is a local-first observability and verified engineering-feedback control plane for small teams and AI-assisted development workflows.

> **Status: pre-alpha implementation.** The architecture and Milhouse OSS 1.0 build contract are approved, but the product described below is not yet implemented. The current Python command is a scaffold and must not be treated as production-ready.

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

## Build status

Implementation follows W00-W18 in the approved plan. Until a work-package gate passes, its behavior is planned rather than available. In particular, the old starter quickstart, example configuration, Compose deployment, MCP example, and project skills are being replaced and validated against the 1.0 contracts before they are advertised as usable.

Current repository validation:

```bash
make test
make docs-check
make skill-check
make secret-scan
```

These commands validate the current source tree; they do not imply that the Milhouse runtime is complete.

## Source and privacy boundary

This is a fresh public implementation. The private operational repository is read-only donor material, not the codebase. Reuse is limited to the audited, generalized algorithms listed in [provenance](docs/provenance.md); private history, telemetry, configuration, paths, fixtures, reports, and agent content are prohibited.

Never attach credentials, real telemetry, raw agent content, private incident data, ClickHouse data, JSONL spools, or generated reports to an issue or pull request. See [Security](SECURITY.md) and [Privacy](PRIVACY.md).

## Documentation

- [Authoritative implementation plan](docs/implementation-plan.md)
- [Implementation status](docs/implementation-status.md)
- [Architecture](docs/architecture.md)
- [Privacy](PRIVACY.md)
- [Threat model](docs/threat-model.md)
- [Contributing](CONTRIBUTING.md)
- [Security reporting](SECURITY.md)
- [Governance](GOVERNANCE.md)
- [Support](SUPPORT.md)

## License

Milhouse is licensed under Apache License 2.0. Contributions require Developer Certificate of Origin sign-off. See [LICENSE](LICENSE) and [CONTRIBUTING.md](CONTRIBUTING.md).
