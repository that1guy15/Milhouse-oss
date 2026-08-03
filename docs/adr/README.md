# Milhouse architecture decision records

These ADRs ratify the locked decisions in the [Milhouse OSS Authoritative Implementation Plan](../implementation-plan.md). They record accepted outcomes for implementation; they do not reopen the alternatives left unresolved in earlier project documents.

The implementation plan remains the normative build contract. If an ADR and the plan disagree, the plan controls and the ADR must be corrected. Changing a public contract, privacy guarantee, stored schema, lifecycle, or release gate requires the amendment process in [plan section 1](../implementation-plan.md#1-authority-and-change-control), not an implicit ADR edit.

ADRs 0001-0014 are plan-version 1.0 ratifications dated 2026-07-18. ADR 0015 is
an owner-approved process adaptation dated 2026-07-19; it changes no public API,
stored schema, privacy promise, or product scope. ADRs 0016 and 0017 record
owner-approved amendments A02 and A03 dated 2026-07-22: ADR 0016 ratifies the
persisted local structured-log contract and amends ADR 0007, and ADR 0017 records
the bounded D01 historical DCO disposition. An ADR 0016 addendum ratifies amendment
A05 dated 2026-07-23 (the exact v1 stored-log schema). The ADR 0004 addendum ratifies
owner-approved amendment A06 dated 2026-07-28 and makes the installation-account
filesystem-containment boundary explicit. The ADR 0007 addendum ratifies
owner-approved amendment A07 dated 2026-08-01, binding W03 audited compaction to
the installation's control-plane pseudonym key ID/epoch and adding the reserved
compaction-successor namespace with its auto-converging upgrade remediation.

| ADR | Ratified decision |
|---|---|
| [0001](0001-product-scope-naming-and-license.md) | Product, 1.0 scope, supported environments, naming, and license |
| [0002](0002-configuration-paths-and-secrets.md) | Configuration, paths, runtime home, and secrets |
| [0003](0003-records-identity-and-metrics.md) | Canonical records, deterministic identity, and metric semantics |
| [0004](0004-spool-sqlite-commit-and-recovery.md) | Durable spool, SQLite control state, commit, replay, recovery, and the A06 installation-account filesystem-containment boundary |
| [0005](0005-clickhouse-analytical-storage.md) | ClickHouse analytical storage, migrations, and recovery |
| [0006](0006-alert-incident-and-feedback-state.md) | Alert, incident, and verified-feedback state machines |
| [0007](0007-privacy-identity-egress-and-retention.md) | Trust, privacy, installation identity, egress, retention, and purge, and the A07 installation-key-provenance and reserved compaction-namespace upgrade addendum |
| [0008](0008-trusted-plugin-boundary.md) | Trusted in-process plugin boundary and collector API |
| [0009](0009-scheduler-process-and-service-model.md) | Scheduler, processes, jobs, and explicit OS services |
| [0010](0010-local-stdio-mcp.md) | Local stdio MCP with bounded, read-first tools |
| [0011](0011-authenticated-ingestion-receiver.md) | Optional authenticated ingestion receiver |
| [0012](0012-application-repository-boundary.md) | Application-repository ownership and `.milhouse` boundary |
| [0013](0013-packaging-versioning-and-release.md) | Packaging, versioning, artifacts, and release train |
| [0014](0014-support-governance-security-and-provenance.md) | Support, governance, security response, and provenance |
| [0015](0015-agent-engineering-workflow.md) | Agent engineering loop, five focused skills, read-only review, sanitized learning, discovery, and authority boundaries |
| [0016](0016-local-structured-log-persistence.md) | Persisted local structured-log wire, namespace, durability, rotation, recovery, concurrency, and `local_log` egress (amendments A02 and A05; amends ADR 0007) |
| [0017](0017-d01-dco-historical-disposition.md) | Exact bounded D01 PR #21 historical DCO disposition (amendment A03) |

## Status vocabulary

- **Accepted (ratification):** fixed by implementation-plan version 1.0 and binding on the build.
- **Accepted (process adaptation):** owner-approved execution control subordinate to Plan 1.0.
- **Superseded:** replaced only by an approved numbered amendment and successor ADR.

No ADR in this index is proposed or undecided.
