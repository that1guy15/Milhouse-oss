# ADR 0008: Trusted plugin boundary

- Status: Accepted (ratification)
- Date: 2026-07-18

## Context

Milhouse needs config-driven integrations and a public extension contract without pretending in-process Python plugins are sandboxed.

## Decision

Collector, notification, and exporter plugin API version 1 uses installed Python entry points in `milhouse.collectors`, `milhouse.notifications`, and `milhouse.exporters`. Configuration cannot import arbitrary modules or execute scripts.

Third-party plugins are trusted local Python code running in-process with the Milhouse user's authority. Capability and privacy manifests are review and compatibility declarations, not containment. Milhouse does not auto-install plugins. Third-party discovery/import is disabled unless `[plugins].allow_third_party = true` and an exact allowlist entry matches distribution, installed version, group, and entry point. Unlisted, duplicated, mismatched, or unknown plugins are refused without import. A sandbox claim requires a future separate-process ADR and enforcement design.

Collector API v1 provides `metadata`, `config_model`, `collect`, `health`, `fixture_contract`, and `privacy_manifest`. Results contain proposed normalized records/cursor plus safe diagnostics; the runtime alone validates, redacts, commits, derives, exports, and advances state. Collectors never write directly to ClickHouse, SQLite projections, reports, application repositories, notifications, or MCP.

Built-ins are statically registered. Their strict discriminated config unions, provider credential references, scheduling separation, bounds, privacy manifests, and first-party list are fixed by plan section 4.8. Integrations remain config-driven rather than project-specific.

## Consequences

Every public plugin passes the contract kit and declares supported fixture versions and capabilities. Operators must review and install third-party distributions explicitly. A malicious installed plugin is treated as a trusted-code compromise, not a contained input failure.

## Plan references

- [Section 4.8: collector and plugin contract](../implementation-plan.md#48-collector-and-plugin-contract)
- [Section 3.4: mandatory runtime pipeline](../implementation-plan.md#34-runtime-pipeline)
- [W05 and W12: registry and provider implementation](../implementation-plan.md#w05--runtime-collector-registry-canary-alerting-and-vertical-slice)
