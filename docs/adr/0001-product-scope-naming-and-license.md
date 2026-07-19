# ADR 0001: Product scope, naming, and license

- Status: Accepted (ratification)
- Date: 2026-07-18

## Context

The earlier OSS project plan left product naming, licensing, and portions of release scope as priority decisions. Plan version 1.0 resolves them.

## Decision

Milhouse is a local-first observability and verified engineering-feedback control plane for one technical operator or a small engineering team across multiple application repositories, including AI-assisted workflows.

Milhouse 1.0 includes the complete collection-to-verification loop, local durable storage, ClickHouse analytics, CLI, bounded MCP, `.milhouse` briefs, `/doh` postmortems, first-party integrations, optional notifications/action sinks, services, recovery/import tooling, documentation, and release hardening. Alpha-only delivery is not completion.

The supported and unsupported environments are exactly those in plan section 2.2. In particular, 1.0 supports Python 3.11-3.14, macOS 14+, Ubuntu 22.04/24.04, Docker Compose for reference ClickHouse, and local stdio MCP; it does not support multi-tenant hosting, a web dashboard, remote MCP, raw agent content, native Windows services, or call-home telemetry.

Names are fixed as follows:

- display name `Milhouse`;
- repository `Milhouse-oss`;
- Python distribution `milhouse-observability`;
- import package and executable `milhouse`;
- Docker/Compose resource prefix `milhouse`.

The source license is Apache-2.0. Contributions use DCO sign-off, with no CLA initially. The private repository is read-only donor/reference material, never the public history or implementation base.

## Consequences

Claims, examples, package metadata, resources, and compatibility tests must use these names and boundaries. A naming collision may be handled only through the plan-amendment process. Product behavior outside the fixed 1.0 scope is deferred rather than silently added.

## Plan references

- [Sections 1 and 2: authority and product contract](../implementation-plan.md#1-authority-and-change-control)
- [Section 7: source reuse and provenance](../implementation-plan.md#7-source-reuse-and-provenance-plan)
- [Section 8.0 and W00: resolved decisions and ratification](../implementation-plan.md#80-resolved-decision-register)
