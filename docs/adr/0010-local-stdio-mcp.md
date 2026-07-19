# ADR 0010: Local stdio MCP

- Status: Accepted (ratification)
- Date: 2026-07-18

## Context

Agents need bounded access to operational evidence without exposing a remote control plane, raw query language, or broad write authority.

## Decision

Milhouse MCP uses the official Python SDK pinned to `mcp>=1.27,<2` and local stdio transport. Moving to SDK 2 requires a compatibility amendment.

The default server is read-only and exposes the bounded structured tools fixed in plan section 4.11: feedback list/get, events query, run status, recent incidents, health summary, weekly report, and structured agent-trace query only when that data is enabled.

Narrow feedback and postmortem writes become available only when both `[mcp].allow_writes = true` and `milhouse mcp serve --allow-writes` are present. Writes call the same domain services as CLI, operate on known IDs, require request ID/rationale/current expected revision where applicable, derive actor identity from the local server/client/OS boundary, and are idempotent and audited. The postmortem tool is registered only after its W11 service exists.

MCP accepts no raw SQL, shell command, arbitrary path, arbitrary URL, authoritative caller-supplied actor, unbounded result, or remote transport in 1.0. Query limits, privacy filtering, freshness, degraded state, and pagination match the common query service.

## Consequences

Client examples use absolute executable/interpreter and config paths. Official client conformance covers initialize lifecycle, cancellation, limits, errors, schemas, privacy, and duplicate writes. Enabling writes cannot bypass feedback authority or verification rules.

## Plan references

- [Section 4.10: shared query contract](../implementation-plan.md#410-query-contract)
- [Section 4.11: MCP contract](../implementation-plan.md#411-mcp-contract)
- [W10-W11: MCP gates and postmortem adapter](../implementation-plan.md#w10--official-sdk-mcp-read-surface-and-bounded-writes)
