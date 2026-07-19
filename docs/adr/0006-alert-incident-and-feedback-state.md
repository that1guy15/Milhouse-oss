# ADR 0006: Alert, incident, and feedback state

- Status: Accepted (ratification)
- Date: 2026-07-18

## Context

Operational history and verification must remain auditable under replay, late evidence, concurrent writers, and untrusted agent claims.

## Decision

Alerts and incidents are system-derived, append-only histories. Alert state follows `inactive -> firing -> resolved`, with `resolved -> firing` for recurrence under the same deterministic key. Incident state follows `open -> mitigated -> resolved`, with correlated new evidence emitting `reopened` and returning the incident to `open`. Operators cannot mutate alert or incident history through public CLI or MCP in 1.0.

Per-key serialization, monotonic revisions, deterministic transition IDs, evidence coordinates, and projection compare-and-swap make replay, late samples, and concurrent derivation idempotent. Cooldown affects delivery only, not state or evidence.

Feedback uses these and only these state transitions:

```text
open      -> accepted | rejected
accepted  -> open | shipped | rejected
shipped   -> verified | regressed
regressed -> accepted | rejected
rejected  -> open
verified  -> regressed
```

Every transition is an append-only record with deterministic ID, previous/new state, monotonic revision, current `expected_revision`, derived actor identity, rationale, request/idempotency ID, and evidence. A stale revision emits no transition; a repeated request returns its original result.

Acceptance requires an owner. Shipment requires a change reference and validation evidence. Reopen/return-to-open operations require rationale. Only the verification engine can produce `verified` or `regressed`, using a bounded typed `VerificationSpecV1` and same-signal-class observations. Manual evidence and GitHub issue state cannot assert verification. `needs_approval` authority remains operator-only as specified in the plan; explicitly enabled agent writes are limited to allowed `agent_safe` work and shipment of operator-accepted work.

## Consequences

CLI, MCP, scheduler, curator, SQLite, and ClickHouse all call the same lifecycle services. Current state is a projection, never an in-place source-of-truth update. Repeated curation over identical evidence cannot create duplicate open work.

## Plan references

- [Section 4.6: alert, incident, and feedback contracts](../implementation-plan.md#46-alert-incident-and-feedback-contracts)
- [W08: feedback service and verification engine](../implementation-plan.md#w08--feedback-service-curator-and-verification-engine)
- [Section 14: complete failure-to-verification definition](../implementation-plan.md#14-comprehensive-definition-of-done)
