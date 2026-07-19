# Verified feedback loop

> Pre-alpha contract summary. Section 4.6 of `docs/implementation-plan.md` is normative.

Milhouse converts repeated, redacted operational evidence into actionable feedback and keeps the lifecycle append-only and reproducible.

```text
failure/workflow signal
-> redacted durable record
-> alert/incident and deterministic curator rule
-> open feedback item
-> accepted with owner
-> shipped with change and validation evidence
-> same-class observation by the verification engine
-> verified or regressed
```

## Lifecycle

```text
open      -> accepted | rejected
accepted  -> open | shipped | rejected
shipped   -> verified | regressed
regressed -> accepted | rejected
rejected  -> open
verified  -> regressed
```

Every transition records deterministic transition ID, previous/new state, monotonic revision, expected revision, derived actor identity, rationale, request ID, and evidence. State-changing writes use compare-and-swap semantics. Current state is a projection, not an in-place source of truth.

Only the verification engine may emit `verified` or `regressed`; 1.0 has no operator override. `request-verification` schedules an observation but cannot choose the result.

## Surfaces

- bounded CLI and local MCP reads;
- explicitly enabled narrow feedback writes;
- generated `.milhouse/FEEDBACK.md` and `AGENT_FEEDBACK.md`;
- human-owned `.milhouse/TEAM_WORKFLOW.md`, created only when absent;
- opt-in GitHub Issue and Telegram summaries that never decide verification state.

## `/doh`

`/doh` requests a neutral postmortem when completed work missed intent. Operator input, requirements, planning, agent behavior, implementation, validation, documentation, and workflow all remain in scope. Evidence is bounded and treated as untrusted data; personal/profanity heuristics are prohibited.
