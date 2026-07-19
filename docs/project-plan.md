# Milhouse OSS Project Plan

The normative project plan is [the authoritative Milhouse OSS 1.0 implementation plan](implementation-plan.md). It locks product contracts, architecture, privacy, work ordering, evidence gates, release responsibilities, and the Definition of Done. [Implementation status](implementation-status.md) is the live evidence ledger.

This page is a concise roadmap only; it cannot override the authoritative plan.

## Build sequence

1. **W00-W02 — Authority and contracts:** repository governance, ADR ratification, package/toolchain foundation, configuration/domain/identity/privacy contracts.
2. **W03-W06 — Durable vertical slice:** SQLite control state, segmented spool, ClickHouse, runtime, canary, base query, CLI, diagnostics, and deterministic demos.
3. **W07-W11 — Feedback product:** file/HTTP ingestion, verified feedback lifecycle, reports/briefs, bounded local MCP, and `/doh` postmortems.
4. **W12-W16 — Integrations and recovery:** providers, agent summaries, notifications, scheduler/services, legacy import, backup/restore, upgrade/rollback, and uninstall.
5. **W17-W18 — Release hardening:** documentation, supply chain, compatibility, performance, clean hosts, security review, and alpha/beta/RC soak.

## Locked decisions

- Product/repository/distribution: Milhouse, `Milhouse-oss`, `milhouse-observability`.
- License/contributions: Apache-2.0 and DCO sign-off.
- Local-first durable architecture: redaction/validation, segmented JSONL spool, SQLite control state, ClickHouse analytics.
- Python 3.11-3.14; macOS 14+ and Ubuntu 22.04/24.04.
- No raw prompts, responses, transcripts, or tool output in 1.0.
- MCP is local stdio and read-only by default.
- External writes, hosted storage, provider calls, services, push, and publication are explicit opt-ins.
- Release train: `1.0.0a1 -> 1.0.0b1 -> 1.0.0rc1 -> 1.0.0`.

Any change to these or another locked plan contract requires the amendment process in section 1 of the authoritative plan.
