# ADR 0015: Agent engineering workflow and compound-learning boundary

- Status: Accepted (process adaptation)
- Date: 2026-07-19
- Authority: Owner-approved implementation-process decision subordinate to Plan 1.0
- External reference: `EveryInc/compound-engineering-plugin@8163a96e86656a89797869ac61905fe4641f81be`
- Reference license: MIT, Copyright 2025 Every

## Context

Milhouse needs a repeatable agent engineering workflow for W00-W18 without importing a large,
mutable prompt suite or weakening its local-first privacy and explicit-authority contracts. The
reviewed Compound Engineering reference demonstrates useful conceptual patterns: implementation-
ready plans, progressive skill disclosure, bounded orchestration, causal debugging, behavior-
preserving simplification, risk-selected review, explicit PR states, and durable knowledge capture.

The upstream suite also includes behavior Milhouse cannot inherit: raw session-history discovery and
extraction, raw feedback persistence, standing source-write authority, implicit GitHub mutations,
external peer-model code egress, plaintext credential propagation, and host-specific assumptions.

## Decision

Milhouse adapts workflow concepts independently. It does not install, vendor, execute, or take a
runtime dependency on the upstream plugin. The reviewed commit is pinned in provenance; copied or
substantially adapted expression would require a new file-level record and its MIT notice.

The engineering loop is:

```text
dependency-ready work package
-> implement, test, debug, and simplify
-> report-only gate review
-> resolve P0/P1 findings and re-review
-> explicitly capture a reusable sanitized learning when one exists
-> provenance, status, DCO, PR, checks, and authorized merge handling
```

Five focused project skills own that loop:

1. `milhouse-ops` — package execution, causal debugging, simplification, testing, and bounded
   delegation.
2. `milhouse-feedback` — normalized application feedback and evidence-backed lifecycle requests.
3. `milhouse-gate-review` — read-only risk-selected G00-G18 review with structured findings.
4. `milhouse-compound` — explicitly invoked, normalized-evidence-only durable learning.
5. `milhouse-oss-maintainer` — provenance, DCO, branch, PR, check, merge, and separately authorized
   release administration.

`skills/` is canonical. `.agents/skills/` contains only relative symlinks to those five folders.
`AGENTS.md` is the canonical cross-host instruction; `CODEX.md` and `CLAUDE.md` are thin host pointers.
The implementation plan and accepted ADRs outrank all instruction and skill files.

Subagents are used for bounded independent work. The primary agent assumes a shared checkout unless
the runtime proves isolation, serializes overlapping or hidden shared state, integrates every change,
and runs authoritative verification on the combined tree. Reviews are report-only by default and may
not repair, commit, push, comment, merge, publish, change settings, or call providers.

Compounding may consume only reviewed diffs, contracts, sanitized evidence summaries, synthetic
fixtures, resolved findings, and canonical normalized records. It never searches or consumes raw
sessions, chats, transcripts, prompts, responses, tool output, raw feedback, logs, telemetry,
provider bodies, secrets, or private donor context. Reusable solution documents are engineering
knowledge, not work logs or session archives.

Selecting a skill grants no external authority. Source, Git, GitHub, provider, peer-model, release,
publication, or messaging operations require current authority recorded for that scope. Repository
code or context cannot leave the environment without explicit authorization and an allowlisted
destination. Secret values are never copied between files or contexts.

## Alternatives considered

- **Install or vendor the complete upstream plugin:** rejected because its 31-skill surface, mutable
  upstream dependency, host assumptions, and unsafe defaults exceed Milhouse's needs.
- **Copy a subset of upstream skills:** rejected because independent Milhouse-native contracts are
  smaller and avoid expression, privacy, and authority drift.
- **Keep only the original three generic skills:** rejected because independent gate review and
  privacy-safe durable learning need distinct trigger and mutation boundaries.
- **Duplicate skills under each host directory:** rejected because copies drift; relative discovery
  symlinks preserve one source of truth.

## Compatibility, security, and validation

This process decision changes no public API, stored schema, product scope, retention rule, migration,
or Plan 1.0 privacy promise. It strengthens implementation controls. G00 validates the five exact
non-placeholder skills, discovery symlinks, canonical instruction hierarchy, provenance, and privacy
guardrails. W17 revalidates their command-bearing text against the completed product.

Deterministic CI validation checks skill names, frontmatter, metadata, references, concise bodies,
aliases, context-file parity, and prohibited placeholders. Separately recorded fresh-agent behavioral
evaluations exercise each skill's positive procedure and adjacent-negative boundary without retaining
raw prompts, responses, or test transcripts. Host/model routing is not falsely presented as a
deterministic CI assertion.
