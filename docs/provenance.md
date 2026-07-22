# Source Provenance and Donor Disposition

## Purpose

Milhouse OSS is a fresh public implementation. This inventory establishes the
source boundary for every reuse decision and prevents private history, private
operations data, or unreviewed donor expression from entering the public tree.

This document is an implementation control, not a statement that every planned
adaptation has occurred. At the W00 snapshot, no private donor file is recorded
as copied or adapted into the OSS implementation. Every future adaptation must
add a completed file-level ledger row before its work-package gate can pass.

## Audited baselines

| Role | Repository and immutable revision | Permitted use | Prohibited use |
|---|---|---|---|
| Public source baseline | `that1guy15/Milhouse-oss@fb81a7faf2c101e8bb3f08ef9120d82c2b20600b` | Starting scaffold, public documentation intent, public community files, and sanitized generic examples after truth review | Generated/cache files, stale claims, duplicate workflows, or any file that fails current privacy/provenance review |
| Private behavior reference | `that1guy15/milhouse@18ee9514ee11413812fde8fe361405b3686e025f` | Read-only algorithm, behavior, provider-format, and failure-mode reference limited to the dispositions below | Git history, branches, configuration, secrets, telemetry, logs, state, reports, private docs, local paths, personal labels, private fixtures, raw sessions, or wholesale source-tree import |

## External workflow reference

| Reference and immutable revision | License | Permitted conceptual use | Excluded use |
|---|---|---|---|
| `EveryInc/compound-engineering-plugin@8163a96e86656a89797869ac61905fe4641f81be` (version 3.19.0 at review) | MIT, Copyright 2025 Every | Implementation-readiness, progressive disclosure, bounded delegation, causal debugging, behavior-preserving simplification, risk-selected report-only review, explicit PR states, deterministic feedback-state concepts, and grounded durable learning | No plugin installation, vendoring, runtime dependency, agents, scripts, assets, configuration, session-history processing, raw feedback persistence, secret propagation, implicit mutation, or external code/context egress |

The reference was reviewed at the pinned commit, including `CONCEPTS.md`, `skills/ce-plan`,
`skills/ce-work`, `skills/ce-code-review`, `skills/ce-debug`, `skills/ce-sweep`, `skills/ce-handoff`,
`skills/ce-compound`, and managed-install code under `src/targets/`. Milhouse independently expresses
the adapted process in ADR 0015 and its five project skills. No upstream source expression, prompt,
agent, script, asset, or configuration was copied in this W00 adaptation.

Any future copied or substantially adapted upstream material requires an exact source-path-to-public-
path ledger row, a description of Milhouse privacy and authority changes, tests, independent review,
and preservation of the upstream MIT copyright and license notice. Concept/reference-only reuse does
not authorize later copying.

The implementation branch preserves the audited public repository history and
is anchored to the exact public baseline. The private repository is not a base,
subtree, submodule, remote to merge, or source of git history. It must remain
read-only throughout implementation. Commands against it are limited to
inspection and comparison; formatting, tests, migrations, dependency tools, or
generators must never run in a way that writes to it.

## Ownership and licensing basis

- Milhouse OSS source is distributed under Apache License 2.0.
- The project owner authorized use of the audited, owner-controlled private
  baseline as a behavior/reference donor by approving implementation plan 1.0.
  That approval does not waive third-party copyright, license, or attribution
  requirements.
- New contributions require Developer Certificate of Origin sign-off. A
  contributor certifies the right to submit the work under the project license;
  no CLA is required initially.
- No dependency source is vendored by default. Runtime and development
  dependencies require license and supply-chain inventory before release.
- If ownership or license provenance for any expression is uncertain, the file
  is quarantined from the public tree and rewritten independently or removed.
  The affected gate cannot pass on an assumption.

## Public baseline disposition

The following is the W00 disposition of the audited public scaffold. “Retain”
always means “retain only after confirming that the content is generic,
accurate for the implemented gate, and free of generated/private data.”

| Public baseline area | Disposition | Owning gate/control |
|---|---|---|
| `LICENSE` | Retain Apache-2.0 text and verify package inclusion | G00, G01, G17 |
| `README.md` | Retain product intent; rewrite all capability/status claims to remain pre-alpha until their gates pass | G00 and each feature gate |
| `AGENTS.md`, `CODEX.md`, `CLAUDE.md` | Establish the G00 engineering-process hierarchy and thin host pointers; refresh product-command guidance only after owning gates pass | G00, owning gates, G17 |
| `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, issue/PR templates | Retain and align with DCO, private security reporting, and no-sensitive-data policy | G00, G17 |
| `docs/architecture.md`, `docs/project-plan.md`, `docs/feedback-loop.md`, setup/publication documents | Treat as source requirements; reconcile to the authoritative plan rather than allowing conflicts | G00, G17 |
| `docs/implementation-plan.md` | Retain as the normative plan; amend only through its change-control process | All gates |
| `.github/workflows/` | Scaffolding only; replace/harden with least privilege, immutable action SHAs, aggregate `required-ci`, and no fork secrets | G01, G17 |
| `ops/github/workflows/` if present | Remove duplicate copies; `.github/workflows/` is canonical | G00, G17 |
| `pyproject.toml`, `setup.sh`, `Makefile` | Scaffolding only; replace/expand through package/toolchain gates | G01, G06, G17 |
| `src/milhouse/`, `tests/`, `config/`, `ops/clickhouse/`, service templates | Scaffolding only; rewrite or expand against v1 contracts with synthetic fixtures | Owning W01–W16 gates |
| `.env.example`, `.mcp.example.json` | Retain only fake/provider-neutral keys and local-safe examples; never copy a real overlay | G01, G02, G10, G17 |
| `skills/`, `.agents/skills/` | Establish five concise engineering-process skills and discovery aliases at G00; validate and refresh product-command claims only after corresponding gates pass | G00, owning gates, G17 |
| `openwiki/` | Optional and noncanonical; retain only if its workflow is verified to avoid private data and unintended telemetry | G17 |
| Caches, local environments, generated reports/state/logs/spool/database files | Exclude unconditionally | G00 and every release scan |

## Private donor file-level disposition

Only the following donor paths are approved even for focused reference or
adaptation. “Adapt” means a fresh public implementation behind v1 contracts,
with generalized names, synthetic tests, and an independent diff review. It
does not mean copying a private module unchanged.

| Private donor path at the fixed revision | Approved disposition | New OSS owner area | Mandatory guardrail | W00/current import state |
|---|---|---|---|---|
| `src/milhouse/timeutils.py` | Adapt small pure helper ideas | `src/milhouse/core/clock.py` | Inject the clock; strict UTC/DST behavior and fuzz tests | PR #16 merged a fresh caller-bounded ASCII parser and injected wall/monotonic clock that adapt only the single-unit elapsed-duration idea from the fixed revision; no donor expression, fixtures, history, defaulting, permissive parsing, or direct wall-clock behavior was imported |
| `src/milhouse/exporters/base.py` | Adapt result/protocol ideas | `src/milhouse/delivery/base.py` | v1 idempotency and checkpoint contracts replace donor state behavior | Not imported |
| `src/milhouse/exporters/clickhouse.py` | Reference serialization/type mapping only | `src/milhouse/storage/clickhouse/` | New migrations, authentication, dedupe, spool checkpoints, and failure model | Not imported |
| `src/milhouse/collectors/site_canary.py` | Adapt HTTP observation behavior | `src/milhouse/collectors/site_canary.py` | New config/domain/privacy/runtime boundaries; collector cannot persist directly | Not imported |
| `src/milhouse/collectors/cloudflare.py` | Reference endpoint/window semantics only | `src/milhouse/collectors/cloudflare.py` | Revision-aware windows and metric semantics must prevent overlap inflation | Not imported |
| `src/milhouse/collectors/agent_session.py` | Reference provider-format recognition only | Provider-neutral agent adapters | Synthetic fixtures; explicit opt-in summaries; no raw content, paths, commands, or transcript storage | Not imported |
| `src/milhouse/collectors/agent_logs.py` | Reference provider-format recognition only | Provider-neutral agent adapters | Same privacy and format-drift controls as `agent_session.py` | Not imported |
| `src/milhouse/notify.py` | Adapt retry/chunking ideas | `src/milhouse/notifications/telegram.py` | New opt-in egress classification, preview, idempotency, and audit layer | Not imported |
| `src/milhouse/reports/briefs.py` | Adapt presentation ideas | `src/milhouse/reporting/` | Use only the bounded query service and untrusted-text renderer | Not imported |
| Donor tests directly covering the rows above | Translate intended behavior; never copy fixtures | Corresponding OSS test suites | Regenerate wholly synthetic fixtures and add v1 crash/privacy/security cases | Not imported |

No other private donor path is approved. A request to add one requires a plan
amendment or an ADR permitted by the plan, an ownership review, a new row here,
and approval before source expression is introduced.

The W02 stable-error, config-diagnostic, and structured-event implementation is a clean-room
rewrite based only on the public plan and current OSS contracts. No private logging or error path is
approved for reuse, and no private donor expression, fixture, history, or behavior is incorporated.

The W02 common-egress policy is likewise a clean-room implementation of the public plan's binding
surface/classification matrix. It uses no private egress, exporter, report, notification, or storage
donor material, and no private expression, fixture, destination, or behavior is incorporated.

The W02 domain-validation guard and marked-path/file-URI redaction remediation are clean-room
implementations derived from the public privacy contract and wholly synthetic adversarial canaries.
No private exception, record, path, fixture, parser, or redaction expression was inspected or reused.

## Mandatory clean-room rewrites

The following areas may use documented product behavior as requirements but may
not reuse donor implementation expression:

- configuration, secret loading, canonical records, and deterministic IDs;
- redaction, trust classification, HMAC pseudonyms, and safe rendering;
- stable errors, config diagnostics, structured logging, and future CLI/log-destination wiring;
- SQLite state, durable spool, runtime, replay, retention, and checkpoints;
- ClickHouse schema, migrations, export, and query repository;
- alerts, incidents, feedback history, curation, and verification;
- outbox, production-error, Cloudflare, GitHub, and generic workflow/admin
  collectors beyond the narrow provider-format reference listed above;
- MCP, receiver, CLI, reports, postmortems, agent polling/checkpoints, scheduler,
  backup/restore/import, and operational packaging.

These areas are marked “rewrite” because the v1 contracts intentionally reject
private donor persistence, identity, privacy, and lifecycle behavior.

## Material that must never be copied

- private repository history, commit messages, branches, tags, remotes, or issue
  content;
- private application/product names, service aliases, personal report language,
  domains, account IDs, local paths, launch labels, or environment defaults;
- `.env`, `.mcp.json`, private configuration, tokens, credentials, RUM tags,
  signed URLs, webhook destinations, or credential-bearing examples;
- telemetry, ClickHouse data, SQLite state, JSONL spool, logs, diagnostics,
  generated reports, backups, incidents, postmortems, or private runbooks;
- raw Codex, Claude, LangSmith, browser, backend, terminal, prompt, response, or
  tool-output content;
- private fixtures, snapshots, caches, or generated documentation;
- application-specific gates, personal/profanity heuristics, or untrusted text
  rendered as instructions;
- donor defects listed in implementation-plan section 7.5, including random
  IDs, duplicate replay, direct state mutation, silent query fallback,
  redaction bypass, arbitrary output paths, or incomplete package resources.

## Required ledger for an actual adaptation

Before an adaptation can merge, append a row below. One row is required for
each donor file/new public file relationship; grouped or implied provenance is
not sufficient.

| Donor path and immutable revision | Public destination | Reuse kind | Contributor/commit | Generalization and privacy changes | Synthetic tests | Independent reviewer/date |
|---|---|---|---|---|---|---|
| _No private donor expression imported as of the W00 snapshot._ | — | — | — | — | — | — |

For reference-only work that produces no copied expression, record the provider
format or behavior reviewed in the implementation pull request and cite the
synthetic contract tests. Never attach private examples or screenshots as
evidence.

## Review and release controls

Every work-package review checks:

1. changed files against this disposition;
2. repository and package inventories for generated/private material;
3. fake/provider-neutral examples and fixtures;
4. public identifiers, local paths, credentials, raw traces, and private names;
5. `git diff`, `git status --short`, secret scans, targeted private-identifier
   scans, and package-content inventory; and
6. provenance rows for every donor-informed file.

Before G17, an independent reviewer must inspect the full tree, git history,
wheel, sdist, SBOM, license inventory, and this ledger. Any unprovenanced or
private-derived material is release-blocking and must be replaced before the
gate can pass.
