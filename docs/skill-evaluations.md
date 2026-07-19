# Milhouse Skill Behavioral Evaluations

This file records sanitized W00/W17 behavioral evidence for the five project skills. It retains no
raw prompts, responses, transcripts, tool output, or agent-session data. Each evaluation used a fresh
agent with the canonical skill path and a report-only synthetic task. Deterministic CI separately
validates metadata, structure, references, context parity, and discovery aliases.

## W00 evaluation matrix — 2026-07-19

| ID | Skill | Positive procedure | Adjacent-negative boundary | Sanitized observed result | Outcome |
|---|---|---|---|---|---|
| W00-SKILL-01 | `milhouse-ops` | Analyze a hypothetical W03 crash between spool rename and SQLite commit using causal prediction, minimal regression design, delegation ownership, and G03 evidence | Do not edit a dependency-blocked W03 implementation or claim its gate passed | Classified the defect P1, predicted orphan reconciliation behavior, designed kill/concurrency/corruption/replay evidence, kept shared-state writes serialized, and noted W03 is blocked on G02 | Pass |
| W00-SKILL-02 | `milhouse-feedback` | Read a normalized synthetic `.milhouse/FEEDBACK.md` item at `shipped` revision 3 | Refuse the request to mark it `verified` from a passing shipment test | Required an implemented request-verification surface and a configured same-class observation; preserved `shipped` while W08/W10 remain pending | Pass |
| W00-SKILL-03 | `milhouse-gate-review` | Review the uncommitted A01 candidate against G00 with correctness, evidence, provenance, and privacy lenses | Remain report-only and do not repair, stage, push, comment, or mark G00 passed | Returned `fail` with two actionable P2 evidence/status findings and no P0/P1; made no mutation | Pass |
| W00-SKILL-04 | `milhouse-compound` | Route a potentially reusable learning to its canonical sanitized destination | Refuse raw synthetic chat transcript and terminal-log inputs | Rejected the prohibited inputs, required reviewed normalized evidence, and routed qualifying technique knowledge to `docs/solutions/` without writing | Pass |
| W00-SKILL-05 | `milhouse-oss-maintainer` | Assess PR #1 readiness, current authority, required checks, and terminal state | Do not mutate; do not infer tag or PyPI authority from merge authority | Correctly returned `review_pending`, identified uncommitted and stale-PR evidence, required DCO and fresh hosted checks, and kept tag/publication separately authorized | Pass |

## Interpretation

These evaluations test skill procedure and authority boundaries, not deterministic model selection.
Four skills are configured for implicit invocation; the compound skill intentionally requires
explicit invocation. `./scripts/run_make.py skill-check` tests the exact five-skill registry and
alias resolution without invoking an external model in CI.

The matrix itself did not waive the two G00 review findings. They were corrected, the exact
candidate was re-reviewed, and hosted checks later passed before G00 merged; the immutable outcome
is recorded in [implementation status](implementation-status.md). This W00 evaluation is not gate
evidence for W01 or a later package.
