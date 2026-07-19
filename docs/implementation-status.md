# Milhouse OSS Implementation Status

This file is the durable execution ledger for the
[authoritative implementation plan](implementation-plan.md). It records gate
status and evidence; it does not amend the plan.

## Current snapshot

| Field | Value |
|---|---|
| Snapshot date | 2026-07-19 |
| Product phase | **Pre-alpha; not released and not ready for production use** |
| Plan | Version 1.0, approved for implementation by the owner on 2026-07-18 |
| Target release | Milhouse OSS 1.0 |
| Working branch | `codex/build-milhouse-v1` |
| Git state | Prior hosted W00 evidence head `11652eff2ec46f9c895c41a1c1a16aa28eac70b8` on `codex/build-milhouse-v1`; the staged A01 candidate still requires commit and exact-head checks |
| Public source baseline | `that1guy15/Milhouse-oss@fb81a7faf2c101e8bb3f08ef9120d82c2b20600b` |
| Private reference baseline | `that1guy15/milhouse@18ee9514ee11413812fde8fe361405b3686e025f` |
| External mutation authority | Owner authorized build-branch pushes, pull requests, and merges to `main` after required checks on 2026-07-19. Tags, package publication, announcements, live-provider calls, and unrelated external mutation remain separately controlled |
| Highest passed gate | None |
| Active package | W00 — Repository, authority, governance, and ADRs |

The audited public baseline is the source scaffold. The private baseline is a
read-only behavior and algorithm donor. Its history, configuration, telemetry,
generated data, private fixtures, and private documentation must never enter
this repository. See [provenance.md](provenance.md).

Read-only GitHub API evidence captured 2026-07-18: the repository is public,
unarchived, and uses protected `main`; Issues and Discussions are enabled;
secret scanning, push protection, and Dependabot security updates are enabled;
Private Vulnerability Reporting is enabled as of 2026-07-19. GitHub correctly refused a sole
administrator self-report, then the documented administrator-side synthetic draft was created,
read back, and closed without publication, CVE, or private fork. `main` requires `test` and
`gitleaks`, one approval, CODEOWNER review, last-push approval, stale-review
dismissal, and admin enforcement. On 2026-07-19 the owner authorized the
solo-maintainer path and engineering changed only the review sub-rule to zero
approvals, no required CODEOWNER approval, and no last-push approval. Strict
`test`/`gitleaks` checks, pull requests, admin enforcement, no force-push, and
no deletion remain.

## Status and evidence rules

The only package states are:

- **Pending** — dependencies or deliverables are incomplete; work may not be
  claimed as accepted.
- **In progress** — implementation is active, but the gate has not passed.
- **Externally pending** — all in-scope engineering evidence is ready, but a
  named owner/reviewer/host/elapsed-time action is still required.
- **Blocked** — a plan stop condition applies. Record the exact condition and
  the needed amendment or authority.
- **Passed** — every gate assertion has current, reviewable evidence and no
  mandatory check is skipped.

A passing entry must record all of the following in this file or in a linked,
immutable evidence record:

1. the exact commit and installed artifact hash where applicable;
2. commands and exit results, including required tests and scans;
3. the operating system, Python, Docker, and ClickHouse versions where relevant;
4. migration/schema/config/API versions exercised;
5. failure-injection or recovery evidence required by the gate;
6. any independent review and owner authorization;
7. open defects and their severity/disposition; and
8. the date and accountable reviewer who accepted the result.

Skipped tests, fixture-only provider behavior presented as live compatibility,
placeholder commands, and unverified external settings are not passing
evidence. A later regression returns the affected gate to **In progress**.

## Work-package ledger

| Package | Depends on | State | Gate evidence required before `Passed` | External owner/reviewer action |
|---|---|---|---|---|
| W00 — authority, governance, ADRs | Owner plan approval | **In progress** | Clean public baseline; correct branch; pre-alpha claims; plan-aligned ADR index; provenance, privacy, threat model, governance, support, and usable review path | E01 and E02 are complete for G00. A01 review, commit, and exact-head hosted checks remain |
| W01 — package and quality toolchain | G00 | Pending | Clean-clone install; wheel/sdist install; CLI help/version; resource inventory; required CI; planted-secret negative test | Replace the temporary `test`/`gitleaks` contexts with aggregate `required-ci` after the W01 workflow exists |
| W02 — domain, config, identity, privacy | G01 | Pending | Strict examples/schema; cross-process deterministic IDs; adversarial no-secret egress tests; critical branch coverage | None beyond review |
| W03 — SQLite, spool, replay, retention | G02 | Pending | Every durable-write kill point; concurrency; corruption recovery; replay of 10,000 records twice; permissions; privacy-expiry behavior | Access to a supported local filesystem/host if not available to engineering |
| W04 — ClickHouse and recovery | G02; G04b also requires G03 | Pending | G04a auth/migrations/checksums; G04b idempotent delivery, 24-hour simulated outage drain, and verified native restore | Docker-capable supported host if not available to engineering |
| W05 — runtime/canary vertical slice | G03 and G04 | Pending | Full canary-to-query slice; ClickHouse outage behavior; exact-once logical drain; alert transition cases | None beyond review |
| W06 — initialization, CLI, demo | G05 | Pending | Nonexpert clean-host flow; idempotent init; credential-free spool demo; health exit codes; installed/source parity | E06 clean-host evidence where engineering lacks the host |
| W07 — file/authenticated ingestion | G05 | Pending | Incremental outbox behavior; acknowledged rotation; P1 detection for unread loss; bounded/replay-safe receiver; offline CI | Owner acknowledgement is required before any non-loopback receiver test |
| W08 — feedback and verification | G07 | Pending | Complete transition matrix; claim cannot verify; idempotent curation; SQLite/ClickHouse parity; verified/regressed synthetic stories | None beyond review |
| W09 — query, reports, repo briefs | G08 | Pending | Metric-window correctness; path/symlink security; bounded/degraded reports; deterministic safe rendering | A configured application repository may be supplied for a final sandbox smoke; fixtures remain the CI basis |
| W10 — MCP | G09 | Pending | Official-client conformance; read-only default; bounded/privacy-filtered results; dual write enablement and idempotent audit | Local client smoke may require owner-provided supported client environment |
| W11 — `/doh` postmortems | G08 and G10 | Pending | Neutral evidence model; all required contributors in scope; untrusted rendering; missing-evidence and scenario tests | None beyond review |
| W12 — provider collectors | G05 | Pending | Per-provider fixture, pagination/rate/cursor/drift/privacy tests; no overlap inflation; least-privilege docs | E04 owner-authorized sandbox smoke is required before each adapter is labelled supported; otherwise it remains experimental |
| W13 — agent summaries/traces | G05 and G08 | Pending | Disabled default; idempotent incremental parse; visible drift; planted prompt/PII/secret absent from every persistence/egress surface | E04 owner-authorized format smoke is needed for a current supported-label claim |
| W14 — notifications/action sinks | G09 and G12 | Pending | Disabled default; redacted dry run; idempotent retry; safe Markdown; no secret/audit leakage; issue closure cannot verify | E04 separately authorizes each sandbox Telegram/GitHub write smoke; no production destination is assumed |
| W15 — scheduler/services | G06, G08, G09, G11, G12, G13, G14 | Pending | Lease exclusion; restart/replay; independent failure containment; freshness; generic service-template clean-host tests | E06 macOS/Ubuntu service-template hosts where unavailable to engineering |
| W16 — import/recovery/lifecycle | G03, G04, G09, G15 | Pending | Read-only/idempotent legacy import; clean-host point-in-time restore; upgrade/rollback; explicit destructive confirmation; RPO/RTO | E06 clean-host restore hosts; any real private legacy source remains owner-controlled and is never required by CI |
| W17 — docs/release hardening | G10–G16 | Pending | All doc/config/skill checks; exact artifact contents; installed workflows; scans; SBOM/provenance; no P0/P1 | E01, E03, E05, E06, and E08 protected-release settings/approvals; revisit required human review when a second maintainer exists |
| W18 — performance/soak/RC | G17 | Pending | Fixed-seed benchmarks; platform/recovery drills; 7/14/7-day soaks; two independent clean hosts; exact RC artifacts; no P0/P1 | E06 hosts, E07 elapsed environment, E05 review, and E08 RC/publish decisions |

“Pending” above means “not accepted”; it does not prohibit dependency-safe
preparatory work allowed by the plan. Dependencies and gates remain normative.

## W00 evidence checklist

| W00 item | Status at this snapshot | Evidence or remaining work |
|---|---|---|
| Owner approved plan 1.0 | Complete | Build instruction received 2026-07-18; external mutation remains separately controlled |
| Workspace uses audited public baseline without private history | Complete | Local branch parent and `origin/main` both resolve to `fb81a7faf2c101e8bb3f08ef9120d82c2b20600b`; only public history is present and private history was never imported |
| Branch `codex/build-milhouse-v1` | Complete | `git branch --show-current` observed locally on 2026-07-18 |
| Plan retained and status ledger created | Complete | [implementation-plan.md](implementation-plan.md) and this file |
| Locked decisions ratified by ADRs | Complete | `docs/adr/README.md` indexes 14 plan ratifications plus accepted process ADR 0015; local link and plan-anchor validation passed |
| README is truthful pre-alpha | Complete | README labels the current command/config/deployment as scaffold and gates every planned capability |
| Privacy contract | Complete as a W00 document | [../PRIVACY.md](../PRIVACY.md); implementation guarantees are not claimed operational until their gates pass |
| Threat/data inventory | Complete as a W00 document | [threat-model.md](threat-model.md); implementation controls still require their owning tests |
| Governance and DCO | Complete as a W00 document | [../GOVERNANCE.md](../GOVERNANCE.md); solo-maintainer pull-request/check policy recorded and applied. Automated DCO enforcement is a W01/W17 control |
| Support policy | Complete as a W00 document | [../SUPPORT.md](../SUPPORT.md) |
| Provenance inventory | Complete as a W00 document | [provenance.md](provenance.md); update per adapted donor file |
| Five-skill engineering workflow | In progress | Owner approved process amendment A01 on 2026-07-19. ADR 0015 pins `EveryInc/compound-engineering-plugin@8163a96e86656a89797869ac61905fe4641f81be` as a concept-only MIT reference and defines five Milhouse-native skills, discovery aliases, read-only review, sanitized learning, and authority guardrails. Static and five-skill fresh-agent validation passed. Gate re-review found both prior P2s resolved and no new P0-P2. DCO commit and exact-head hosted checks remain |
| Private vulnerability path | Complete for G00 | API read-back returned `enabled: true`. The private-report endpoint returned the documented HTTP 403 for the sole repository administrator; GitHub directs administrators to create a draft advisory instead. A clearly marked low-severity synthetic draft was created at 14:41:07Z, read back as private draft, and closed at 14:41:22Z with `published_at: null`, no CVE, no private fork, and zero remaining triage reports. A true third-party delivery smoke is deferred to E05/G17 when an independent reviewer exists |
| Merge/review path | Complete | Owner authorized solo-maintainer merges on 2026-07-19. Live protection retains PRs, strict `test`/`gitleaks`, admin enforcement, no force-push/deletion, with zero approvals and no impossible CODEOWNER/last-push self-review. PR #1 is mergeable and both protected checks passed at evidence head `11652eff2ec46f9c895c41a1c1a16aa28eac70b8` |
| Apache-2.0 ownership/provenance and DCO | Complete for W00 | Apache-2.0 retained; DCO policy and sign-off workflow documented; donor ledger records no private expression imported. Independent release review remains E05 for G17/G18 |
| Stale private-first/duplicate workflow instructions removed | Complete | Canonical workflows remain only under `.github/workflows`; stale `ops/github/workflows` copies/instructions removed; OpenWiki marked optional/noncanonical |

G00 is **not passed** until every W00 row is complete and the plan/ADR index,
merge path, public tree, and private-reference boundary are reviewed together.

## W00 validation evidence — 2026-07-18 through 2026-07-19

- The DCO-signed W00 commits through prior evidence head
  `11652eff2ec46f9c895c41a1c1a16aa28eac70b8` are pushed to PR #1.
- Branch `codex/build-milhouse-v1`, `HEAD`, and `origin/main` were verified at
  public baseline `fb81a7faf2c101e8bb3f08ef9120d82c2b20600b` before the W00
  commit.
- `make test`: passed (`1 passed` against the imported scaffold).
- `make docs-check`: passed.
- `make skill-check`: passed.
- `make secret-scan`: passed using the repository's current lightweight
  fallback because local `gitleaks` is not installed; W01 must make the scanner
  fail closed and G17 still requires full-history gitleaks/independent scans.
- W00 PR #1 initially exposed one gitleaks false positive in threat-model test
  prose. The prose was rewritten and only the exact historical finding
  fingerprint was suppressed in `.gitleaksignore`; no rule/path/general value
  allowlist was added.
- At prior evidence head `11652eff2ec46f9c895c41a1c1a16aa28eac70b8`,
  GitHub reported PR #1 mergeable and both protected `test` and `gitleaks`
  checks successful. Live branch protection retained strict checks, admin
  enforcement, required conversation resolution, and disabled force pushes
  and deletion.
- Targeted current-tree and full-public-history scans found no private personal
  label/path or credential-shaped value. The only `Tokru` match is the explicit
  prohibited-donor example in the authoritative plan.
- All checked-in TOML/JSON and GitHub YAML parsed successfully.
- `git diff --check`, ADR file/link/plan-anchor validation, and the
  duplicate-workflow absence checks passed.
- No private donor command wrote to the donor tree, and no private history,
  configuration, fixture, telemetry, report, or source file was imported.
- A01 local validation passed: `make docs-check`, `make skill-check`, `make test`
  (`2 passed` on Python 3.12.8/macOS), `make secret-scan`, `git diff --check`,
  JSON parsing, local Markdown-link resolution, and all five upstream
  `quick_validate.py` skill checks. Local secret scanning used the documented
  lightweight fallback because gitleaks is not installed; hosted gitleaks remains required.
- The deterministic negative fixture correctly rejected an injected `TODO` placeholder. The
  disposable fixture was outside the repository and was deleted after the test; no raw agent
  content was retained.
- [skill-evaluations.md](skill-evaluations.md) records sanitized behavior and adjacent-negative
  evidence for all five skills without raw prompts, responses, transcripts, or tool output.
- The first A01 gate review returned two P2 findings: static CI had been conflated with behavioral
  evidence, and W00 was incorrectly labelled externally pending. Both were corrected. Read-only
  re-review found no new P0-P2 and returned `externally_pending` only for commit and hosted checks.
- E01 private-path evidence: enabled read-back succeeded; the self-report endpoint returned GitHub's
  expected sole-administrator HTTP 403; an administrator-side `[TEST ONLY]` low-severity draft was
  created at 14:41:07Z, read back privately, and closed at 14:41:22Z. `published_at` remained null,
  no CVE or private fork was created, and the remaining triage count was zero.

The original W00 engineering and E02 PR-path test are complete. E01 is complete for G00 using
GitHub's documented sole-administrator path. A01 review, commit, and exact-head hosted checks remain;
W01 must not begin until they resolve and G00 passes.

## External action register

These actions cannot be inferred from “build it.” Engineering must prepare the
exact request/evidence, and the named owner must authorize or perform it.

| ID | Earliest gate | Accountable actor | Required action and evidence | Current state |
|---|---|---|---|---|
| E01 | G00/G17 | Repository owner | Enable GitHub private vulnerability reporting and test private advisory visibility and closeout without publishing sensitive content | Complete for G00 on 2026-07-19: enabled read-back passed; sole-admin self-report produced GitHub's documented 403; admin-side synthetic draft create/read/close passed with no publication, CVE, fork, or remaining triage report. Re-run a true third-party reporter-to-reviewer smoke with E05 at G17 |
| E02 | G00/G01/G17 | Repository owner | Maintain a usable solo-maintainer PR path; retain strict protected checks/admin enforcement/no force-push/deletion; move to required human/CODEOWNER review when a second maintainer exists | Complete for G00 on 2026-07-19: PR #1 was mergeable and `test`/`gitleaks` passed under the applied policy. W01 replaces contexts with aggregate `required-ci` |
| E03 | Before first public package/tag | Project owner | Verify project/distribution-name availability and complete any desired trademark/legal review; approve a plan amendment if names change | Pending |
| E04 | G12–G14 | Operator/project owner | Supply sandbox-only credentials and explicitly authorize each live provider/session-format/notification/action call; approve the redacted destination and retain the smoke record | Pending; fixture work may proceed |
| E05 | G17/G18 | Project owner and independent reviewer | Select an independent reviewer for security, provenance, package contents, and release evidence; record reviewer identity, scope, findings, fixes, and acceptance | Pending |
| E06 | G06/G15–G18 | Project owner/host owner | Supply or authorize required clean macOS 14/latest and Ubuntu 22.04/24.04 hosts when engineering cannot; retain exact environment and artifact-hash evidence | Pending until needed |
| E07 | G18 | Project owner/elapsed monitor | Keep the approved environment available for the 7-day alpha, 14-day beta, and 7-day RC soaks; preserve continuity evidence and respond to monitor alerts | Pending |
| E08 | G17/G18/release | Project/release owner | Build-branch push/PR/merge is authorized. Separately authorize protected release environment, signed tag/build, Trusted Publishing, GitHub Release, any visibility change, and announcement. Approval for one step does not imply the next | Branch push/PR/merge authorized 2026-07-19; release actions pending |
| E09 | Release completion | Project owner/release monitor | Authorize public-registry installs, announcement only after verification, and at least 72 hours of post-publication monitoring | Pending |

## Defects, amendments, and stop conditions

| ID | Date | Decision | Scope and disposition |
|---|---|---|---|
| A01 | 2026-07-19 | Owner-approved Compound Engineering process adaptation | Ratified by ADR 0015. Uses `EveryInc/compound-engineering-plugin@8163a96e86656a89797869ac61905fe4641f81be` as a concept-only MIT reference. Establishes five Milhouse-native skills, discovery aliases, read-only gate review, sanitized learning, and explicit privacy, egress, and mutation boundaries. No public API, stored schema, privacy promise, product scope, or release gate changed |

Add each discovered issue with severity P0–P3, owner, affected gates,
reproduction/evidence, and disposition. Stop only the affected workstream when a
locked privacy guarantee is infeasible, donor ownership is uncertain, a safe
reversible migration cannot be designed, or a change would materially expand
external writes, hosted operation, raw-content handling, or multi-tenancy.

## Update procedure

For every package:

1. Set it to **In progress** only after its dependencies permit work.
2. Link the implementation commit, tests, docs, and gate command output.
3. Record all open defects and external evidence separately.
4. Have CI or an independent reviewer evaluate the exact candidate.
5. Mark **Passed** only when every gate clause is satisfied.
6. Update the highest-passed gate and current snapshot without rewriting prior
   evidence; retain superseded evidence as dated history or immutable links.

Engineering completion, release-candidate readiness, and release completion are
three distinct outcomes. G18 can produce a release evidence packet; it does not
authorize or claim publication.
