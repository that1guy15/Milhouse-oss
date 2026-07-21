# Milhouse OSS Implementation Status

This file is the durable execution ledger for the
[authoritative implementation plan](implementation-plan.md). It records gate
status and evidence; it does not amend the plan.

## Current snapshot

| Field | Value |
|---|---|
| Snapshot date | 2026-07-21 |
| Product phase | **Pre-alpha; not released and not ready for production use** |
| Plan | Version 1.0, approved for implementation by the owner on 2026-07-18 |
| Target release | Milhouse OSS 1.0 |
| Working branch | `codex/w02-structured-errors` |
| Git state | This snapshot is based on protected `main` commit `48af4d4e0112d9d2121e8a600c9375af5b1a6837`; every job in post-merge Required CI run `29869922059` passed |
| Public source baseline | `that1guy15/Milhouse-oss@fb81a7faf2c101e8bb3f08ef9120d82c2b20600b` |
| Private reference baseline | `that1guy15/milhouse@18ee9514ee11413812fde8fe361405b3686e025f` |
| External mutation authority | Owner authorized build-branch pushes, pull requests, and merges to `main` after required checks on 2026-07-19. Tags, package publication, announcements, live-provider calls, and unrelated external mutation remain separately controlled |
| Highest passed gate | G01 |
| Active package | W02 implementation: clean-room stable-error and safe structured-event primitives plus bounded value-free config diagnostics after the merged time, domain, config, identity, privacy, and key-material foundations |

The audited public baseline is the source scaffold. The private baseline is a
read-only behavior and algorithm donor. Its history, configuration, telemetry,
generated data, private fixtures, and private documentation must never enter
this repository. See [provenance.md](provenance.md).

Read-only GitHub API evidence captured 2026-07-18: the repository is public,
unarchived, and uses protected `main`; Issues and Discussions are enabled;
secret scanning, push protection, and Dependabot security updates are enabled;
Private Vulnerability Reporting is enabled as of 2026-07-19. GitHub correctly refused a sole
administrator self-report, then the documented administrator-side synthetic draft was created,
read back, and closed without publication, CVE, or private fork. On 2026-07-19 the owner authorized
the solo-maintainer path and engineering changed the review sub-rule to zero approvals, no required
CODEOWNER approval, and no last-push approval. After the W01 aggregate first passed, the temporary
`test`/`gitleaks` contexts were replaced by the single strict GitHub Actions `required-ci` context.
Pull requests, stale-review dismissal, conversation resolution, administrator enforcement, no
force-push, and no deletion remain. An intentional W01 failure subsequently proved the required
aggregate blocks merge.

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
| W00 — authority, governance, ADRs | Owner plan approval | **Passed** | PR #1 merged as signed squash commit `79b9fdca3c567b1de48a3136fbe4ba0dd981926a`; reviewed head tree matched protected `main`; post-merge `test` and `gitleaks` passed | E01 and E02 complete for G00; third-party PVR delivery remains E01/E05 at G17 |
| W01 — package and quality toolchain | G00 | **Passed** | [G01 evidence](gate-evidence/G01.md): exact candidate and remediation trees passed local gates, 18-check hosted PR runs, three independent reviews, signed protected merges, exact-tree equality, post-merge required CI, and corrected default-branch updater execution at commit `333c051ea1018a624715b98bf5dad7c885bdeca5` | G01 accepted by engineering on 2026-07-19 under the owner-authorized solo-maintainer path; aggregate `required-ci` and protection controls remain active |
| W02 — domain, config, identity, privacy | G01 | **In progress** | Merged PRs #8-#16 provide deterministic bytes/IDs, strict config/schema/CLI foundations, canonical record envelopes, keyed pseudonyms, safe URL/path/evidence handling, layered redaction, nested allowlists, secure runtime paths and secret loading, secure pseudonym-key material creation/recovery, injected UTC/monotonic clocks, and an internal caller-bounded duration parser. This clean-room candidate adds shared stable coded errors, code-only unknown-error normalization, injected sink-agnostic structured events restricted to safe machine metadata, private raw Pydantic models, and bounded config diagnostics that hide values and unknown keys. W06 owns public CLI/JSON/stderr rendering; W02 retains persisted structured-log destination and rotation work for a later slice unless a plan-consistent ADR reassigns it; W03 owns durable data-retention execution. Common egress enforcement, plugin validation, cross-platform identity evidence, and the final G02 adversarial corpus remain required before `Passed` | None beyond review |
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
| Five-skill engineering workflow | Complete | ADR 0015 pins `EveryInc/compound-engineering-plugin@8163a96e86656a89797869ac61905fe4641f81be` as a concept-only MIT reference. Five Milhouse-native skills, aliases, canonical instructions, sanitized evaluations, and strict negative validation merged in signed commit `79b9fdca3c567b1de48a3136fbe4ba0dd981926a`; final review found no P0-P2 and protected post-merge checks passed |
| Private vulnerability path | Complete for G00 | API read-back returned `enabled: true`. The private-report endpoint returned the documented HTTP 403 for the sole repository administrator; GitHub directs administrators to create a draft advisory instead. A clearly marked low-severity synthetic draft was created at 14:41:07Z, read back as private draft, and closed at 14:41:22Z with `published_at: null`, no CVE, no private fork, and zero remaining triage reports. A true third-party delivery smoke is deferred to E05/G17 when an independent reviewer exists |
| Merge/review path | Complete | Owner authorized solo-maintainer merges on 2026-07-19. PR #1 merged through the repository's squash-only policy as signed commit `79b9fdca3c567b1de48a3136fbe4ba0dd981926a`; the reviewed head tree matched protected `main`, and both post-merge checks passed |
| Apache-2.0 ownership/provenance and DCO | Complete for W00 | Apache-2.0 retained; DCO policy and sign-off workflow documented; donor ledger records no private expression imported. Independent release review remains E05 for G17/G18 |
| Stale private-first/duplicate workflow instructions removed | Complete | Canonical workflows remain only under `.github/workflows`; stale `ops/github/workflows` copies/instructions removed; OpenWiki marked optional/noncanonical |

G00 **passed** on 2026-07-19 at protected-main commit
`79b9fdca3c567b1de48a3136fbe4ba0dd981926a` after the plan/ADR index, merge path,
public tree, private-reference boundary, seven supplemental P2 dispositions, and exact-tree hosted
checks were reviewed together.

## W00 validation evidence — 2026-07-18 through 2026-07-19

- The DCO-signed W00 commits through prior evidence head
  `11652eff2ec46f9c895c41a1c1a16aa28eac70b8` are pushed to PR #1.
- Branch `codex/build-milhouse-v1`, `HEAD`, and `origin/main` were verified at
  public baseline `fb81a7faf2c101e8bb3f08ef9120d82c2b20600b` before the W00
  commit.
- `make test`: passed (`1 passed` against the imported scaffold).
- `make docs-check`: passed.
- `make skill-check`: passed.
- `make secret-scan`: passed using the repository's then-current lightweight
  fallback because local `gitleaks` was not installed. W01 subsequently made tree/history scans
  fail closed and self-testing; G17 still requires independent release scans.
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
- Supplemental pre-merge audits found one P2 in publication-checklist state and four P2s in skill
  metadata, canonical-source, context-parity, and privacy validation. The checklist now separates
  the completed administrator draft test from the open G17 third-party smoke. Validation now parses
  the exact metadata schema, rejects canonical-source symlinks, enforces hierarchy/role/mutation
  parity, scans every skill/evidence context, and includes negative regressions for each defect.
- A later validation audit found two additional P2s: SKILL frontmatter could pass malformed YAML,
  and private Linux user or privileged-home paths were not detected. All five frontmatters now use
  an exact quoted-string schema with duplicate/type/mapping regressions; Linux skill/evidence path
  regressions complete the synthetic privacy matrix. The final local suite passes 14 tests.
- Final report-only review of head `46f99e0a3af6741cfb2089b4672116ec0e04defc` found no remaining
  P0-P2. Protected `test` and `gitleaks` passed on that exact head before merge.
- PR #1 merged at 15:23:58Z as signed squash commit
  `79b9fdca3c567b1de48a3136fbe4ba0dd981926a`. Its tree exactly matched the reviewed head; protected
  post-merge [`test`](https://github.com/that1guy15/Milhouse-oss/actions/runs/29692758580) and
  [`gitleaks`](https://github.com/that1guy15/Milhouse-oss/actions/runs/29692758558) both passed.
- E01 private-path evidence: enabled read-back succeeded; the self-report endpoint returned GitHub's
  expected sole-administrator HTTP 403; an administrator-side `[TEST ONLY]` low-severity draft was
  created at 14:41:07Z, read back privately, and closed at 14:41:22Z. `published_at` remained null,
  no CVE or private fork was created, and the remaining triage count was zero.

W00, E01 for G00, E02, and A01 are complete. The independent third-party PVR delivery smoke remains
deferred to E01/E05 at G17. W01 began from the exact protected-main G00 commit.

## External action register

These actions cannot be inferred from “build it.” Engineering must prepare the
exact request/evidence, and the named owner must authorize or perform it.

| ID | Earliest gate | Accountable actor | Required action and evidence | Current state |
|---|---|---|---|---|
| E01 | G00/G17 | Repository owner | Enable GitHub private vulnerability reporting and test private advisory visibility and closeout without publishing sensitive content | Complete for G00 on 2026-07-19: enabled read-back passed; sole-admin self-report produced GitHub's documented 403; admin-side synthetic draft create/read/close passed with no publication, CVE, fork, or remaining triage report. Re-run a true third-party reporter-to-reviewer smoke with E05 at G17 |
| E02 | G00/G01/G17 | Repository owner | Maintain a usable solo-maintainer PR path; retain strict protected checks/admin enforcement/no force-push/deletion; move to required human/CODEOWNER review when a second maintainer exists | Complete for G00/G01 on 2026-07-19: protected PRs #1, #2, and #5 merged through the authorized path; the sole strict aggregate `required-ci` context, admin enforcement, conversation resolution, and no force-push/deletion controls remain active. Revisit human/CODEOWNER review at G17 or when a second maintainer exists |
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
