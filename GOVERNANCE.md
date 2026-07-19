# Milhouse governance

Milhouse is currently a maintainer-led pre-alpha project.

## Roles

- **Project owner/lead maintainer:** accountable for product scope, external settings, reviewer appointment, release authorization, and security coordination.
- **Maintainers:** review source, contracts, migrations, privacy/security impact, documentation, and release evidence.
- **Contributors:** submit DCO-signed changes with tests, docs, synthetic data, and provenance.
- **Independent reviewers:** evaluate the security/provenance/release packet and material changes when appointed; Codex/sub-agent review supplies recorded engineering review in solo-maintainer development.
- **Release owner:** authorizes protected tags, Trusted Publishing, GitHub/PyPI publication, announcement, and rollback/yank decisions.

The current accountable owner and sole GitHub maintainer is `@that1guy15`. In solo-maintainer mode, every owner-authored change still uses a pull request and mandatory protected checks, but GitHub human-approval/CODEOWNER requirements are zero because self-approval is impossible. The owner is explicitly authorized to merge those pull requests after checks pass. A second trusted maintainer triggers required human/CODEOWNER approval.

## Decision process

`docs/implementation-plan.md` version 1.0 is the approved build authority. ADRs under `docs/adr/` ratify its locked outcomes. Implementation details may change through review only when every external contract, security/privacy property, migration, and acceptance gate remains intact.

A material change to scope, privacy, external writes, stored/public schemas, destructive behavior, or data-loss guarantees requires a numbered plan amendment with alternatives, compatibility, migration, security, and test impact plus owner approval. An ADR cannot silently amend the plan.

## Contributions and review

- Apache-2.0 source license.
- Developer Certificate of Origin 1.1 sign-off on every commit; no CLA initially.
- Pull requests, protected checks, resolved review, provenance review, and recorded Codex/sub-agent review evidence.
- Owner-authored changes cannot manufacture a self-approval; the solo-maintainer rule uses zero required approvals while retaining pull requests and checks.
- Security-sensitive changes receive targeted privacy/threat-model review.
- No P0/P1 defect or unresolved ownership/provenance concern may merge or release.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the contributor workflow.

## Releases

Engineering completion, release-candidate readiness, and publication are separate. On 2026-07-19 the owner authorized build-branch pushes, pull-request creation, and merging those pull requests to `main` after required checks. This does not authorize live-provider use, tags, package publication, visibility changes, announcements, or other external messages. Release authority and evidence follow sections 12-14 of the implementation plan.

## Conduct and security

Participation follows [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Security and privacy issues use the private process in [SECURITY.md](SECURITY.md), never a public issue containing sensitive material.
