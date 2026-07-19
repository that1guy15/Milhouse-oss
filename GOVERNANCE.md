# Milhouse governance

Milhouse is currently a maintainer-led pre-alpha project.

## Roles

- **Project owner/lead maintainer:** accountable for product scope, external settings, reviewer appointment, release authorization, and security coordination.
- **Maintainers:** review source, contracts, migrations, privacy/security impact, documentation, and release evidence.
- **Contributors:** submit DCO-signed changes with tests, docs, synthetic data, and provenance.
- **Independent reviewers:** evaluate owner-authored changes and the security/provenance/release packet without self-approval.
- **Release owner:** authorizes protected tags, Trusted Publishing, GitHub/PyPI publication, announcement, and rollback/yank decisions.

The current accountable owner is represented by `@that1guy15` in CODEOWNERS. A second trusted reviewer must be appointed for a normal owner-authored pull-request path; until that external action is complete, G00 remains pending.

## Decision process

`docs/implementation-plan.md` version 1.0 is the approved build authority. ADRs under `docs/adr/` ratify its locked outcomes. Implementation details may change through review only when every external contract, security/privacy property, migration, and acceptance gate remains intact.

A material change to scope, privacy, external writes, stored/public schemas, destructive behavior, or data-loss guarantees requires a numbered plan amendment with alternatives, compatibility, migration, security, and test impact plus owner approval. An ADR cannot silently amend the plan.

## Contributions and review

- Apache-2.0 source license.
- Developer Certificate of Origin 1.1 sign-off on every commit; no CLA initially.
- Pull requests, protected checks, resolved review, provenance review, and eligible independent approval.
- Owner-authored changes cannot be self-approved.
- Security-sensitive changes receive targeted privacy/threat-model review.
- No P0/P1 defect or unresolved ownership/provenance concern may merge or release.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the contributor workflow.

## Releases

Engineering completion, release-candidate readiness, and publication are separate. Build approval does not authorize remote push, live-provider use, a tag, package publication, visibility changes, announcement, or external messages. Release authority and evidence follow sections 12-14 of the implementation plan.

## Conduct and security

Participation follows [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Security and privacy issues use the private process in [SECURITY.md](SECURITY.md), never a public issue containing sensitive material.
