# Milhouse engineering journal

The Milhouse engineering journal is a maintainer-authored series in the repository's
[Announcements](https://github.com/that1guy15/Milhouse-oss/discussions/categories/announcements)
Discussions category. It lets people follow the architecture, tradeoffs, verification evidence,
and useful mistakes behind the build without mistaking active engineering for a product release.

## Publication contract

Publish after a meaningful architecture or feature slice reaches `merged_verified`. Group small
pull requests into one coherent milestone post; do not publish empty status updates merely to meet a
calendar. If several meaningful slices land together, publish a weekly roundup. Release, security,
incident-response, and availability announcements retain their separate authorization.

Each post must distinguish these claim classes:

- **Implemented and verified** — present on protected `main`, with exact pull-request and hosted-check
  links.
- **Architecture decision** — accepted and binding, but not necessarily implemented.
- **In progress** — actively being built and not yet accepted by its gate.
- **Planned** — dependency-bound future work, not a shipping or schedule commitment.
- **Not available** — an explicit pre-alpha, support, production-data, or release boundary.

Human explanation leads. Commit hashes and check runs support the story instead of replacing it.
Every post should answer: what problem are we solving, what changed, how does it fit the system, how
was it verified, what did we learn, what remains unavailable, and what is next?

## Workflow

1. Select only merged public evidence. Never inspect or quote private donor material, raw agent
   sessions, provider data, production telemetry, generated reports, or private incidents.
2. Draft a Markdown source under `docs/engineering-journal/` using the structure below. A feature PR
   may carry its own post, or a focused documentation PR may group several merged slices.
3. Run documentation, privacy, identifier, and secret checks. Review every capability statement
   against the exact protected commit and current implementation status.
4. Merge the source through the normal DCO, review, and Required CI path.
5. Publish the human-readable body in the maintainer-only `Announcements` category using the
   checked-in `announcements.yml` form. Link the source file and exact protected evidence.
6. If a factual correction is needed, preserve transparency: add a dated correction to the post and
   its checked-in source rather than silently changing the historical claim.

Publishing a journal post does not change a work-package state, pass a gate, authorize a release,
or prove that an unimplemented component works.

## Post structure

```text
Title
Pre-alpha status note
Why this matters
Implemented and verified
Architecture walkthrough
Verification evidence
What we learned
What is not available
What comes next
```

The canonical source for the inaugural post is
[Building Milhouse in public: foundations before features](engineering-journal/2026-07-22-foundations-before-features.md).
