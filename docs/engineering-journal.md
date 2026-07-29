# Milhouse engineering journal

The Milhouse engineering journal is a maintainer-authored series in the repository's
[Announcements](https://github.com/that1guy15/Milhouse-oss/discussions/categories/announcements)
Discussions category. It lets people follow the architecture, tradeoffs, verification evidence,
and useful mistakes behind the build without mistaking active engineering for a product release.

Each meaningful journal milestone also produces an unpublished personal-learning companion. The
Discussion is the precise engineering record. The companion teaches one useful idea to a reader who
does not already understand observability, durable systems, or verified feedback loops. It uses an
honest beginner-peer voice: what we built, what the maintainer learned, why it matters, and how it
could eventually help a user.

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

## Paired learning companion

The learning companion is not a simplified changelog and must not pretend the author is a storage,
observability, or distributed-systems expert. It should:

- start with one question a curious nonexpert might ask;
- explain unfamiliar terms at first use or replace them with ordinary language;
- use a concrete everyday example before architecture detail;
- connect the feature to a future user benefit without claiming unfinished behavior exists;
- say what the author learned or initially found confusing;
- link the Discussion as the technical evidence record rather than copying all of its details;
- distinguish what works on protected `main`, what is being built, and what a user cannot do yet;
- avoid code, commit hashes, coverage percentages, and internal class names unless they teach the
  selected idea; and
- end with the next question in the learning journey.

Use one companion post when the milestone has one central mental model that fits a focused article.
Create a series plan when the draft would teach more than one independent concept, require more than
about 1,600 words, or force a reader to understand one topic before another. A series gives each post
one reader question, one practical analogy, one Milhouse connection, and one honest availability
boundary. The Discussion may support several later articles; do not force a one-to-one publication
schedule. A series plan is not itself a blog post; each completed, dependency-ready article in the
series receives its own draft-only Substack handoff.

## Workflow

1. Select only merged public evidence. Never inspect or quote private donor material, raw agent
   sessions, provider data, production telemetry, generated reports, or private incidents.
2. Draft the evidence-first Markdown source under `docs/engineering-journal/` using the Discussion
   structure below. A feature PR may carry its own post, or a focused documentation PR may group
   several merged slices.
3. From the same public evidence, prepare an unpublished personal-learning companion using the
   [learning-companion template](community-learning-template.md). Store it only in the
   owner-approved personal-content workspace or the task artifact directory; do not commit the
   personal draft unless the owner explicitly requests a public canonical copy.
4. Decide whether the topic is one focused article or a series. For a series, create the complete
   sequence and draft the first dependency-ready article; later entries may follow later milestones.
5. Run documentation, privacy, identifier, and secret checks. Review every capability statement
   against the exact protected commit and current implementation status.
6. Merge the Discussion source and reusable workflow/template changes through the normal DCO,
   review, and Required CI path.
7. Publish the human-readable body in the maintainer-only `Announcements` category using the
   checked-in `announcements.yml` form. Link the source file and exact protected evidence.
8. Complete the learning companion's voice and evidence checks. The owner's final editorial review
   happens in the saved Substack draft editor.
9. For every completed learning blog derived from a Discussion about current work or features, use
   the connected Chrome session and the owner's already-authenticated Substack account. Create a new
   post, transfer the title, subtitle, body, headings, lists, and links, and verify that the editor
   reports **Saved**. Keep the draft editor available for owner review and return its draft URL in the
   task handoff; do not commit personal account or draft metadata to the repository.
10. Stop at the saved draft. Do not publish, schedule, send an email, change account settings, or
    request credentials. If authenticated Chrome is unavailable, retain the task artifact, report
    the Substack handoff as pending, and do not substitute an unsigned-in preview browser.
11. If a factual correction is needed, preserve transparency: add a dated correction to the post and
   its checked-in source rather than silently changing the historical claim.

Publishing a journal post does not change a work-package state, pass a gate, authorize a release,
or prove that an unimplemented component works.

The standing Substack authority recorded in the implementation-status E10 register covers creating
and saving unpublished drafts only. It is not personal-blog publication authority, and it never
extends GitHub Discussion authorization into distribution through Substack.

## Discussion structure

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

## Learning-companion structure

```text
One reader question as the title
Why I wanted to understand this
An everyday example
The idea in plain language
What we built in Milhouse
Why it could benefit a user
What I learned or still find uncertain
What is not available yet
The next question in the series
```

## Canonical sources

- [Build Journal #1 — Foundations before features](engineering-journal/2026-07-22-foundations-before-features.md)
- [Build Journal #2 — From privacy contracts to durable storage](engineering-journal/2026-07-24-privacy-contracts-to-durable-storage.md)
- [Build Journal #3 — When durable storage means recoverable evidence](engineering-journal/2026-07-29-recoverable-evidence.md)
