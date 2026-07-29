# Community learning-companion template

Use this template with the [engineering-journal workflow](engineering-journal.md). The result is an
unpublished personal-content draft. Every completed blog post derived from an engineering-journal
Discussion about current work or features also receives the draft-only Substack handoff below. A
saved draft is not a release announcement or permission to publish, schedule, or send externally.

## Draft metadata

- **Reader question:** What should a curious nonexpert understand after reading?
- **Companion Discussion:** Link the evidence-first GitHub Discussion.
- **Audience:** Describe what the reader is not expected to know.
- **One user benefit:** State the practical outcome without claiming planned behavior exists.
- **Current boundary:** State what Milhouse cannot yet do.
- **Series position:** Standalone, or part N of a named sequence.
- **Substack handoff:** Pending or Saved; keep the personal draft URL in the task handoff, not here.

## Suggested structure

### Title: ask one plain-language question

Prefer a question or useful tension over a feature name. For example: “Why is writing a file not the
same as saving evidence?”

### Why I wanted to understand this

Use first person. Name the author's starting assumption, confusion, or curiosity. Do not claim prior
expertise.

### Start with an everyday example

Introduce one analogy that carries the central idea. Keep it accurate enough to help without making
the analogy do all of the technical work.

### Explain the idea in plain language

Define necessary terms at first use. Prefer “a record of what happened” to “telemetry” until the
distinction matters. Explain one mental model, not the whole architecture.

### Connect it to Milhouse

Describe only behavior verified on protected `main`. Link the companion Discussion for exact pull
requests, checks, and implementation detail.

### Explain the user benefit

Connect the foundation to reliability, privacy, recovery, or learning. Use future tense for benefits
that depend on unfinished product layers.

### Say what I learned

Name the changed understanding, tradeoff, or remaining question. A credible learning post can say
“I did not realize...” or “I am still learning...” without weakening the verified technical record.

### Preserve the availability boundary

Say what is not released, supported, or implemented. Never convert green CI or a merged foundation
into a product-availability claim.

### Lead to the next question

End with one natural follow-up topic. If that question needs its own mental model, make it the next
article rather than extending the current draft.

## Voice and evidence check

- [ ] The post sounds like a curious builder sharing a lesson, not an expert lecture.
- [ ] A nonexpert can explain the central idea after one read.
- [ ] Jargon is defined, removed, or linked to a later article.
- [ ] The Discussion remains the source for engineering detail and verification evidence.
- [ ] Implemented, in-progress, planned, and unavailable behavior are visibly distinct.
- [ ] No private data, raw agent content, private paths, provider payloads, or donor material appears.
- [ ] The draft does not imply that saving it grants permission to publish, schedule, or send it.

## Required Substack draft handoff

Apply these steps to every completed blog post derived from a Discussion about current work or
features. A series plan remains a task artifact, but each completed article in that series follows
the same handoff.

1. Use the connected Chrome session and the owner's already-authenticated Substack account. Never
   request, copy, store, or transmit login credentials.
2. Create a new post and transfer the reviewed title, subtitle, body, headings, lists, and links.
3. Verify the content boundary and formatting, then wait until the editor reports **Saved**.
4. Keep the draft editor open for owner review and return the draft URL only in the private task
   handoff; do not commit personal account or draft metadata.
5. Stop. Do not publish, schedule, send an email, change account settings, or invoke any final
   distribution action.

If the authenticated Chrome session is unavailable, leave the reviewed artifact intact and report
the Substack handoff as pending. Do not substitute an unsigned-in preview browser or broaden the
request into account recovery.
