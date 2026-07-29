# Community learning-companion template

Use this template with the [engineering-journal workflow](engineering-journal.md). The result is an
unpublished personal-content draft, not a release announcement or permission to publish externally.

## Draft metadata

- **Reader question:** What should a curious nonexpert understand after reading?
- **Companion Discussion:** Link the evidence-first GitHub Discussion.
- **Audience:** Describe what the reader is not expected to know.
- **One user benefit:** State the practical outcome without claiming planned behavior exists.
- **Current boundary:** State what Milhouse cannot yet do.
- **Series position:** Standalone, or part N of a named sequence.

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
- [ ] The draft does not imply permission to publish to Substack or another external destination.
