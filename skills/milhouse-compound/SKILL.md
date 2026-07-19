---
name: "milhouse-compound"
description: "Capture one verified, reusable Milhouse engineering learning in sanitized project documentation. Use only when explicitly asked to compound, document, or preserve a solved problem or pattern after verification. Never search raw agent sessions or persist prompts, responses, transcripts, tool output, telemetry, or private donor material."
---

# Milhouse Compound

## Require verified reusable evidence

Invoke this skill only after implementation evidence and a `milhouse-gate-review` result exist. Keep
one learning only when it generalizes beyond the current patch and is not already documented.

Allowed inputs are reviewed diffs, accepted ADRs, sanitized status entries, concise command-result
summaries, synthetic fixtures, resolved findings, and canonical normalized feedback or postmortem
records. Never discover, search, read, extract, summarize, or persist session histories, chats,
transcripts, prompts, responses, tool output, raw feedback or outboxes, logs, telemetry databases,
provider bodies, credentials, private donor context, or copied external context.

## Route the knowledge

- Public contract or stored-schema change: use the numbered amendment or ADR process.
- Gate evidence or defect state: update `docs/implementation-status.md`.
- Operational procedure: update the owning runbook or troubleshooting page.
- Reuse or license fact: update `docs/provenance.md`.
- Security vulnerability: use private reporting; do not create a public learning.
- Reusable verified engineering technique or failure pattern: create one file under
  `docs/solutions/` using `references/solution-contract.md`.

Do not edit instruction files automatically. Do not create a learning merely to summarize work.

## Write a sanitized learning

1. Search canonical documentation for overlap and update the existing artifact when appropriate.
2. Ground each claim in repository contracts, a reviewed diff, synthetic tests, and concise command
   evidence.
3. Remove names, local paths, credentials, private identifiers, raw quotes, payloads, and source
   content. Use work-package, gate, component, and evidence identifiers instead.
4. Record applicability and when the pattern must not be used.
5. Run `git diff --check`, `./scripts/run_make.py docs-check`,
   `./scripts/run_make.py skill-check`, and `./scripts/run_make.py secret-scan`.
6. Hand the artifact to `milhouse-oss-maintainer`; never commit, push, or publish automatically.

Selecting this skill authorizes only the explicitly requested sanitized documentation write.
