# Feedback Workflow Reference

Feedback item statuses:

- `open`: evidence exists and no owner/action has been accepted.
- `accepted`: a permitted actor supplied an owner, rationale, request ID, expected revision, and
  evidence through the domain service.
- `shipped`: a typed change reference and validation-evidence IDs landed and await observation.
- `verified`: the verification engine observed the configured same-class improvement.
- `regressed`: the verification engine observed no improvement or a worse same-class signal.
- `rejected`: the item was intentionally declined with rationale.

An application agent may request acceptance, shipping, rejection, reopening, or verification only
through an implemented surface. It never asserts `verified` or `regressed`, and caller-supplied actor
text is not authoritative identity.

Evidence to include when requesting a transition:

- PR or commit
- test result
- deploy/run ID
- relevant typed event query
- current revision and idempotent request ID
- remaining risk

Use normalized briefs or typed MCP results only. Do not read raw outboxes, sessions, logs, provider
bodies, prompts, transcripts, tool output, or telemetry databases. Do not call work verified based
on agent confidence.
