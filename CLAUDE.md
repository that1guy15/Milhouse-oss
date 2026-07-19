# Claude Code Guide

Claude Code should treat Milhouse as an observability and feedback-loop system, not just a monitoring script.

Read first:

- `README.md`
- `docs/implementation-plan.md`
- `docs/implementation-status.md`
- `docs/architecture.md`
- `docs/feedback-loop.md`
- `docs/agents-and-tools.md`

Use the Milhouse MCP server when configured. If MCP is not available, read repo-local `.milhouse/` feedback briefs in the application repo.

Rules:

- Do not mark work complete without validation evidence.
- Do not write to application repos outside configured `.milhouse/` feedback directories unless explicitly assigned product work.
- Do not persist raw prompts, responses, transcripts, or tool output; that behavior is out of scope for Milhouse 1.0.
- Treat the private implementation as read-only donor material and record any intentional reuse in `docs/provenance.md`.
- Treat `/doh` as a request for postmortem analysis across prompts, assumptions, implementation, validation, and workflow.
- Prefer small, testable changes with clear acceptance evidence.
