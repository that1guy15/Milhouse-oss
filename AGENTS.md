# Agent Instructions

Milhouse is a local-first observability and feedback-loop platform for AI-assisted engineering teams.

Before changing Milhouse internals, read:

- `docs/implementation-plan.md`
- `docs/implementation-status.md`
- `docs/architecture.md`
- `docs/project-plan.md`
- `docs/agents-and-tools.md`
- `SECURITY.md`

Use these skills when available:

- `milhouse-ops` for Milhouse internals
- `milhouse-feedback` when consuming operational feedback from an application repo
- `milhouse-oss-maintainer` for public release, sanitization, and repository hygiene

Rules:

- Do not commit secrets, telemetry, logs, generated reports, raw agent transcripts, `.env`, `.mcp.json`, or private overlays.
- Treat `docs/implementation-plan.md` as the normative 1.0 contract. Do not change a locked contract without its amendment process.
- Never persist raw prompts, responses, transcripts, or tool output in 1.0.
- Keep the private donor repository read-only and record intentional reuse in `docs/provenance.md`.
- Keep examples generic.
- Keep app repos read-only except configured `.milhouse/` feedback directories.
- Prefer config-driven collectors over hardcoded project logic.
- Run `make test`, `make docs-check`, and `make skill-check` before reporting complete.
- Treat `/doh` as a postmortem trigger, not a blame shortcut.
