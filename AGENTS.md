# Agent Instructions

Milhouse is a local-first observability and feedback-loop platform for AI-assisted engineering teams.

Before changing Milhouse internals, read:

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
- Keep examples generic.
- Keep app repos read-only except configured `.milhouse/` feedback directories.
- Prefer config-driven collectors over hardcoded project logic.
- Run `make test`, `make docs-check`, and `make skill-check` before reporting complete.
- Treat `/doh` as a postmortem trigger, not a blame shortcut.
