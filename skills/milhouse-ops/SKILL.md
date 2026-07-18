---
name: milhouse-ops
description: Operate, extend, and validate Milhouse internals. Use when changing or reviewing collectors, config, spool/replay/export, ClickHouse schema, MCP tools, feedback lifecycle, redaction, reports, setup, tests, or production observability behavior in the Milhouse repository.
---

# Milhouse Ops

## Start

Read these files before changing internals:

- `docs/architecture.md`
- `docs/project-plan.md`
- `docs/agents-and-tools.md`
- `SECURITY.md`

For release or sanitization work, also read `skills/milhouse-oss-maintainer/SKILL.md`.

## Operating Rules

- Keep Milhouse local-first by default.
- Spool events before export.
- Keep collectors config-driven.
- Treat redaction as part of the data model, not an afterthought.
- Keep MCP read-focused unless a write is narrow, explicit, and auditable.
- Do not write to application repos except configured `.milhouse/` feedback directories.
- Do not add private app names, local paths, account IDs, tokens, raw traces, generated reports, or telemetry.
- Prefer fixture tests over live API tests.

## Implementation Workflow

1. Inspect existing docs and tests.
2. Identify the affected surface: collector, schema, feedback, MCP, report, config, or setup.
3. Make the smallest coherent change.
4. Add or update fake fixtures.
5. Run validation.
6. Update docs and examples.
7. Report what changed, what was verified, and what risk remains.

## Validation

Run:

```bash
make test
make docs-check
make skill-check
```

For public release or data-sensitive work:

```bash
make secret-scan
git status --short
```

## References

- `references/checklist.md`
