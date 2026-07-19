# Codex Guide

Codex should use this repository as the public Milhouse source of truth. `docs/implementation-plan.md` is the normative 1.0 build contract and `docs/implementation-status.md` is the evidence ledger.

## Skills

Use:

- `$milhouse-ops` when changing collectors, storage, reports, MCP, config, redaction, setup, or tests.
- `$milhouse-feedback` when reading Milhouse output from an app repo.
- `$milhouse-oss-maintainer` when preparing public releases, sanitizing examples, or checking repo hygiene.

Execute W00-W18 in dependency order. Do not copy the private repository as a base, change a locked contract implicitly, or mark a gate complete without its recorded evidence.

## Tools

Expected local tools:

- shell
- git
- Python 3.11+
- pytest
- ruff
- Docker or Compose
- ClickHouse client or HTTP
- gitleaks or trufflehog
- MCP-compatible agent client

Use `apply_patch` for manual edits.

## Validation

Before saying work is complete:

```bash
make test
make docs-check
make skill-check
```

For public release work:

```bash
make secret-scan
git status --short
```

## Privacy

Never copy private telemetry, logs, raw agent sessions, local paths, tokens, account IDs, or production incident details into this repo.
Milhouse 1.0 never persists raw prompts, responses, transcripts, or tool output.
