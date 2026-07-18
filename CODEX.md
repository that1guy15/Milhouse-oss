# Codex Guide

Codex should use this repository as the public Milhouse source of truth.

## Skills

Use:

- `$milhouse-ops` when changing collectors, storage, reports, MCP, config, redaction, setup, or tests.
- `$milhouse-feedback` when reading Milhouse output from an app repo.
- `$milhouse-oss-maintainer` when preparing public releases, sanitizing examples, or checking repo hygiene.

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
