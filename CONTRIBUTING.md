# Contributing To Milhouse

Thanks for helping build Milhouse.

Milhouse handles operational data, agent traces, and feedback loops, so contribution quality is measured by correctness, privacy, and reproducibility as much as feature speed.

## Development Setup

```bash
./setup.sh
make test
make docs-check
make skill-check
```

## Contribution Rules

- Keep examples generic and fake.
- Do not commit `.env`, generated reports, JSONL spools, ClickHouse data, raw agent transcripts, or private incident details.
- Prefer config-driven providers over hardcoded service names.
- Keep local-first behavior working.
- Add or update tests when changing collectors, schema, feedback lifecycle, MCP tools, or redaction.
- Update docs when changing commands, config, or agent workflows.

## Pull Request Checklist

- Tests pass.
- Docs checks pass.
- Skills validate.
- Config examples parse.
- No private domains, account IDs, tokens, local paths, or generated telemetry are present.
- Any new collector has fixture tests.
- Any new alert or feedback rule documents threshold behavior and false-positive handling.
- Pull requests target `main` and require maintainer review before merge.
- CODEOWNERS requires `@that1guy15` review for repository-wide changes.

## Community Channels

- Use Issues for actionable bugs, features, docs gaps, and integration requests.
- Use Discussions for architecture questions, design tradeoffs, ideas, and show-and-tell posts.
- Use private security reporting for credentials, telemetry exposure, or privacy bugs.

## Commit Style

Use concise conventional-style commits when possible:

```text
feat(collector): add generic workflow status collector
fix(redaction): mask bearer tokens in browser traces
docs(agent): describe Codex feedback workflow
```

## Security Issues

Do not open public issues for security or privacy leaks. Follow [SECURITY.md](SECURITY.md).
