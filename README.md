# Milhouse

Milhouse is a local-first observability and feedback-loop platform for AI-assisted engineering teams.

It watches production systems, deploys, synthetic checks, developer workflows, and AI agent sessions, then turns those signals into feedback that humans, Codex, Claude Code, and other agents can act on.

Repository remote: `https://github.com/that1guy15/Milhouse-oss.git`

## What Milhouse Does

- Collects production health, deploy, CI, browser, backend, and agent workflow events.
- Spools events locally before export so collection keeps working during outages.
- Stores analytical data in local ClickHouse by default.
- Exposes read-focused MCP tools for agents.
- Writes repo-local `.milhouse/` feedback briefs for passive agent context.
- Creates postmortem-style feedback when `/doh` marks missed intent or failed validation.
- Sends optional weekly summaries and urgent alerts through Telegram.

## Current Status

This repository is the OSS starter kit and handoff package. It contains the public architecture, setup contract, contribution docs, agent instructions, and project skills needed to rebuild the reusable Milhouse platform safely.

The private Milhouse implementation should not be made public directly. Reusable code should be copied into this repo only after it has been sanitized, generalized, tested, and scanned.

## Quickstart

```bash
git clone https://github.com/that1guy15/Milhouse-oss.git milhouse-oss
cd milhouse-oss
./setup.sh
```

Then edit:

```text
.env
config/milhouse.toml
```

Useful local commands:

```bash
make docs-check
make skill-check
make test
```

## Configuration

Milhouse uses a public-safe base repo plus private overlays.

Public repo:

```text
config/example.toml
.env.example
```

Private user config:

```text
~/milhouse-private/
  .env
  config/milhouse.toml
```

The public repo must never contain real tokens, production incident data, raw agent transcripts, ClickHouse data, JSONL spools, generated reports, or private application config.

## Agent Integration

Milhouse is designed for both active MCP access and passive repo context.

For MCP, copy `.mcp.example.json` into the agent environment and point `MILHOUSE_CONFIG` at a private config file.

For passive repo feedback, Milhouse writes files like:

```text
my-app/.milhouse/
  FEEDBACK.md
  AGENT_FEEDBACK.md
  TEAM_WORKFLOW.md
  feedback-outbox.jsonl
```

Application repos should normally be read-only to Milhouse and AI agents except for their configured `.milhouse/` feedback directory.

## Documentation

Start here:

- [Architecture](docs/architecture.md)
- [Project Plan](docs/project-plan.md)
- [Agents And Tools](docs/agents-and-tools.md)
- [Feedback Loop](docs/feedback-loop.md)
- [OpenWiki](docs/openwiki.md)
- [GitHub Setup](docs/github-setup.md)
- [Security And Privacy](SECURITY.md)
- [Publication Checklist](docs/publication-checklist.md)

## Project Skills

This repo ships Codex-compatible skills:

- `skills/milhouse-ops`: operate and extend Milhouse internals.
- `skills/milhouse-feedback`: consume Milhouse feedback in application repos.
- `skills/milhouse-oss-maintainer`: sanitize, document, and validate public releases.

## License

Apache License 2.0. See [LICENSE](LICENSE).
