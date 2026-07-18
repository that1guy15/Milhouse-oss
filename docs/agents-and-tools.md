# Agents And Tools

Milhouse is built for a team of human and AI operators. This document defines the reusable agent roles, project skills, MCP surface, and tools needed for the OSS version.

## Required Agent Roles

### Product Operator

Owns priorities, confirms scope, marks `/doh` events, and reviews weekly reports.

### Milhouse Maintainer Agent

Maintains Milhouse internals, collectors, schema, redaction, reports, setup, and release safety.

Uses:

- `skills/milhouse-ops`
- `skills/milhouse-oss-maintainer`

### Application Delivery Agent

Builds the user's product or application. It consumes Milhouse feedback but should not mutate Milhouse internals unless explicitly assigned.

Uses:

- `skills/milhouse-feedback`
- MCP `feedback_list`, `events_query`, and `runs_status`
- repo `.milhouse/` briefs

### Operations Reviewer Agent

Reviews deploys, production health, error spikes, stuck jobs, workflow regressions, and alert gaps.

Uses:

- ClickHouse queries
- Cloudflare/GitHub collectors
- weekly report generator
- Telegram notifications

### Feedback Curator Agent

Turns repeated evidence into feedback items with owners, severity, verification signals, and proposed corrective actions.

### Postmortem Agent

Runs `/doh` investigations. It must assume the operator, prompt, requirements, agents, validation, docs, and workflow are all in scope.

### Documentation Agent

Keeps README, docs, skills, OpenWiki, and examples aligned with the implementation.

### Security Reviewer Agent

Reviews privacy boundaries, redaction, secret scans, generated telemetry exclusions, and public release readiness.

## Project Skills

### `milhouse-ops`

Use for Milhouse internals:

- collectors
- config
- ClickHouse schema
- spool/replay/export
- reports
- MCP server
- Telegram notifications
- redaction
- tests

### `milhouse-feedback`

Use inside application repos:

- read current feedback
- query Milhouse status
- update `.milhouse/` feedback outbox
- connect corrective action to PRs/commits
- request `/doh` postmortems

### `milhouse-oss-maintainer`

Use for public repo work:

- sanitize source/docs
- prepare releases
- run secret scans
- check private identifiers
- keep examples generic
- validate skills and docs

## Required Tools

- Git and GitHub
- Python 3.11+
- pytest
- ruff
- Docker or compatible container runtime
- ClickHouse local server
- MCP-compatible agent clients
- Codex
- Claude Code
- OpenWiki or similar generated docs tool
- gitleaks or trufflehog

## Optional Integrations

- Cloudflare APIs
- GitHub Actions
- Telegram Bot API
- LangSmith
- OpenAI API
- Anthropic API
- hosted ClickHouse
- GitHub Issues

## MCP Surface

Read-focused tools should ship first:

- `feedback_list`
- `feedback_get`
- `events_query`
- `runs_status`
- `health_summary`
- `weekly_report_get`

Narrow write tools:

- `feedback_update_status`
- `postmortem_create`

Every write must be auditable and bounded.

## Tooling Guardrails

- Do not query live systems in tests.
- Do not require production API keys for local setup.
- Do not commit `.mcp.json`; commit `.mcp.example.json`.
- Do not write to application repos outside configured `.milhouse/` directories.
- Do not store raw agent transcripts unless explicitly configured.
