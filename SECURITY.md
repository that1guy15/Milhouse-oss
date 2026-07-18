# Security And Privacy

Milhouse observes systems and AI workflows. Treat every telemetry source as potentially sensitive.

## Do Not Commit

- `.env` or `.env.*` files with real values
- API tokens, bot tokens, account IDs, RUM tags, webhook URLs, or admin credentials
- `spool/`, `data/`, `logs/`, `reports/generated/`, or ClickHouse data
- raw Claude Code, Codex, LangSmith, browser, backend, or terminal transcripts
- production incident reports containing private user, company, or customer data
- private application configuration

## Private Overlay Pattern

Keep public Milhouse code separate from private operational config.

```text
milhouse/
  config/example.toml

~/milhouse-private/
  .env
  config/milhouse.toml
  docs/private-runbook.md
```

Run with:

```bash
MILHOUSE_CONFIG=~/milhouse-private/config/milhouse.toml milhouse health
```

## Agent Trace Handling

Agent trace ingestion should be opt-in. Before enabling it, decide:

- what logs are collected
- how long traces are retained
- how prompts and tool outputs are redacted
- whether raw transcripts are stored at all
- who can query traces through MCP

Milhouse should store structured summaries and redacted events by default, not unlimited raw session logs.

## Reporting Vulnerabilities

If you find a security issue, report it privately to the repository owner. Include:

- affected version or commit
- reproduction steps
- impact
- suggested mitigation if known

Please do not include live credentials or private user data in the report.
