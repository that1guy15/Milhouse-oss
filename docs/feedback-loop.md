# Feedback Loop

Milhouse closes the loop between what the team builds, how it behaves in production, how AI agents work, and what the operator needs to improve next.

## Loop

```mermaid
sequenceDiagram
  participant User as Operator
  participant Agent as Codex / Claude Code
  participant App as Application
  participant MH as Milhouse
  participant Store as ClickHouse
  participant Brief as Repo .milhouse Brief
  participant Report as Telegram / Weekly Report

  User->>Agent: Request work
  Agent->>App: Build, test, deploy
  App->>MH: Emit deploy, error, browser, backend, and usage events
  Agent->>MH: Emit session summary and tool failures
  MH->>Store: Store redacted normalized events
  MH->>MH: Curate patterns into feedback_items
  MH->>Brief: Write repo-local feedback
  MH->>Report: Send summaries and urgent alerts
  Agent->>Brief: Read feedback next session
  Agent->>MH: Update feedback status with PR/commit
  MH->>App: Re-check production signal
  MH->>Store: Mark verified or regressed
```

## Feedback Item Lifecycle

```text
open -> accepted -> shipped -> verified
open -> accepted -> shipped -> regressed
open -> rejected
```

Completion requires verification against the same class of signal that created the item.

## Inputs

- production incidents
- backend exceptions
- browser exceptions
- deploy failures
- stuck workflow jobs
- site canary failures
- agent tool failures
- repeated validation misses
- operator `/doh` marks
- weekly trend summaries

## Outputs

- MCP queryable feedback
- repo `.milhouse/FEEDBACK.md`
- repo `.milhouse/AGENT_FEEDBACK.md`
- repo `.milhouse/TEAM_WORKFLOW.md`
- GitHub issues when configured
- Telegram weekly summary
- postmortem report

## `/doh`

`/doh` means the previous work set missed intent while being treated as complete.

Milhouse should investigate:

- user prompt clarity
- requirements and status docs
- agent plan and execution
- validation evidence
- production or workflow signals
- what was assumed
- what was skipped
- what would prevent recurrence

The operator is assumed to be in scope alongside every agent and process step.
