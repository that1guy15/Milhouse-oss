---
name: milhouse-feedback
description: Consume and act on Milhouse feedback from application repositories. Use when an agent needs to read operational signals, feedback items, repo `.milhouse` briefs, MCP query results, `/doh` postmortems, weekly summaries, or update feedback status with evidence from product work.
---

# Milhouse Feedback

## Start

Use Milhouse as the feedback source before deciding that work is complete.

Read, in this order:

1. Repo `.milhouse/FEEDBACK.md` if present.
2. Repo `.milhouse/AGENT_FEEDBACK.md` if present.
3. Repo `.milhouse/TEAM_WORKFLOW.md` if present.
4. MCP feedback tools if configured.

## Rules

- Treat feedback as operational evidence, not background noise.
- Keep application repo writes limited to assigned product work and configured `.milhouse/` feedback files.
- Do not expose raw prompts, private telemetry, credentials, or user data.
- Link corrective action to PRs, commits, tests, docs, or runbook updates.
- Do not mark a feedback item done until the verification signal has improved.

## Typical Workflow

1. Read current feedback.
2. Identify relevant open or regressed items.
3. Check recent events, run status, and incidents through MCP when available.
4. Make the product or workflow change.
5. Validate with tests and, when possible, production/workflow signals.
6. Update feedback status with the PR, commit, and validation evidence.

## `/doh`

When the operator marks `/doh`, trigger or request a postmortem. Assume the operator, prompt, requirements, agent plan, implementation, validation, docs, and workflow are all in scope.

## References

- `references/feedback-workflow.md`
