# OSS Public Repo Plan

Milhouse OSS should be created as a fresh, sanitized repository instead of publishing a private operational tree directly.

## Goal

Create a public project that anyone can fork or download, configure with their own settings, and use to add observability and feedback loops to AI-assisted development workflows.

## Keep

- local-first collectors
- JSONL spool-before-export
- local ClickHouse store
- redaction
- replay/export
- feedback item lifecycle
- MCP read surface
- repo `.milhouse/` feedback briefs
- `/doh` postmortems
- weekly reports
- fixture-based tests

## Generalize

- application-specific collectors become generic service/admin/workflow collectors
- hardcoded app names become config targets
- personal launchd labels become templates
- provider tokens become env-var references
- private docs become generic runbooks

## Exclude

- generated telemetry
- local logs
- raw agent transcripts
- private incidents
- private configs
- real domains, account IDs, RUM tags, tokens, and local paths
- current private git history unless fully audited and intentionally preserved

## Initial Public Deliverables

- README
- Apache-2.0 license
- contribution guide
- security policy
- code of conduct
- setup script
- example config
- MCP example
- Codex and Claude Code docs
- project skills
- architecture docs
- feedback loop docs
- publication checklist
- CI and secret-scan workflows

## Complete Means

A new user can clone the repo, run `./setup.sh`, edit config, run tests, and understand how to connect Milhouse to their app and agents without seeing any private project context.
