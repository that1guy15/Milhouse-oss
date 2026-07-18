# Milhouse OSS Project Plan

This plan turns the private Milhouse implementation into a reusable public project.

## Phase OSS-0: Safety Freeze

Goal: prevent accidental data exposure.

Tasks:

- Inventory private implementation files.
- Identify reusable modules.
- Exclude generated telemetry, logs, state, private docs, private config, and raw agent sessions.
- Add `.gitignore`, `SECURITY.md`, and publication checklist.
- Run local secret scans.

Done when the intended public export has no generated data or private identifiers.

## Phase OSS-1: Generic Core

Goal: make the implementation reusable.

Tasks:

- Copy sanitized reusable source into `src/milhouse`.
- Rename app-specific modules to generic service/admin/workflow collectors.
- Keep site canary, Cloudflare, dev events, agent logs, feedback, MCP, reports, redaction, replay, and ClickHouse exporters.
- Replace all hardcoded app names, domains, account IDs, local paths, and launchd labels.
- Add fake fixtures.

Done when tests pass against fake fixtures and no command depends on private project names.

## Phase OSS-2: Setup Experience

Goal: one-command bootstrap.

Tasks:

- Keep `setup.sh` idempotent.
- Add `.env.example`.
- Add `config/example.toml`.
- Add local ClickHouse Docker Compose.
- Add `make test`, `make docs-check`, `make skill-check`, and `make secret-scan`.
- Document private overlays.

Done when a clean clone can install and run local validation without private credentials.

## Phase OSS-3: Agent Experience

Goal: make Milhouse useful to Codex and Claude Code.

Tasks:

- Add `.mcp.example.json`.
- Add `AGENTS.md`, `CODEX.md`, and `CLAUDE.md`.
- Add `skills/milhouse-ops`.
- Add `skills/milhouse-feedback`.
- Add `.milhouse/` feedback directory docs.
- Add `/doh` postmortem docs.

Done when an agent can consume feedback, query status, and create/update postmortem items from documented interfaces.

## Phase OSS-4: Documentation And OpenWiki

Goal: support humans and agents equally well.

Tasks:

- Maintain concise human docs in `docs/`.
- Generate or document OpenWiki output in `openwiki/`.
- Add docs CI.
- Add public examples.
- Keep instruction files short and link to deeper docs.

Done when README, docs, skills, and generated wiki agree on setup and architecture.

## Phase OSS-5: Public Launch

Goal: make the repository public safely.

Tasks:

- Confirm license.
- Add contribution and conduct docs.
- Add issue and PR templates.
- Add CI and secret scanning.
- Run secret scan over current tree and git history.
- Create initial clean commit.
- Push to private GitHub repo first.
- Enable GitHub secret scanning.
- Make public only after final review.

Done when a new user can follow the README and run the quickstart without private context.

## Priority Decisions

- Confirm Apache-2.0 vs MIT. This starter uses Apache-2.0.
- Confirm public name and repository spelling.
- Decide default retention for agent traces.
- Decide whether raw transcripts are ever stored.
- Decide provider plugin boundary for Cloudflare, GitHub, LangSmith, Telegram, and future systems.
- Decide whether OpenWiki is committed, generated in CI, or published separately.
- Decide whether hosted ClickHouse is a documented advanced option in v0.1.
