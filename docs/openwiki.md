# OpenWiki

Milhouse should support both human docs and agent-readable generated documentation.

Recommended layers:

1. Human docs in `docs/`.
2. Agent instructions in `AGENTS.md`, `CODEX.md`, `CLAUDE.md`, and `skills/`.
3. Generated wiki material in `openwiki/`.

## OpenWiki Usage

OpenWiki can generate and maintain repo documentation for agents:

- https://github.com/langchain-ai/openwiki
- https://www.langchain.com/blog/introducing-openwiki-an-open-source-agent-for-repo-documentation

Suggested workflow after implementation files exist:

```bash
openwiki --init
openwiki generate
```

Do not include private telemetry, generated reports, raw traces, `.env`, or private overlays in generated docs.

## Alternatives To Evaluate

- MkDocs Material for human docs.
- GitHub Pages for hosted public docs.
- DeepWiki-style generated repo explanations for external readers.
- Custom MCP docs index for agents.

## Docs Rule

Do not make `AGENTS.md`, `CODEX.md`, or `CLAUDE.md` huge. Keep them short and link to deeper docs.
