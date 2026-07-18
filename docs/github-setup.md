# GitHub Setup

The intended GitHub repository is:

```text
https://github.com/that1guy15/Millhouse.git
```

## Current Private-First Setup

Create the repo as private first, push the starter tree, enable GitHub security features, then make public after review.

Recommended settings:

- Issues enabled.
- Pull requests enabled.
- Wiki optional.
- GitHub Actions enabled after workflow files are activated.
- Secret scanning enabled.
- Default branch: `main`.

## Activating GitHub Actions

The workflow templates live in:

```text
ops/github/workflows/
```

To activate them, copy them into:

```text
.github/workflows/
```

The GitHub token used for that commit needs the `workflow` scope. With GitHub CLI:

```bash
gh auth refresh -h github.com -s workflow
mkdir -p .github/workflows
cp ops/github/workflows/*.yml .github/workflows/
git add .github/workflows
git commit -m "ci: activate GitHub workflows"
git push
```

## Repository Metadata

Suggested description:

```text
Local-first observability and feedback loops for AI-assisted engineering teams
```

Suggested topics:

```text
observability, ai-agents, clickhouse, mcp, devtools, operations, feedback-loop
```
