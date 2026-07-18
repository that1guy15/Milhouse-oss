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
- Discussions enabled.
- Wiki optional and disabled by default because OpenWiki docs live in-repo.
- GitHub Actions enabled after workflow files are activated.
- Secret scanning enabled.
- Default branch: `main`.
- `main` protected with pull request review required.
- CODEOWNERS requires `@that1guy15` review.

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

Once activated, branch protection should require the `test` and `gitleaks` checks to pass before merge.

## Branch Protection

`main` should require:

- pull requests before merge
- at least one approving review
- CODEOWNERS review
- stale review dismissal after new commits
- resolved conversations
- status checks when Actions are active
- no force pushes
- no branch deletion

## Repository Metadata

Suggested description:

```text
Local-first observability and feedback loops for AI-assisted engineering teams
```

Suggested topics:

```text
observability, ai-agents, clickhouse, mcp, devtools, operations, feedback-loop
```
