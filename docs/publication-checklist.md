# Publication Checklist

Use this before pushing or making the repository public.

## Local Tree

- [ ] `git status --short` reviewed.
- [ ] `.env` is ignored and untracked.
- [ ] `.mcp.json` is ignored and untracked.
- [ ] `spool/`, `data/`, `logs/`, `reports/generated/`, and `.milhouse/` are ignored and untracked.
- [ ] Config examples use fake domains and env var names.
- [ ] Docs do not include private incidents, private paths, account IDs, RUM tags, tokens, or raw traces.

## Validation

- [ ] `make test`
- [ ] `make docs-check`
- [ ] `make skill-check`
- [ ] `make secret-scan`
- [ ] `gitleaks detect --source .`
- [ ] `trufflehog filesystem .`

## GitHub

- [ ] Remote points to the intended repository.
- [ ] GitHub secret scanning is enabled.
- [ ] Branch protection is configured.
- [ ] GitHub Actions workflows are activated from `ops/github/workflows/` after `workflow` scope is available.
- [ ] CI is passing.
- [ ] Issues and PR templates are present.
- [ ] Repository is private until final review is complete.

## Approval

- [ ] Owner approves public release.
- [ ] Final diff reviewed by a security-focused agent.
- [ ] README quickstart verified from a fresh clone.
