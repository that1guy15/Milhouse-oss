---
name: milhouse-oss-maintainer
description: Prepare, sanitize, document, and validate Milhouse for open source publication. Use when creating the public repo, copying reusable code from a private implementation, configuring GitHub, writing setup docs, choosing release files, checking secrets, or reviewing whether a Milhouse tree is safe to publish.
---

# Milhouse OSS Maintainer

## Start

Read:

- `docs/oss-public-repo-plan.md`
- `docs/project-plan.md`
- `docs/publication-checklist.md`
- `SECURITY.md`

## Publication Rules

- Never make a private operational repo public directly.
- Copy only sanitized reusable code and docs into the public repo.
- Keep examples fake and provider-neutral unless explicitly marked as optional provider examples.
- Remove generated telemetry, local state, logs, raw traces, private incidents, local paths, tokens, account IDs, and private app names.
- Configure remotes without pushing until the owner approves.
- Prefer a private GitHub repo first, then make public after secret scanning and review.

## Build Workflow

1. Create or inspect the clean OSS repo.
2. Add license, README, contribution docs, security docs, setup, example config, agent docs, skills, and CI.
3. Copy reusable implementation only after sanitization.
4. Rename private/app-specific modules to generic provider or service names.
5. Run tests, docs checks, skill checks, and secret scans.
6. Review `git status --short`.
7. Commit only the safe public tree.
8. Push only after explicit owner approval.

## Validation

Run:

```bash
make test
make docs-check
make skill-check
make secret-scan
```

Also scan manually for:

```bash
grep -RIn "TOKEN\\|SECRET\\|PASSWORD\\|account_id\\|rum_site_tag\\|/Users" .
```

## References

- `references/release-safety.md`
