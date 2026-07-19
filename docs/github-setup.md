# GitHub Repository Controls

Repository settings are external state and require owner authorization. This page records the required end state; it does not claim that a setting is currently enabled. Evidence belongs in `docs/implementation-status.md`.

Repository: `that1guy15/Milhouse-oss`
Default branch: `main`

## Required controls

- Issues, pull requests, and private vulnerability reporting enabled.
- Discussions optional; every template warns against real telemetry or credentials.
- Secret scanning and push protection enabled.
- Dependabot alerts/updates, dependency review, and CodeQL enabled by W17.
- Actions permitted only from the checked-in `.github/workflows/` definitions.
- Default workflow token permissions read-only; per-job elevation only.
- Protected release environment with required owner approval and PyPI Trusted Publishing.

## Branch protection

`main` must require:

- pull request before merge;
- aggregate `required-ci` plus all release-plan security/integration dependencies;
- resolved conversations and dismissal of stale approval;
- eligible CODEOWNER approval for non-owner changes;
- a recorded independent reviewer for owner-authored changes until a second CODEOWNER is appointed;
- DCO sign-off check;
- no force push or branch deletion.

The review path must be tested with a non-production pull request. Do not configure an impossible self-review requirement.

## Workflow source

`.github/workflows/` is the only workflow source. Stale copies under `ops/github/workflows/` were removed in W00. W01/W17 replace the starter workflows with least-privilege, full-SHA-pinned CI and release workflows.

## Private reporting evidence

After owner authorization, enable GitHub Private Vulnerability Reporting and create a draft synthetic report without submitting real sensitive data. Record the setting URL, date, actor, and draft result in implementation status. Until then, G00 remains externally pending.
