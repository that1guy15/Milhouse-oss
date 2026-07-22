# GitHub Repository Controls

Repository settings are external state and require owner authorization. This page records the required end state; it does not claim that a setting is currently enabled. Evidence belongs in `docs/implementation-status.md`.

Repository: `that1guy15/Milhouse-oss`
Default branch: `main`

## Required controls

- Issues, pull requests, and private vulnerability reporting enabled.
- Discussions enabled with a maintainer-authored `Announcements` build journal; every template warns
  against real telemetry, credentials, private identifiers, and raw agent content.
- Secret scanning and push protection enabled.
- Dependabot alerts/updates, dependency review, and CodeQL enabled by W17.
- Actions permitted only from the checked-in `.github/workflows/` definitions.
- Default workflow token permissions read-only; per-job elevation only.
- Protected release environment with required owner approval and PyPI Trusted Publishing.

## Branch protection

`main` must require:

- pull request before merge;
- aggregate `required-ci` plus all release-plan security/integration dependencies;
- resolved conversations and stale-review dismissal where reviews exist;
- DCO sign-off check;
- no force push or branch deletion.

Solo-maintainer mode uses zero required approvals, `require_code_owner_reviews = false`, and `require_last_push_approval = false`, while retaining mandatory pull requests, strict status checks, and admin enforcement. This avoids an impossible self-review gate without permitting unchecked direct merges. Contributor pull requests still receive owner review by project policy. Required human/CODEOWNER approval is enabled when another trusted maintainer is appointed.

The review path must be tested with a non-production pull request. W00 uses its implementation branch as that test.

## Workflow source

`.github/workflows/` is the only workflow source. Stale copies under `ops/github/workflows/` were removed in W00. W01/W17 replace the starter workflows with least-privilege, full-SHA-pinned CI and release workflows.

## Private reporting evidence

After owner authorization, enable GitHub Private Vulnerability Reporting and create a draft synthetic report without submitting real sensitive data. Record the setting URL, date, actor, and draft result in implementation status. Until then, G00 remains externally pending.
