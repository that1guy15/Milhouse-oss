# ADR 0014: Support, governance, security, and provenance

- Status: Accepted (ratification)
- Date: 2026-07-18

## Context

A public observability product needs an actionable support/security path and auditable origin for code derived from a private donor.

## Decision

The public project uses Apache-2.0, DCO sign-off, no initial CLA, truthful compatibility/support matrices, CODEOWNERS, and branch/review rules that permit a real reviewed merge path. Private GitHub vulnerability reporting is enabled and tested. Public issue templates warn against attaching credentials or real telemetry.

The public audited OSS head is the source baseline. The private repository remains read-only donor/reference material. Private history, telemetry, configuration, generated data, paths, fixtures, and personal/project-specific behavior are never imported. Any adapted donor code is generalized in a fresh public commit, recorded file-by-file in `docs/provenance.md`, independently reviewed, and covered by synthetic OSS tests. Material with uncertain ownership/provenance is quarantined and replaced before its gate passes.

Security severity and release response follow plan sections 10 and 12: credential/data exposure, remote code execution, or uncontrolled external mutation is P0; acknowledged loss, unsafe writes, replay corruption, or broken recovery is P1. P0/P1 findings block release and can trigger service stop, release hold/yank, credential rotation, private advisory, restore, and regression coverage. No P0/P1 may remain open at RC; P2 exceptions require an owner and explicit disposition.

Required CI includes least-privilege full-SHA workflows, no fork secrets or `pull_request_target`, gitleaks history and private-identifier scans, CodeQL, dependency review/audit, license/container/package-content checks, SBOM, and provenance. The aggregate `required-ci` cannot pass when a mandatory dependency is skipped or failed.

Support promises are limited to the recorded platform/version matrix and documented upgrade window. Live providers are labelled supported only after an owner-authorized sandbox smoke with version/date evidence; otherwise they are experimental. External settings, independent review, physical hosts, elapsed soak, push, tag, and publication remain owner/independent-reviewer responsibilities identified by the plan.

## Consequences

Governance and support documentation must name real maintainership, reporting, compatibility, escalation, and lifecycle procedures before release. Publication pauses for unresolved provenance, private-data findings, or required external evidence; source implementation may continue on independent workstreams.

## Plan references

- [Sections 1 and 7: authority and provenance](../implementation-plan.md#1-authority-and-change-control)
- [Sections 9-10: CI, security, and operations](../implementation-plan.md#9-testing-and-validation-contract)
- [Sections 11-13: community, release, and responsibility](../implementation-plan.md#11-documentation-and-community-deliverables)
- [W00 and W17: governance and release hardening](../implementation-plan.md#w00--repository-authority-governance-and-adrs)
