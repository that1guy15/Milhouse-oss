# ADR 0013: Packaging, versioning, and release

- Status: Accepted (ratification)
- Date: 2026-07-18

## Context

Installed-package behavior, repository behavior, release evidence, and promoted artifacts must not drift.

## Decision

Milhouse is a Python application packaged as distribution `milhouse-observability`, import package `milhouse`, and executable `milhouse`, using setuptools. Runtime migrations, templates, schemas, service files, and other resources live in the package and are accessed with `importlib.resources`; repository copies are generated from those same resources.

Python 3.11-3.14 and the platform/ClickHouse matrix in plan section 2.2 are release contracts. Runtime dependency ranges are bounded by compatible majors, while CI/releases use a hash-locked environment. Installation supports pipx and uv tool; editable clone setup is contributor-only. Docker Compose supplies ClickHouse, not Milhouse itself.

Semantic Versioning governs the distribution. The initial train is exactly `1.0.0a1 -> 1.0.0b1 -> 1.0.0rc1 -> 1.0.0`, incrementing prerelease sequence numbers when needed. Configuration, record, spool, plugin, MCP, SQLite, and ClickHouse schemas retain independent versions and explicit migration/compatibility rules.

A protected workflow builds a universal wheel and sdist once from a signed immutable tag, tests those exact artifacts, and promotes them unchanged. Release outputs include hashes, SBOM, license inventory, and provenance/attestation. PyPI publication uses OIDC Trusted Publishing with no long-lived token. Released files are never overwritten; defects use yank plus patch release.

Engineering completion, release-candidate readiness, and release completion are distinct. G18 prepares qualified RC artifacts and evidence. Tagging, publication, GitHub Release creation, public installation, announcement, and 72-hour monitoring require the separate owner authorization and procedure in plan section 12.3.

## Consequences

Package-content and clean-environment tests are mandatory for wheel and sdist. No command may rely on checkout-only files. CI, support matrices, artifact metadata, quickstarts, and documentation must describe the same versions and resources.

## Plan references

- [Sections 2.2-2.3 and 3.3: compatibility, names, and dependencies](../implementation-plan.md#22-primary-user-and-supported-environments)
- [Section 6: target repository and packaged resources](../implementation-plan.md#6-target-repository-layout)
- [Section 12: release and maintenance contract](../implementation-plan.md#12-release-and-maintenance-contract)
- [W17-W18: supply-chain and 1.0 gates](../implementation-plan.md#w17--documentation-skills-community-ci-and-supply-chain-hardening)
