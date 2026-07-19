# Publication Checklist

Publication is not authorized by a source-build instruction. Use this checklist only after G18 and explicit owner approval. The authoritative requirements are in sections 12-14 of `docs/implementation-plan.md`.

## Source and privacy

- [ ] W00-W18 evidence is complete and `release-candidate-ready`.
- [ ] Git tree and full history contain no credentials, private identifiers, paths, telemetry, state, reports, raw agent content, or unreviewed donor material.
- [ ] Donor provenance is complete and independently reviewed.
- [ ] Config, fixtures, docs, issues, and examples are synthetic and provider-neutral.
- [ ] Privacy/threat-model inventories have no unknown owner, classification, egress, or retention.

## Quality and recovery

- [ ] Aggregate required CI, integration, security, packaging, docs, compatibility, performance, and soak gates pass on the exact release commit.
- [ ] Acknowledged-record crash/replay guarantees and clean-host backup/restore/upgrade/rollback drills pass.
- [ ] No P0/P1 defect is open; every P2 has a recorded disposition.
- [ ] Independent security, provenance, workflow, and package-content review is signed.

## Repository and supply chain

- [ ] Private vulnerability reporting is enabled and test-drafted.
- [ ] Branch protection, CODEOWNERS, DCO, and independent review path are operational.
- [ ] All Actions are pinned to full commit SHAs with least-privilege permissions.
- [ ] Secret scanning/push protection, CodeQL, dependency review, Dependabot, container scan, and license policy are active.
- [ ] Signed immutable tag, protected release environment, and PyPI Trusted Publishing are configured.
- [ ] Wheel/sdist are built once, tested unchanged, inventoried, hashed, and accompanied by SBOM/provenance.

## Authorized publication

- [ ] Owner separately approves protected tag/build and publication.
- [ ] Exact `1.0.0` artifacts publish through Trusted Publishing and GitHub Release.
- [ ] Public PyPI installation, spool-only/full demos, MCP reads, upgrade, backup, and restore pass on clean macOS and Ubuntu.
- [ ] Announcement follows verification, not publication alone.
- [ ] Seventy-two-hour post-publication monitoring completes without an unresolved release blocker.
