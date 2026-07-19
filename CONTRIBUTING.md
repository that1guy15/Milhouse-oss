# Contributing to Milhouse

Milhouse handles operational evidence and agent-workflow summaries. Correctness, privacy, durability, and reproducibility take priority over feature speed.

## Current project state

Milhouse is pre-alpha and is being built through the gates in `docs/implementation-plan.md`. Before implementing a change, identify its owning work package and preserve every locked public, storage, privacy, and migration contract.

## Development setup

The supported contributor setup will be finalized in W01. For the current scaffold:

```bash
./setup.sh
make test
make docs-check
make skill-check
make secret-scan
```

Do not use live provider credentials or production data in tests. Use synthetic fixtures and deterministic clocks.

## Contribution rules

- Keep examples generic and fake.
- Never commit credentials, telemetry, JSONL spools, ClickHouse data, generated reports, private incidents, raw prompts/responses/transcripts/tool output, or private paths.
- Keep the private donor repository read-only. Record any intentional algorithm/code adaptation in `docs/provenance.md`.
- Preserve local-first, spool-before-export behavior.
- Keep collectors config-driven and bounded.
- Write only to explicitly configured Milhouse state and application `.milhouse/` directories.
- Add tests and documentation with every behavior or interface change.
- Use a numbered plan amendment before changing a locked contract.

## Developer Certificate of Origin

Milhouse uses the [Developer Certificate of Origin 1.1](https://developercertificate.org/), not a CLA. Every commit must include a `Signed-off-by` trailer certifying that the contributor has the right to submit it:

```bash
git commit -s -m "feat(component): describe the change"
```

The sign-off name and email must identify the contributor. Pull requests containing unsigned commits cannot merge until the commits are corrected.

## Pull requests

Pull requests target `main` and require:

- passing aggregate `required-ci` and all protected security/integration checks once W17 installs them;
- at least one approval from an eligible CODEOWNER who did not author the change;
- resolved review threads;
- no P0/P1 defect or privacy/provenance uncertainty;
- plan/status/documentation updates when applicable.

Until a second maintainer is appointed, owner-authored changes require an explicitly recorded independent reviewer in the pull request rather than self-approval. Repository settings and the effective review path are evidence for G00/G17.

## Before opening a pull request

- [ ] Tests, docs checks, skill checks, and secret scans pass.
- [ ] New collectors have synthetic success, error, rate-limit, drift, and redaction fixtures.
- [ ] Public commands/config/schema changes match the implementation plan.
- [ ] No private identifiers, real telemetry, credentials, or generated state are present.
- [ ] Reused donor behavior is listed in `docs/provenance.md`.
- [ ] Commits contain DCO sign-off.

## Security and privacy reports

Do not place vulnerability details, leaked values, or private telemetry in a public issue. Follow [SECURITY.md](SECURITY.md).
