# Contributing to Milhouse

Milhouse handles operational evidence and agent-workflow summaries. Correctness, privacy, durability, and reproducibility take priority over feature speed.

## Current project state

Milhouse is pre-alpha and is being built through the gates in `docs/implementation-plan.md`. Before implementing a change, identify its owning work package and preserve every locked public, storage, privacy, and migration contract.

## Development setup

The active W01 candidate uses Python 3.11-3.14, exactly uv 0.11.29, and the checked-in
`uv.lock`. Install the exact uv version through its supported installer or package manager, then
bootstrap the repository:

```bash
./setup.sh
./scripts/run_make.py quality
./scripts/run_make.py test-coverage
```

`setup.sh` is contributor-only. It verifies the uv executable and synchronizes all locked
development groups and extras; it does not initialize Milhouse, create local product state, start
ClickHouse, install a service, or call a provider. Product initialization belongs to W06. Use the
canonical script rather than reconstructing its safety checks as a manual sync command.

See [Contributor setup](docs/setup.md), [Development workflow](docs/development.md), and
[Dependency policy](docs/dependencies.md) before changing the toolchain or lock.

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
- Change dependency declarations in `pyproject.toml`, regenerate `uv.lock` with
  `./scripts/run_make.py lock`, and review both files together. Never hand-edit the lock.

## Developer Certificate of Origin

Milhouse uses the [Developer Certificate of Origin 1.1](https://developercertificate.org/), not a CLA. Every commit must include a `Signed-off-by` trailer certifying that the contributor has the right to submit it:

```bash
git commit -s -m "feat(component): describe the change"
```

The sign-off name and email must identify the contributor. Pull requests containing unsigned commits cannot merge until the commits are corrected.

## Pull requests

Pull requests target `main` and require:

- passing aggregate `required-ci` and all protected security/integration checks applicable to the
  active work package;
- resolved review threads;
- no P0/P1 defect or privacy/provenance uncertainty;
- plan/status/documentation updates when applicable.

While the project has one GitHub maintainer, owner-authored work uses a pull request with mandatory protected checks, recorded Codex/sub-agent review evidence, and zero impossible self-approvals. The sole maintainer may merge that pull request after all required checks pass. Pull requests from other contributors still require maintainer review as project policy. When a second trusted maintainer is appointed, required human/CODEOWNER approval will be enabled without changing the source contracts.

## Before opening a pull request

- [ ] `./scripts/run_make.py quality`, `./scripts/run_make.py test-coverage`,
  `./scripts/run_make.py docs-check`, `./scripts/run_make.py skill-check`, and
  `./scripts/run_make.py secret-scan` pass.
- [ ] `./scripts/run_make.py lock-check` passes, and any intentional dependency change includes a
  reviewed lock diff.
- [ ] `./scripts/run_make.py package-check` and `./scripts/run_make.py artifact-smoke` pass when
  package code, metadata, resources, or dependencies changed.
- [ ] New collectors have synthetic success, error, rate-limit, drift, and redaction fixtures.
- [ ] Public commands/config/schema changes match the implementation plan.
- [ ] No private identifiers, real telemetry, credentials, or generated state are present.
- [ ] Reused donor behavior is listed in `docs/provenance.md`.
- [ ] Commits contain DCO sign-off.

## Security and privacy reports

Do not place vulnerability details, leaked values, or private telemetry in a public issue. Follow [SECURITY.md](SECURITY.md).
