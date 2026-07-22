# Development workflow

Milhouse development is package- and gate-driven. Select one dependency-ready work package from the
[authoritative plan](implementation-plan.md), confirm its state in
[implementation status](implementation-status.md), and use synthetic evidence. The W01 toolchain is
pre-alpha infrastructure; it does not make later product commands available.

## Reproducible environment

The repository requires Python 3.11-3.14 and exactly uv 0.11.29. `scripts/run_uv.py` resolves the
uv executable from `MILHOUSE_UV` or `PATH`, verifies its exact version, and then delegates without
falling back to another package manager. It anchors commands to this checkout and ignores ambient
uv/Python project redirection, user-level uv configuration, and gate-altering pytest, coverage,
typing, property-test, and tool control variables. The Makefile invokes the wrapper with Python
isolated mode and refuses Make modes that can skip recipes or ignore failures. Canonical gate
commands first use `scripts/run_make.py`, which replaces itself with the platform `make` after
removing inherited Make preloads, flags, shell startup controls, and exported shell functions.
Normal command arguments and Make's exit status are preserved.

The canonical bootstrap is:

```bash
./setup.sh
```

Invoke it exactly as `./setup.sh`, not through `sh setup.sh` or `bash setup.sh`. Direct execution is
part of the safety boundary because the sanitized shebang removes inherited shell startup and
option controls before the script body runs. The script then resolves the supported bootstrap
interpreter once and uses this locked copy-mode operation:

```bash
MILHOUSE_PYTHON="$(/usr/bin/env python3 -I -c \
  'from pathlib import Path; import sys; print(Path(sys.executable).resolve(strict=True))')"
"$MILHOUSE_PYTHON" -I scripts/run_uv.py sync \
  --locked --all-groups --all-extras --exact \
  --link-mode copy --python "$MILHOUSE_PYTHON"
```

Run targets from the repository root with `./scripts/run_make.py TARGET`; the Makefile refuses
another working directory before any cleanup or tool command. All supported targets execute tools
through the project environment. An unrelated ambient virtual environment or globally installed
linter must not determine the result. Direct `make TARGET` remains a convenience only when the
parent environment and `PATH` are trusted. Its retained Makefile guard rejects inherited preloads,
but it cannot prevent preload code from running before the Makefile itself is parsed, so direct
invocation is not canonical gate evidence.

Do not hand-edit `uv.lock`. For an intentional dependency change:

```bash
./scripts/run_make.py lock
./scripts/run_make.py lock-check
./scripts/run_make.py quality
./scripts/run_make.py audit
./scripts/run_make.py license-check
```

Review `pyproject.toml` and `uv.lock` together. The lock is reproducibility evidence, not a substitute
for bounded direct dependency ranges or a maintenance/license/security assessment.

## Make target reference

| Canonical command | Purpose |
|---|---|
| `./scripts/run_make.py setup` | Safely synchronize every development group and extra from the existing lock with restrictive environment permissions. |
| `./scripts/run_make.py lock` | Intentionally resolve and rewrite `uv.lock` with exact uv. |
| `./scripts/run_make.py lock-check` | Fail if project metadata and the checked-in lock disagree. |
| `./scripts/run_make.py format` | Apply Ruff formatting to owned Python source and tests. |
| `./scripts/run_make.py format-check` | Check formatting without mutation. |
| `./scripts/run_make.py lint` | Run the configured Ruff lint rules. |
| `./scripts/run_make.py type-check` | Run strict mypy over `src/milhouse` and repository Python tooling. |
| `./scripts/run_make.py test` | Run the complete ordinary offline pytest topology. |
| `./scripts/run_make.py test-coverage` | Run tests with branch data and enforce overall line and branch thresholds. |
| `./scripts/run_make.py identity-portability` | Recompute immutable identity vectors in isolated processes for the required Ubuntu/macOS portability gate. |
| `./scripts/run_make.py repo-check` | Validate setup syntax, project metadata, and checked-in TOML, JSON, YAML, and package-resource policy. |
| `./scripts/run_make.py docs-check` | Validate local Markdown links/anchors and bounded external-link availability. |
| `./scripts/run_make.py workflow-check` | Validate workflow structure and required-CI aggregation invariants. |
| `./scripts/run_make.py skill-check` | Validate the five canonical project skills and discovery aliases. |
| `./scripts/run_make.py quality` | Run the non-mutating W01 formatting, lint, typing, repository, docs, workflow, and skill gates. |
| `./scripts/run_make.py build` | Build one wheel and one sdist from the current source tree. |
| `./scripts/run_make.py package-check` | Validate metadata, manifest, inventories, resources, and both artifact formats. |
| `./scripts/run_make.py artifact-smoke` | Install the exact wheel and sdist in empty environments and exercise package/CLI/resources. |
| `./scripts/run_make.py audit` | Audit the locked Python dependency graph. |
| `./scripts/run_make.py license-check` | Inventory locked dependency licenses and enforce repository policy. |
| `./scripts/run_make.py private-identifier-check` | Scan tracked current-tree text and paths for concrete local machine identifiers without echoing matched values. |
| `./scripts/run_make.py secret-scan` | Run the private-identifier check plus fail-closed current-tree and public-history gitleaks scans. |
| `./scripts/run_make.py secret-scan-self-test` | Prove both gitleaks paths reject a runtime-planted disposable secret. |

The quality, coverage, package, and security targets are complementary. A green formatter or test
run does not waive another required gate.

## Tests and coverage

The repository topology mirrors the plan:

| Directory | W01 responsibility |
|---|---|
| `tests/unit/` | Isolated package, CLI, and validator behavior. |
| `tests/property/` | Hypothesis invariants over bounded synthetic values. |
| `tests/contract/` | Public metadata, resource, and repository contracts. |
| `tests/integration/` | Multi-module source-checkout behavior without live providers. |
| `tests/e2e/` | User-visible module and command paths. |
| `tests/security/` | Adversarial path, package, scanner, and fail-closed behavior. |
| `tests/migration/` | Versioned resource/migration foundation and later schema transitions. |
| `tests/packaging/` | Wheel/sdist metadata, inventory, installation, CLI, and resources. |
| `tests/fixtures/` | Explicitly tracked, parseable, synthetic JSON/JSONL fixtures. |

Normal CI cannot call a live provider or require a production credential. Secret-shaped adversarial
test values are generated only in disposable runtime locations and are never committed, copied into
documentation, or printed. Global pytest configuration deliberately omits local-variable display;
privacy-sensitive tests must also keep runtime canaries out of parameters, assertion operands,
captured output, command arguments, environment variables, and persisted Hypothesis examples.
Repository validation rejects root `pytest.ini`, `.pytest.ini`, `tox.ini`, and `setup.cfg` files so
none can silently replace the reviewed `pyproject.toml` pytest policy.

W01 enforces at least 90% line coverage and 85% branch coverage separately across both the
`milhouse` package and owned Python tooling under `scripts`; tooling is not hidden behind a
product-only denominator. Every current archive, filesystem, network, privacy, scanner-bootstrap,
contribution-provenance, tool-execution, coverage-policy, and protected-CI trust-boundary module is
enumerated in the `test-coverage` target and must independently reach at least 95% branch coverage.
W02 and later work must add each new security-, identity-, spool-, migration-, feedback-, or
path-critical module to that exact inventory when it is introduced.

## Package validation

The distribution name is `milhouse-observability`; the import package and executable are both
`milhouse`. Version output and package metadata derive from one version source. Runtime assets must
be declared explicitly and have byte-identical source, wheel, and sdist copies.

Use:

```bash
./scripts/run_make.py build
./scripts/run_make.py package-check
./scripts/run_make.py artifact-smoke
```

Artifact validation checks that the build directory contains exactly one wheel and one sdist,
rejects generated/private/cache content, runs strict metadata checks, installs each artifact in a
new environment with the checkout removed from import resolution, and exercises `milhouse --help`,
`milhouse --version`, and packaged resources. Release artifacts are not produced or published by
these contributor targets.

## Security checks

Run these before proposing public, packaging, provenance, or privacy-sensitive changes:

```bash
./scripts/run_make.py secret-scan
./scripts/run_make.py secret-scan-self-test
./scripts/run_make.py audit
./scripts/run_make.py license-check
```

The secret scan is fail closed: a missing, wrong-version, checksum-mismatched, or failed scanner is
a failure. The self-test creates its planted values outside tracked fixtures and removes its
disposable workspace. Never add a real credential to prove scanning.

The `license-check` target writes the raw `pip-licenses --from=all --format=json --with-system`
inventory only to ignored `build/license-inventory.json`; CI does not upload it. The checker then
requires an exact current-host dependency closure, evaluates markers across the complete supported
CPython/macOS/Linux matrix, binds conditional evidence to exact wheel hashes in `uv.lock`, excludes
only proven Windows-only lock members, and verifies the two exact development-only license
exceptions documented in [Dependency policy and inventory](dependencies.md#license-policy-and-cross-platform-evidence).
Do not hand-edit or publish the generated inventory, remove `--with-system`, or replace the checker
with pip-licenses' single-field filtering.

CI uses least-privilege permissions and full 40-character action commit SHAs. The aggregate
`required-ci` job evaluates every mandatory dependency with `always()` semantics and succeeds only
when each expected result is exactly `success`; failed, cancelled, skipped, missing, or unknown
results fail the aggregate.

The W01 workflow exercises source compatibility and installation of the same built artifacts on
Python 3.11, 3.12, 3.13, and 3.14 on Ubuntu. A hosted matrix result is still required gate evidence;
documenting the matrix or passing only the local interpreter is not equivalent.

## Documentation and repository data

The `docs-check` target validates local Markdown targets and anchors and applies a bounded external
link check. The `repo-check` target parses repository TOML, JSON, YAML, and package resources
strictly. Dependabot entries must use canonical in-repository directories, resolve to
Milhouse-approved regular manifests, and use the ecosystem matching that manifest (`docker-compose`
for Compose, not `docker`). Automated version updates currently cover GitHub Actions. The exact
Python lock remains enforced by lock and compatibility checks and scanned for known vulnerabilities
by required-CI `pip-audit`; automated Python version updates wait until GitHub's hosted updater can
run the uv version Milhouse requires. Container update tracking returns with its owning package and
matching ecosystem. Keep examples fake and provider-neutral. Do not commit credentials, private
paths, raw telemetry, generated reports, state, agent content, or donor fixtures.

Before handoff, follow [Contributing](../CONTRIBUTING.md), run the checks required by the active
work package, inspect the combined tree, and report any unverified external behavior separately.
Local results alone do not change gate status.
