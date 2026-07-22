# Dependency policy and inventory

Milhouse keeps its dependency surface explicit because package reproducibility, offline operation,
license compatibility, and supply-chain review are product requirements. The normative policy is
[implementation-plan section 3.3](implementation-plan.md#33-technology-and-dependency-policy), and
the accepted packaging decision is [ADR 0013](adr/0013-packaging-versioning-and-release.md).

This page describes direct dependencies declared in `pyproject.toml`. `uv.lock` is the exact,
hash-bearing CI/development resolution for those declarations and their transitive graph. Including
a planned library in the package foundation does not mean its owning product feature is implemented.

## Selection rules

A dependency must materially reduce implementation or compatibility risk and have:

- an active upstream or a small, stable, auditable surface;
- a bounded compatible range rather than an unbounded latest version;
- an acceptable source license and a reviewable transitive license inventory;
- no requirement for hosted Milhouse services, production credentials, or call-home telemetry;
- a clear owning module and removal path;
- lock, vulnerability, license, package-content, and installed-artifact coverage.

The Python standard library remains the default for asyncio, SQLite, TOML reads, hashing/HMAC, JSON,
filesystem operations, signals, and scheduling. Adding a broker, scheduler framework, hosted LLM
SDK, remote analytics client, or second database would change the planned architecture and requires
more than a routine dependency update.

## Runtime dependencies

| Declaration | Purpose and owner | Maintenance and license rationale |
|---|---|---|
| `click>=8.1,<9` | W01 modular CLI and the later command tree. | Mature bounded major; BSD-3-Clause upstream license is compatible with Apache-2.0 distribution. |
| `clickhouse-connect>=0.8,<1` | W04 authenticated ClickHouse client/export/query layer. | Official ClickHouse Python client line and Apache-2.0 upstream license; the range stops before a potentially breaking 1.x line. |
| `filelock>=3.15,<4` | W03 supported cross-process file locks where SQLite leases are insufficient. | Focused, widely used API with a permissive upstream license; the implementation still owns durability and reconciliation semantics. |
| `httpx>=0.27,<1` | W05 bounded asynchronous HTTP and later provider clients. | Maintained async/sync client with BSD-3-Clause upstream license; Milhouse wraps it with its own timeout, TLS, redirect, retry, size, and SSRF policy. |
| `mcp>=1.27,<2` | W10 local stdio MCP implementation and conformance. | Official Python SDK and MIT upstream license; `<2` is a locked compatibility contract because stable SDK v2 was not available when plan 1.0 was fixed. |
| `packaging>=24,<27` | W02 installed-plugin PEP 440 version-syntax validation. | PyPA's focused Apache-2.0/BSD-2-Clause library avoids a home-grown version grammar; Milhouse preserves each raw version string and still requires exact configured-to-installed equality. |
| `platformdirs>=4,<5` | W02/W06 deterministic platform config and state roots. | Small cross-platform abstraction with MIT upstream license; avoids CWD- or private-path-dependent defaults. |
| `pydantic>=2.12,<3` | W02 strict config/domain models and JSON Schema. | Maintained typed validation ecosystem with MIT upstream license; bounded to the reviewed v2 validator API used by the value-safe domain boundary. |
| `python-dotenv>=1,<2` | W02 loading only explicitly selected environment files. | Small BSD-3-Clause upstream package; Milhouse disables implicit `.env` discovery and never serializes secret values. |

Runtime ranges are deliberately compatible ranges, not exact pins. CI and contributor environments
resolve them through the hash-bearing lock; release candidates test the exact promoted resolution.
Dependabot may propose updates, but no automated update may bypass tests or compatibility review.

## Optional receiver extra

The `receiver` extra records the dependencies and compatibility range owned directly by Milhouse's
W07 receiver. It is a feature boundary, not currently a transitive-installation boundary: the
official MCP SDK also depends on Starlette and Uvicorn, so a base W01 environment can contain both
distributions before the receiver feature is implemented or enabled.

| Declaration | Purpose and boundary |
|---|---|
| `starlette>=1.3.1,<2` | W07 optional receiver application and request lifecycle; BSD-3-Clause upstream license. The lower bound contains the 2026 request URL and form-limit security corrections required by the locked audit. |
| `uvicorn[standard]>=0.30,<1` | W07 optional foreground ASGI serving; BSD-3-Clause upstream license. It does not install or start a service automatically. |

The receiver is not implemented by W01 and remains disabled, loopback-only by default, and
separate from `milhouse run` when W07 delivers it. Contributors install all extras so package and
dependency conflicts are caught early.

Artifact validation keeps the base and receiver installation checks separate. For both the wheel
and the wheel built from the sdist, it first synchronizes the exact hash-locked receiver closure
without the project or development group, then installs that artifact's `receiver` extra from a
local file URI without changing the locked dependencies and runs `pip check`. The same flow supports
offline execution; it validates packaging and dependency compatibility, not the future W07 receiver
feature.

## Development dependencies

Development tools never become required imports for a base Milhouse runtime.

| Area | Direct tools | Reason retained |
|---|---|---|
| Build and artifact checks | `build`, `setuptools`, `wheel`, `check-wheel-contents`, `twine` | Standards-based wheel/sdist builds from the same locked backend used by `pyproject.toml`, strict metadata validation, explicit source/wheel/sdist inventories, byte-parity checks, and installed-artifact checks. The runtime `packaging` dependency is also reused by artifact checks. |
| Tests and coverage | `pytest`, `pytest-asyncio`, `pytest-cov`, `coverage`, `hypothesis`, `respx` | Offline test topology, async behavior, separate line/branch evidence, property invariants, and bounded HTTP simulation. |
| Static quality | `ruff`, `mypy`, `types-pyyaml` | One formatter/linter, strict typing, and checked YAML-tool annotations with a small tool surface. |
| Repository and docs validation | `pyyaml`, `validate-pyproject`, `mkdocs-material` | Strict structured-file/project metadata parsing and the later canonical W17 documentation build. |
| Supply chain | `pip-audit`, `pip-licenses`, `cyclonedx-bom`, `zizmor` | Locked dependency audit, license inventory, SBOM preparation, and workflow security analysis. |

The locked build backend uses setuptools 83.x. Version 83.0.0 is the first release containing the
Unicode-normalization correction for the `MANIFEST.in` exclusion bypass described by
[GHSA-h35f-9h28-mq5c](https://github.com/pypa/setuptools/security/advisories/GHSA-h35f-9h28-mq5c).
This lower bound matters directly to Milhouse because release validation builds an sdist on macOS.

Most selected tools use permissive MIT, BSD, or Apache licenses. Hypothesis and
`validate-pyproject` use MPL-2.0 and remain development-only, unmodified external tools; their
presence does not add their source to Milhouse artifacts. This is an engineering inventory, not
legal advice. `./scripts/run_make.py license-check` evaluates the actual locked graph, and G17
requires a reviewed license inventory for the exact release artifacts.

## License policy and cross-platform evidence

The canonical `./scripts/run_make.py license-check` command generates the installed inventory with
`pip-licenses --from=all --format=json --with-system` and passes it to the fail-closed checker in
`scripts/check_licenses.py`. `--with-system` is required: build and inventory packages such as pip,
setuptools, wheel, pip-licenses, PrettyTable, and wcwidth are part of the development closure and
cannot disappear from review merely because pip-licenses hides them by default. The checker requires
the inventory to equal the current host's marker-evaluated root, receiver, and development closure;
deleting any ordinary row or adding an ambient package fails the check.

The same check evaluates dependency markers separately for every CPython 3.11-3.14 combination on
Darwin x86-64/arm64 and Linux x86-64/aarch64, then reviews the union. A package present on another
supported combination but absent on the current host must have a structured record in
`config/license-policy.toml`. Each such record names one wheel URL and SHA-256 from `uv.lock`, the
exact `.dist-info/METADATA` path inspected after hash verification, and all three metadata values
used by pip-licenses. This keeps CI network-free without turning a current-host inventory into a
false claim about the complete support matrix. The current conditional records are
`backports-tarfile`, `importlib-metadata`, `jeepney`, `secretstorage`, and `zipp`.

Windows is not a supported Milhouse 1.0 platform. Marker traversal therefore excludes the current
Windows-only `pywin32` and `pywin32-ctypes` lock members, verifies that each excluded member is
actually reachable on the Windows matrix, and rejects unsupported-only members that are not
Windows-specific.

All non-unknown values in `License-Expression`, `License-Metadata`, and `License-Classifier` must
match the reviewed allowlist. Unknown-only packages and unrecognized values fail. GPL, AGPL, and
LGPL markers in any of the three sources also fail except for these two exact, development-only
records and dependency paths:

- `chardet==5.2.0`: `milhouse-observability -> cyclonedx-bom -> chardet`;
- `docutils==0.23`: `milhouse-observability -> twine -> readme-renderer -> docutils`.

Dependency-review v5 ignores versions when matching PURLs, so its CI license exceptions are the
unversioned `pkg:pypi/chardet` and `pkg:pypi/docutils`. Those broad action-level matches are accepted
only when paired with the canonical `license-check` target, which enforces the exact versions and
development-only paths above. Neither mechanism exempts either package, or any other dependency,
from vulnerability checks.

The checker proves that neither exception is reachable from the root runtime or receiver closure.
Any version, metadata, path, alternate-path, or runtime-reachability drift invalidates the exception.
Changing a dependency marker, supported platform, wheel hash, or license value therefore requires a
fresh exact artifact inspection and policy review; the checker never fetches metadata from the
network during validation.

Gitleaks is an external repository scanner rather than a Python dependency. The W01 wrapper pins
gitleaks 8.30.1 and verifies an allowlisted platform archive SHA-256 before execution. A missing,
wrong-version, or checksum-mismatched scanner fails the check; it never falls back to a grep-only
success path. GitHub Actions are similarly pinned by full 40-character commit SHA rather than a
mutable tag.

## Lock and update procedure

The only supported resolver is exactly uv 0.11.29:

```bash
python3 -I scripts/run_uv.py
```

Changing the resolver itself is a toolchain migration: update the exact version in
`scripts/run_uv.py`, the accepted range in `pyproject.toml`, CI configuration, the lock, and this
documentation in one reviewed change. Re-run clean-bootstrap and artifact evidence; do not let a
mutable installer or ambient uv choose the version.

For an intentional direct dependency change:

1. document the owner, need, alternatives, maintenance state, license, security impact, and removal
   path in the pull request;
2. edit only the direct declaration in `pyproject.toml`;
3. run `./scripts/run_make.py lock`, then inspect the complete `uv.lock` diff;
4. run `./scripts/run_make.py lock-check`, `./scripts/run_make.py quality`,
   `./scripts/run_make.py test-coverage`, `./scripts/run_make.py audit`, and
   `./scripts/run_make.py license-check`;
5. run `./scripts/run_make.py build`, `./scripts/run_make.py package-check`, and
   `./scripts/run_make.py artifact-smoke` to prove base and optional installation behavior;
6. update this page when purpose, boundary, range, extra, or license posture changes.

Never hand-edit `uv.lock`, silently widen a runtime major, suppress an audit finding without a
documented exact advisory disposition, or copy dependency source into the repository. Release
artifacts, SBOMs, and license inventories remain W17/W18 work and require their own evidence.
