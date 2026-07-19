# Contributor setup

This page describes the pre-alpha source-checkout environment used to build and test Milhouse. It
is not an end-user installation or product-initialization guide. `milhouse init`, user
configuration, local state, and the deterministic demo are W06 deliverables and are not available
from the W01 foundation.

## Prerequisites

- a public Milhouse OSS checkout;
- Python 3.11, 3.12, 3.13, or 3.14;
- exactly uv 0.11.29;
- a POSIX shell and `make`.

Docker, ClickHouse, provider credentials, and production data are not needed for W01. Normal tests
must remain offline and use only tracked synthetic fixtures or runtime-generated adversarial values.

The repository wrapper rejects a missing uv executable or any uv version other than 0.11.29. If
the exact executable is not on `PATH`, set `MILHOUSE_UV` to its absolute path:

```bash
MILHOUSE_UV=/absolute/path/to/uv python3 -I scripts/run_uv.py
```

The command prints `uv 0.11.29 ready` only after checking the executable and version.

## Bootstrap the locked environment

From the repository root, run:

```bash
./setup.sh
```

Invoke the bootstrap exactly as `./setup.sh`. Do not run `sh setup.sh`, `bash setup.sh`, or another
explicit interpreter; that bypasses the environment-sanitizing shebang and is unsupported.

The script's sanitized shebang discards inherited shell startup and option controls before any
recipe can run. Its first child process is absolute `/usr/bin/env`, which starts isolated Python,
rejects any remaining exported shell-function controls, validates Python 3.11-3.14, and resolves
the trusted interpreter once. Setup then delegates to this locked copy-mode operation:

```bash
MILHOUSE_PYTHON="$(/usr/bin/env python3 -I -c \
  'from pathlib import Path; import sys; print(Path(sys.executable).resolve(strict=True))')"
"$MILHOUSE_PYTHON" -I scripts/run_uv.py sync \
  --locked --all-groups --all-extras --exact \
  --link-mode copy --python "$MILHOUSE_PYTHON"
```

It creates or updates the project `.venv` from `uv.lock`, including the development dependency
group and optional receiver extra used by the complete test matrix. The lock includes hashes for the
resolved environment. Setup uses a restrictive process umask and copy mode so environment files are
not linked to the uv cache. It rejects a symlinked root, foreign-owned or multiply linked files,
special entries, previously group/world-writable state, and every internal symbolic link except
verified virtual-environment interpreter links and Linux's in-root `lib64 -> lib` link. Nested
filesystem mount boundaries are also prohibited. It then restricts the private directory boundary
and safe owned entries. A stale or inconsistent lock is an error; setup does not silently rewrite
it. If setup rejects an older multiply linked `.venv`, remove that disposable environment and
rerun `./setup.sh`; no product state is stored there.

The contributor bootstrap does **not**:

- copy or create `.env` files or Milhouse configuration;
- create spool, database, log, report, backup, or other product state;
- start Docker or ClickHouse;
- install or start launchd or systemd services;
- call a provider or external model;
- write to an application repository.

## Verify the checkout

Run the environment-bound targets:

```bash
./scripts/run_make.py quality
./scripts/run_make.py test-coverage
./scripts/run_make.py docs-check
./scripts/run_make.py skill-check
./scripts/run_make.py secret-scan
```

For packaging-sensitive changes, also run:

```bash
./scripts/run_make.py build
./scripts/run_make.py package-check
./scripts/run_make.py artifact-smoke
```

The active gate and exact required evidence remain in
[implementation status](implementation-status.md). Passing local commands does not by itself mark
G01 passed.

## Next steps

- [Development workflow](development.md) explains every supported Make target and test suite.
- [Dependency policy](dependencies.md) explains dependency groups, locking, licensing, and review.
- [Contributing](../CONTRIBUTING.md) covers DCO sign-off and pull-request requirements.
