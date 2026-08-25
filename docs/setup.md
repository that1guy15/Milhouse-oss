# Contributor setup

This page describes the pre-alpha source-checkout environment used to build and test Milhouse: it
gets the hash-locked contributor toolchain working. It is not an end-user installation guide.

Once setup succeeds, `milhouse config validate`, `milhouse init`, `milhouse health`, and
`milhouse demo` all work from the checkout against a local, spool-only state root — no Docker,
ClickHouse, or credentials required. [Quickstart](quickstart.md) covers that path.

## Prerequisites

- a public Milhouse OSS checkout;
- Python 3.11, 3.12, 3.13, or 3.14;
- exactly uv 0.11.29;
- a POSIX shell and `make`.

Docker, ClickHouse, provider credentials, and production data are not needed for W01. Normal tests
must remain offline and use only tracked synthetic fixtures or runtime-generated adversarial values.

### Installing exactly uv 0.11.29

The pin is exact: the wrapper rejects a missing uv executable or any other version, and CI installs
the same one. A package manager will generally give you the wrong version — `brew install uv`
tracks latest — so install the pinned version directly:

```bash
# Astral's installer, pinned to the exact version (installs into ~/.local/bin):
curl -LsSf https://astral.sh/uv/0.11.29/install.sh | sh

# or, into an isolated tool environment:
pipx install uv==0.11.29
```

Confirm the wrapper agrees before going further:

```bash
python3 -I scripts/run_uv.py
```

It prints `uv 0.11.29 ready` only after checking the executable and its version. Any other version
is refused, and the message names the executable it resolved — which is the part you need when the
resolved one is not the one you expected.

### When the wrong uv is found first

The wrapper resolves uv the way Python does, not the way your shell does. A version manager whose
`python3` is a **shim** — pyenv and conda both do this — prepends its own `bin` directory to `PATH`
*inside* the interpreter. If that directory holds a different uv, it wins, even though `which uv`
in your shell shows the correct one:

```console
$ uv --version
uv 0.11.29 (901092ee1 2026-07-15 aarch64-apple-darwin)     # what your shell sees

$ ./scripts/run_make.py test
run_uv: expected uv 0.11.29; ~/.pyenv/versions/3.12.8/bin/uv reported another version. Install
that exact version or set MILHOUSE_UV to the absolute path of the correct one
```

Set `MILHOUSE_UV` to the absolute path of the correct executable — export it from your shell profile
on a machine where this applies, so every target uses it:

```bash
export MILHOUSE_UV="$HOME/.local/bin/uv"
```

This matters beyond convenience: running the suite under an unpinned uv produces numbers that do
not count as evidence. Defect **D07** in [implementation status](implementation-status.md) records a
review whose results were discounted for exactly this reason (host `uv 0.7.10` against the locked
`0.11.29`).

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

### Choosing the bootstrap interpreter

By default the bootstrap uses the first `python3` on `PATH`. Set `MILHOUSE_PYTHON` to an absolute
path to choose a different one — the same escape hatch `MILHOUSE_UV` provides for uv:

```bash
MILHOUSE_PYTHON=/opt/homebrew/opt/python@3.12/bin/python3 ./setup.sh
```

Use it when the default `python3` is below the 3.11 floor, or is installed but broken. A Homebrew
Python whose `platform.mac_ver()` returns empty values is the common case; uv refuses it with
`Broken Python installation`, and without the override there is no way past it.

The override selects an interpreter; it does not bypass any check. The chosen interpreter is still
required to be a resolvable executable in the supported 3.11–3.14 range, and is rejected with a
message naming it and its version if it is not.

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
any implementation gate passed.

## Next steps

- [Quickstart](quickstart.md) initializes a local state root and runs the spool-only path.
- [Development workflow](development.md) explains every supported Make target and test suite.
- [Dependency policy](dependencies.md) explains dependency groups, locking, licensing, and review.
- [Contributing](../CONTRIBUTING.md) covers DCO sign-off and pull-request requirements.
