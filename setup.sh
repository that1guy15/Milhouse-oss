#!/usr/bin/env -S -u BASH_ENV -u ENV -u SHELLOPTS -u BASHOPTS /bin/sh

# The bootstrap interpreter. Defaults to the first python3 on PATH; set MILHOUSE_PYTHON to an
# absolute path to override it -- the same escape hatch MILHOUSE_UV provides for the pinned uv.
# Without this, whichever python3 happens to be first on PATH is the only interpreter setup can
# ever use, so one broken or too-old default (a Homebrew Python whose platform.mac_ver() is empty,
# or a system 3.9) makes setup unrunnable with no supported way out. The override is validated by
# exactly the same checks as the default: it is a choice of interpreter, never a bypass.
MILHOUSE_BOOTSTRAP_PYTHON="${MILHOUSE_PYTHON:-python3}"

if [ -n "${MILHOUSE_PYTHON:-}" ] && [ ! -x "${MILHOUSE_PYTHON}" ]; then
  printf '%s\n' \
    "setup: MILHOUSE_PYTHON is set but is not an executable file: ${MILHOUSE_PYTHON}" >&2
  exit 1
fi

if ! MILHOUSE_PYTHON="$(/usr/bin/env "$MILHOUSE_BOOTSTRAP_PYTHON" -I -c '
import os
import sys
from pathlib import Path

if any(name.startswith("BASH_FUNC_") for name in os.environ):
    raise SystemExit("setup: exported shell functions are prohibited")
if not (3, 11) <= sys.version_info[:2] < (3, 15):
    raise SystemExit(
        f"setup: Python 3.11-3.14 is required, but {sys.executable} is "
        f"{sys.version_info[0]}.{sys.version_info[1]}; "
        "set MILHOUSE_PYTHON to a supported interpreter"
    )
try:
    interpreter = Path(sys.executable).resolve(strict=True)
except OSError:
    raise SystemExit("setup: the bootstrap interpreter could not be resolved") from None
print(interpreter)
')"; then
  exit 1
fi

set -eu
umask 077

MILHOUSE_REPO_ROOT="$("$MILHOUSE_PYTHON" -I -c '
import sys
from pathlib import Path

try:
    script = Path(sys.argv[1]).resolve(strict=True)
except OSError:
    raise SystemExit("setup: the repository root could not be resolved") from None
print(script.parent)
' "$0")"

"$MILHOUSE_PYTHON" -I "$MILHOUSE_REPO_ROOT/scripts/prepare_environment.py" \
  --quiet --trusted-python "$MILHOUSE_PYTHON" "$MILHOUSE_REPO_ROOT/.venv"

printf '%s\n' "Synchronizing the hash-locked Milhouse contributor environment..."
"$MILHOUSE_PYTHON" -I "$MILHOUSE_REPO_ROOT/scripts/run_uv.py" \
  sync --locked --all-groups --all-extras --exact \
  --link-mode copy --python "$MILHOUSE_PYTHON"
"$MILHOUSE_PYTHON" -I "$MILHOUSE_REPO_ROOT/scripts/prepare_environment.py" \
  --quiet --trusted-sync-result --trusted-python "$MILHOUSE_PYTHON" \
  "$MILHOUSE_REPO_ROOT/.venv"

printf '%s\n' \
  "Contributor environment ready. Run './scripts/run_make.py quality' and './scripts/run_make.py test-coverage'."
printf '%s\n' \
  "Then initialize local state with 'milhouse init' and try it with 'milhouse demo'."
