#!/usr/bin/env -S -u BASH_ENV -u ENV -u SHELLOPTS -u BASHOPTS /bin/sh

if ! MILHOUSE_PYTHON="$(/usr/bin/env python3 -I -c '
import os
import sys
from pathlib import Path

if any(name.startswith("BASH_FUNC_") for name in os.environ):
    raise SystemExit("setup: exported shell functions are prohibited")
if not (3, 11) <= sys.version_info[:2] < (3, 15):
    raise SystemExit("setup: Python 3.11-3.14 is required")
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
printf '%s\n' "Product initialization and local state creation remain gated to W06."
