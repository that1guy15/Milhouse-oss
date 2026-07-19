#!/usr/bin/env -S python3 -I
"""Start the platform Make with inherited preload and shell controls removed."""

from __future__ import annotations

import os
import sys
from collections.abc import Mapping, Sequence

CONTROL_ENVIRONMENT = frozenset(
    {
        "BASHOPTS",
        "BASH_ENV",
        "ENV",
        "GNUMAKEFLAGS",
        "MAKEFILES",
        "MAKEFLAGS",
        "MAKELEVEL",
        "MAKEOVERRIDES",
        "MAKE_RESTARTS",
        "MFLAGS",
        "SHELLOPTS",
    }
)
CONTROL_PREFIXES = ("BASH_FUNC_",)


def _sanitized_environment(source: Mapping[str, str] | None = None) -> dict[str, str]:
    environment = dict(os.environ if source is None else source)
    for key in tuple(environment):
        if key in CONTROL_ENVIRONMENT or key.startswith(CONTROL_PREFIXES):
            environment.pop(key)
    return environment


def main(arguments: Sequence[str] | None = None) -> int:
    """Replace this process with Make, preserving its arguments and result."""

    make_arguments = list(sys.argv[1:] if arguments is None else arguments)
    try:
        os.execvpe("make", ["make", *make_arguments], _sanitized_environment())
    except OSError:
        print("make-launcher: platform make is unavailable", file=sys.stderr)
        return 127


if __name__ == "__main__":
    raise SystemExit(main())
