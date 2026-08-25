"""Shared, bounded SQL-identifier validation for the storage layer.

Every database and table name the runner, exporter, and repository interpolate into a statement
must be a bounded ``[A-Za-z_][A-Za-z0-9_]{0,127}`` identifier. Values themselves are never
interpolated (inserts bind native column data; reads bind ``{name:Type}`` parameters), but the
object *names* are structural and cannot be parameter-bound, so they are validated fail-closed here
against one regex rather than re-derived per caller.
"""

from __future__ import annotations

import re

from milhouse.storage.errors import StorageError

_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}", flags=re.ASCII)


def require_identifier(value: object, *, code: str, message: str) -> str:
    """Return ``value`` if it is a bounded SQL identifier, else raise ``StorageError``."""

    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        raise StorageError(code, message)
    return value


__all__ = ["require_identifier"]
