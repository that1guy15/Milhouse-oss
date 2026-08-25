"""Fixed, value-safe error types for the runtime collector pipeline (W05, plan section 4.8).

Every runtime failure is a stable ``MH_RUNTIME_*`` code carrying only bounded developer text. Like
the spool and storage boundaries, these errors never render a rejected value, a secret, a driver
payload, or a machine-local path, so a runtime failure — including one raised while resolving an
untrusted third-party plugin — is safe to surface, log, or summarize.
"""

from __future__ import annotations

from milhouse.core.errors import MilhouseError


class RegistryError(MilhouseError):
    """A stable collector-registry resolution or plugin-binding failure."""


class PipelineError(MilhouseError):
    """A stable runtime context, result, or pipeline-construction failure."""


__all__ = ["PipelineError", "RegistryError"]
