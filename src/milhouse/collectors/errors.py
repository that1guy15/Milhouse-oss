"""Fixed, value-safe error type for first-party collectors (W05, plan section 4.8).

A first-party collector build or run failure is a stable ``MH_COLLECTOR_*`` code carrying only
bounded developer text. The message never renders a target URL, a secret, a resolved host, or a
machine-local path, so the failure is safe to surface through the pipeline's collector isolation.
"""

from __future__ import annotations

from milhouse.core.errors import MilhouseError


class CollectorError(MilhouseError):
    """A fail-closed first-party collector failure carrying a fixed ``MH_COLLECTOR_*`` code.

    Codes: ``MH_COLLECTOR_CONFIG`` (the configuration handed to a first-party factory is not the
    expected collector configuration, or its target URL cannot form a bounded observation identity).
    """


__all__ = ["CollectorError"]
