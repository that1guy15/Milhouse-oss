"""First-party collectors (W05 onward).

Each collector satisfies the runtime :class:`~milhouse.runtime.registry.Collector` protocol and is
registered against its configuration type through a first-party factory. Increment 2 delivers the
``site_canary`` collector; :func:`register_site_canary` wires it into a runtime registry.
"""

from __future__ import annotations

from milhouse.collectors.errors import CollectorError
from milhouse.collectors.site_canary import (
    SITE_CANARY_TYPE,
    SiteCanaryCollector,
    build_collector,
    register_site_canary,
    site_canary_factory,
)

__all__ = [
    "SITE_CANARY_TYPE",
    "CollectorError",
    "SiteCanaryCollector",
    "build_collector",
    "register_site_canary",
    "site_canary_factory",
]
