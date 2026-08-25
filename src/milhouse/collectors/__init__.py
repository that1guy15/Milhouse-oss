"""First-party collectors (W05 onward).

Each collector satisfies the runtime :class:`~milhouse.runtime.registry.Collector` protocol and is
registered against its configuration type through a first-party factory. The ``site_canary``
collector turns one bounded probe into an availability event; the ``file_outbox`` collector (W07)
turns a compliant ``.milhouse`` outbox into event records, resuming from its durable source cursor.
Each ``register_*`` helper wires one collector into a runtime registry.
"""

from __future__ import annotations

from milhouse.collectors.errors import CollectorError
from milhouse.collectors.file_outbox import (
    FILE_OUTBOX_TYPE,
    FileOutboxBinding,
    FileOutboxCollector,
    file_outbox_factory,
    register_file_outbox,
)
from milhouse.collectors.site_canary import (
    SITE_CANARY_TYPE,
    SiteCanaryCollector,
    build_collector,
    register_site_canary,
    site_canary_factory,
)

__all__ = [
    "FILE_OUTBOX_TYPE",
    "SITE_CANARY_TYPE",
    "CollectorError",
    "FileOutboxBinding",
    "FileOutboxCollector",
    "SiteCanaryCollector",
    "build_collector",
    "file_outbox_factory",
    "register_file_outbox",
    "register_site_canary",
    "site_canary_factory",
]
