"""The ``site_canary`` collector: one bounded GET turned into one availability event (W05).

The site-canary collector is the first first-party collector. On each run it performs exactly one
GET to its configured URL through the shared :class:`~milhouse.http.client.BoundedHttpClient` — GET
only, no redirect following, TLS verification on, SSRF-guarded — and classifies the target as
``healthy`` when the response status is one of the configured ``expected_statuses`` and ``degraded``
otherwise. It emits a single ``availability`` :class:`~milhouse.domain.records.EventDataV1` draft
and returns it to the pipeline, which owns redaction, identity, commit, and delivery.

Record identity (plan section 4.2): the draft carries a **deterministic observation coordinate** —
the scheduled run instant from ``context.now`` together with the sanitized URL route — so the record
id is stable and idempotent for one scheduled probe. Re-running the same probe at the same instant
yields the same record id; a later scheduled instant yields a distinct one. The collector never
renders a raw or credentialed URL: a client, SSRF, or timeout failure returns a fail-closed
``CollectorResult(status="failed")`` with only privacy-safe counts, and any unexpected fault
propagates to the pipeline's per-collector isolation as a fixed code.
"""

from __future__ import annotations

import hashlib
from datetime import timedelta
from typing import cast

from milhouse.collectors.errors import CollectorError
from milhouse.config._models import CollectorConfig
from milhouse.config._models import SiteCanaryCollector as SiteCanaryConfig
from milhouse.core.clock import format_timestamp
from milhouse.domain.identity import ObservationCoordinateV1
from milhouse.domain.records import (
    CollectorDescriptorV1,
    EventDataV1,
    RecordDraftV1,
    SourceDescriptorV1,
)
from milhouse.http import BoundedHttpClient, HttpClientError
from milhouse.privacy.sanitize import sanitize_url
from milhouse.runtime.context import CollectorContext
from milhouse.runtime.registry import Collector, CollectorRegistry
from milhouse.runtime.result import CollectorResult

#: The configuration discriminator and registry key for this first-party collector.
SITE_CANARY_TYPE = "site_canary"

_IMPLEMENTATION_VERSION = "1.0.0"
_COLLECTOR_TYPE = "site.canary"
_SOURCE_TYPE = "source.event"
_RECORD_NAME = "site.canary"
_OBSERVATION_KIND = "site.canary.probe"
#: A fixed v4-shaped namespace for canary source identity; stable so records stay idempotent.
_CANARY_NAMESPACE = "mh_ns1_5ca9a1b2c3d44e5f8a0b1c2d3e4f5a6b"
#: Nominal record expiry; true retention is governed by the segment header and storage TTL.
_NOMINAL_EXPIRY = timedelta(days=30)
#: An observation string part is bounded to 256 UTF-8 bytes, so the sanitized route must fit.
_MAX_ROUTE_BYTES = 256


class SiteCanaryCollector:
    """A resolved site-canary collector: its descriptor plus one pure, bounded ``collect`` call."""

    __slots__ = (
        "_client",
        "_expected_statuses",
        "_request_url",
        "_sanitized_url",
        "_source_generation_digest",
        "descriptor",
    )

    def __init__(self, config: SiteCanaryConfig, *, client: BoundedHttpClient) -> None:
        if not isinstance(config, SiteCanaryConfig):
            raise CollectorError("MH_COLLECTOR_CONFIG", "a site_canary configuration is required")
        sanitized = sanitize_url(str(config.url)).value
        if len(sanitized.encode("utf-8")) > _MAX_ROUTE_BYTES:
            raise CollectorError(
                "MH_COLLECTOR_CONFIG", "the canary target URL exceeds the observation route bound"
            )
        self._client = client
        self._request_url = str(config.url)
        self._sanitized_url = sanitized
        self._expected_statuses = frozenset(config.expected_statuses)
        self._source_generation_digest = _source_generation_digest(sanitized)
        self.descriptor = CollectorDescriptorV1(
            id=config.id,
            type=_COLLECTOR_TYPE,
            implementation_version=_IMPLEMENTATION_VERSION,
        )

    def collect(self, context: CollectorContext) -> CollectorResult:
        """Probe the target once and return one availability event, or a fail-closed result."""

        try:
            probe = self._client.get(
                self._request_url,
                timeout_seconds=context.request_timeout_seconds,
                verify_tls=True,
            )
        except HttpClientError:
            # A client, SSRF, TLS, or timeout failure is a fail-closed run outcome, never a leaked
            # URL: the pipeline records a failed status and the canary emits no false availability.
            return CollectorResult(
                status="failed",
                drafts=(),
                diagnostics={"probes": 1, "probe_failures": 1},
            )
        health = "healthy" if probe.status_code in self._expected_statuses else "degraded"
        draft = self._draft(context, status_code=probe.status_code, health=health)
        return CollectorResult(
            status="ok",
            drafts=(draft,),
            diagnostics={
                "probes": 1,
                "healthy": int(health == "healthy"),
                "degraded": int(health == "degraded"),
            },
        )

    def _draft(
        self,
        context: CollectorContext,
        *,
        status_code: int,
        health: str,
    ) -> RecordDraftV1:
        now = context.now
        stamp = format_timestamp(now)
        observation = ObservationCoordinateV1(
            kind=_OBSERVATION_KIND,
            parts={"scheduled_at": stamp, "route": self._sanitized_url},
        )
        source = SourceDescriptorV1(
            id=context.collector.id,
            type=_SOURCE_TYPE,
            producer="collector",
            observation_namespace_id=_CANARY_NAMESPACE,
            source_generation_digest=self._source_generation_digest,
            observation=observation,
        )
        data = EventDataV1(
            category="availability",
            status=health,
            attributes={"http_status": status_code},
        )
        return RecordDraftV1(
            record_type="event",
            name=_RECORD_NAME,
            occurred_at=now,
            observed_at=now,
            ingested_at=now,
            expires_at=now + _NOMINAL_EXPIRY,
            operation_id=f"{context.collector.id}:{stamp}",
            collector_run_id=f"{context.collector.id}:{stamp}",
            scope="target",
            source=source,
            collector=context.collector,
            target=context.target,
            severity="info",
            trust_level="authenticated",
            privacy_class="internal",
            redaction_version="r1-e1",
            data=data,
        )


def _source_generation_digest(sanitized_url: str) -> str:
    """Derive a stable 64-hex source-generation digest from the collector type and route."""

    material = f"{_COLLECTOR_TYPE}\x00{_IMPLEMENTATION_VERSION}\x00{sanitized_url}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def build_collector(
    config: SiteCanaryConfig,
    *,
    client: BoundedHttpClient | None = None,
) -> SiteCanaryCollector:
    """Build one site-canary collector, defaulting to a real bounded HTTP client in production."""

    return SiteCanaryCollector(config, client=BoundedHttpClient() if client is None else client)


def site_canary_factory(config: CollectorConfig) -> Collector:
    """The first-party factory registered against the ``site_canary`` type (real client).

    The registry hands a factory the shared collector-config union; the concrete-type check lives in
    the collector constructor, which fails closed with ``MH_COLLECTOR_CONFIG`` on a mismatch.
    """

    return build_collector(cast(SiteCanaryConfig, config))


def register_site_canary(registry: CollectorRegistry) -> None:
    """Register the site-canary collector's first-party factory into a runtime registry."""

    registry.register(SITE_CANARY_TYPE, site_canary_factory)


__all__ = [
    "SITE_CANARY_TYPE",
    "SiteCanaryCollector",
    "build_collector",
    "register_site_canary",
    "site_canary_factory",
]
