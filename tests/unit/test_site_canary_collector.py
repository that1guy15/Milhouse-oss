"""The site-canary collector: healthy/degraded classification, fail-closed failure, stable identity.

Every test is offline: the collector's bounded HTTP client is built over an injected resolver and an
``httpx`` ``MockTransport``, so no real DNS or socket is used. Record identity is checked by
finalizing the produced draft exactly as the pipeline would.
"""

from __future__ import annotations

from datetime import timedelta

import httpx
import pytest
from _http_fakes import fixed_resolver, responding_transport, stream_response
from _record_factories import INSTALLATION_ID, NOW

from milhouse.collectors.errors import CollectorError
from milhouse.collectors.site_canary import (
    SITE_CANARY_TYPE,
    build_collector,
    register_site_canary,
    site_canary_factory,
)
from milhouse.config._models import SiteCanaryCollector, TargetConfig
from milhouse.domain.records import (
    EventDataV1,
    TargetDescriptorV1,
    finalize_record,
)
from milhouse.privacy.pseudonym import Pseudonymizer
from milhouse.privacy.redact import LayeredRedactor
from milhouse.runtime.context import CollectorContext
from milhouse.runtime.registry import CollectorRegistry

_PUBLIC = "93.184.216.34"
_URL = "https://example.test/health"


def _config(
    collector_id: str = "canary1", *, url: str = _URL, statuses=(200,)
) -> SiteCanaryCollector:
    return SiteCanaryCollector(
        id=collector_id,
        target="t1",
        type="site_canary",
        url=url,
        expected_statuses=list(statuses),
    )


def _target() -> TargetDescriptorV1:
    config = TargetConfig(id="t1", name="Example Target", kind="web_service", environment="test")
    return TargetDescriptorV1(
        id=config.id, name=config.name, kind=config.kind, environment=config.environment
    )


def _collector(response_factory, *, config=None, resolver=None):
    transport, captured = responding_transport(response_factory)
    from milhouse.http import BoundedHttpClient

    client = BoundedHttpClient(resolver=resolver or fixed_resolver(_PUBLIC), transport=transport)
    return build_collector(config or _config(), client=client), captured


def _context(collector, *, now=NOW):
    return CollectorContext(
        now=now,
        installation_id=INSTALLATION_ID,
        collector=collector.descriptor,
        target=_target(),
        request_timeout_seconds=30,
        redactor=LayeredRedactor(Pseudonymizer(b"k" * 32)),
    )


# --- classification ----------------------------------------------------------------------------


def test_a_response_in_expected_statuses_is_a_healthy_availability_event() -> None:
    collector, _ = _collector(lambda request: stream_response(200))
    result = collector.collect(_context(collector))
    assert result.status == "ok"
    assert dict(result.diagnostics) == {"probes": 1, "healthy": 1, "degraded": 0}
    (draft,) = result.drafts
    assert isinstance(draft.data, EventDataV1)
    assert draft.data.category == "availability"
    assert draft.data.status == "healthy"
    assert draft.data.attributes["http_status"] == 200
    assert draft.record_type == "event"
    assert draft.name == "site.canary"
    assert draft.scope == "target"
    assert draft.target is not None and draft.target.id == "t1"


def test_a_response_outside_expected_statuses_is_a_degraded_event() -> None:
    collector, _ = _collector(lambda request: stream_response(503))
    result = collector.collect(_context(collector))
    assert result.status == "ok"
    assert dict(result.diagnostics) == {"probes": 1, "healthy": 0, "degraded": 1}
    (draft,) = result.drafts
    assert draft.data.status == "degraded"
    assert draft.data.attributes["http_status"] == 503


def test_the_collector_probes_the_configured_url_once_with_tls_and_no_redirect() -> None:
    collector, captured = _collector(lambda request: stream_response(200))
    collector.collect(_context(collector))
    assert len(captured) == 1
    request = captured[0]
    assert request.method == "GET"
    assert request.url.host == _PUBLIC  # pinned to the validated IP
    assert request.headers["host"] == "example.test"


# --- a probe failure is a degraded, alertable event (no url / error-detail leak) ---------------


def test_a_client_failure_yields_a_degraded_probe_failure_event_with_no_leaked_detail() -> None:
    # The host resolves to a private address, so the SSRF guard trips inside the client.
    collector, _ = _collector(
        lambda request: stream_response(200), resolver=fixed_resolver("10.0.0.5")
    )
    result = collector.collect(_context(collector))
    # A fully-failing probe stays alertable: one degraded availability event carrying only a
    # privacy-safe probe_failed count -- never a false-healthy sample, never a dropped record.
    assert result.status == "ok"
    assert dict(result.diagnostics) == {"probes": 1, "probe_failures": 1, "degraded": 1}
    (draft,) = result.drafts
    assert isinstance(draft.data, EventDataV1)
    assert draft.data.category == "availability"
    assert draft.data.status == "degraded"
    assert dict(draft.data.attributes) == {"probe_failed": 1}
    assert "http_status" not in draft.data.attributes
    # The record identity shape is unchanged from a responding probe (scheduled instant + route).
    assert set(draft.source.observation.parts) == {"scheduled_at", "route"}
    # Neither the resolved private address nor any error detail leaks into the result or its draft.
    assert "10.0.0.5" not in repr(result)


def test_a_transport_timeout_yields_a_degraded_probe_failure_event() -> None:
    def timing_out(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("slow")

    transport = httpx.MockTransport(timing_out)
    from milhouse.http import BoundedHttpClient

    client = BoundedHttpClient(resolver=fixed_resolver(_PUBLIC), transport=transport)
    collector = build_collector(_config(), client=client)
    result = collector.collect(_context(collector))
    assert result.status == "ok"
    (draft,) = result.drafts
    assert draft.data.status == "degraded"
    assert dict(draft.data.attributes) == {"probe_failed": 1}
    # The transport error detail never leaks into the result.
    assert "slow" not in repr(result)


# --- deterministic, idempotent record identity -------------------------------------------------


def test_the_record_id_is_deterministic_for_a_fixed_instant_and_url() -> None:
    first, _ = _collector(lambda request: stream_response(200))
    second, _ = _collector(lambda request: stream_response(200))
    record_a = finalize_record(
        first.collect(_context(first)).drafts[0], installation_id=INSTALLATION_ID
    )
    record_b = finalize_record(
        second.collect(_context(second)).drafts[0], installation_id=INSTALLATION_ID
    )
    assert record_a.record_id == record_b.record_id
    assert record_a.source.observation.kind == "site.canary.probe"
    assert set(record_a.source.observation.parts) == {"scheduled_at", "route"}


def test_a_later_scheduled_instant_yields_a_distinct_record_id() -> None:
    collector, _ = _collector(lambda request: stream_response(200))
    later, _ = _collector(lambda request: stream_response(200))
    early = finalize_record(
        collector.collect(_context(collector)).drafts[0], installation_id=INSTALLATION_ID
    )
    late = finalize_record(
        later.collect(_context(later, now=NOW + timedelta(minutes=5))).drafts[0],
        installation_id=INSTALLATION_ID,
    )
    assert early.record_id != late.record_id


def test_two_canaries_on_the_same_target_produce_distinct_record_ids() -> None:
    one, _ = _collector(lambda request: stream_response(200), config=_config("canary1"))
    two, _ = _collector(lambda request: stream_response(200), config=_config("canary2"))
    record_one = finalize_record(
        one.collect(_context(one)).drafts[0], installation_id=INSTALLATION_ID
    )
    record_two = finalize_record(
        two.collect(_context(two)).drafts[0], installation_id=INSTALLATION_ID
    )
    assert record_one.record_id != record_two.record_id


# --- factory, registration, and build guards ---------------------------------------------------


def test_registration_binds_the_site_canary_type_to_a_resolvable_collector() -> None:
    registry = CollectorRegistry()
    register_site_canary(registry)
    assert registry.registered_types == frozenset({SITE_CANARY_TYPE})
    collector = registry.resolve(_config("canary9"))
    assert collector.descriptor.id == "canary9"
    assert collector.descriptor.type == "site.canary"
    assert collector.descriptor.implementation_version == "1.0.0"


def test_the_production_factory_builds_a_collector_with_a_real_client() -> None:
    collector = site_canary_factory(_config())
    assert collector.descriptor.id == "canary1"


def test_a_non_canary_configuration_is_rejected_at_build() -> None:
    class _Other:
        id = "x"

    with pytest.raises(CollectorError) as caught:
        build_collector(_Other())  # type: ignore[arg-type]
    assert caught.value.code == "MH_COLLECTOR_CONFIG"


def test_a_target_url_that_overflows_the_observation_route_bound_is_rejected() -> None:
    config = _config(url="https://example.test/" + "a" * 300)
    with pytest.raises(CollectorError) as caught:
        build_collector(config)
    assert caught.value.code == "MH_COLLECTOR_CONFIG"
