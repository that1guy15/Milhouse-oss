"""The collector registry: first-party factories and fail-closed third-party plugin binding.

The registry resolves a configured collector to a bound collector. Two paths exist:

* **First-party.** A collector type string is registered against a factory (``type -> factory``).
  Resolving a configuration of that type builds the collector through its factory. An unregistered,
  unknown, or not-yet-implemented type fails closed with a fixed code — never a crash or silent
  skip. Increment 1 registers no first-party types by default (the site-canary collector is a later
  increment); the mechanism and the registration API exist and are exercised with a fake collector.

* **Third-party.** A plugin collector is bound only at pipeline-resolve time, never at import. The
  binding re-runs the *exact* allowlist validation against installed package metadata AND then binds
  the concrete entry-point object it will load — re-checking the installed version and the exact
  entry-point object reference before ``load()``. This closes the time-of-check/time-of-use gap
  flagged in :mod:`milhouse.config.plugins`: a distribution that changed after configuration was
  validated fails closed here rather than silently loading a different object. Any validation,
  binding, or construction failure raises a fixed :class:`~milhouse.runtime.errors.RegistryError`
  that never renders a distribution name, object reference, path, or driver payload.
"""

from __future__ import annotations

import importlib.metadata
from collections.abc import Callable
from typing import Protocol, runtime_checkable

from milhouse.config._models import CollectorConfig, PluginAllowlistEntry, PluginsConfig
from milhouse.config.errors import ConfigError
from milhouse.config.plugins import validate_configured_plugins
from milhouse.domain.records import CollectorDescriptorV1
from milhouse.runtime.context import CollectorContext
from milhouse.runtime.errors import RegistryError
from milhouse.runtime.result import CollectorResult

_COLLECTOR_PLUGIN_GROUP = "milhouse.collectors"
# A registered first-party type is the collector-config discriminator (e.g. ``site_canary``); it
# shares the configuration identifier grammar (lowercase, bounded, no path or separator surprises).
_TYPE_NAME_MAX = 64


@runtime_checkable
class Collector(Protocol):
    """A resolved collector: its provenance descriptor and a single pure ``collect`` call.

    A collector reads its injected :class:`~milhouse.runtime.context.CollectorContext` and returns a
    :class:`~milhouse.runtime.result.CollectorResult`. It never writes to the spool or performs any
    durable side effect; the pipeline owns validation, redaction, identity, commit, and delivery.
    """

    descriptor: CollectorDescriptorV1

    def collect(self, context: CollectorContext) -> CollectorResult: ...


#: A first-party factory binds one collector configuration to a resolved collector instance.
CollectorFactory = Callable[[CollectorConfig], Collector]


def _validate_type_name(value: object) -> str:
    if type(value) is not str or not value or len(value) > _TYPE_NAME_MAX:
        raise RegistryError("MH_RUNTIME_REGISTRY_TYPE", "a bounded collector type name is required")
    return value


def _require_collector(candidate: object, code: str, message: str) -> Collector:
    if not isinstance(candidate, Collector):
        raise RegistryError(code, message)
    return candidate


class CollectorRegistry:
    """A mutable mapping of first-party collector types to factories plus plugin binding."""

    __slots__ = ("_factories",)

    def __init__(self) -> None:
        self._factories: dict[str, CollectorFactory] = {}

    def __repr__(self) -> str:
        return f"CollectorRegistry(first_party_types={len(self._factories)})"

    @property
    def registered_types(self) -> frozenset[str]:
        """The set of registered first-party collector type names."""

        return frozenset(self._factories)

    def register(self, type_name: str, factory: CollectorFactory) -> None:
        """Register one first-party collector type against its factory; reject a duplicate."""

        name = _validate_type_name(type_name)
        if not callable(factory):
            raise RegistryError("MH_RUNTIME_REGISTRY_TYPE", "a collector factory must be callable")
        if name in self._factories:
            raise RegistryError(
                "MH_RUNTIME_REGISTRY_DUPLICATE", "a collector type is already registered"
            )
        self._factories[name] = factory

    def resolve(self, config: CollectorConfig) -> Collector:
        """Resolve one configured first-party collector, failing closed on an unknown type."""

        type_name = _validate_type_name(getattr(config, "type", None))
        factory = self._factories.get(type_name)
        if factory is None:
            # Unknown, unallowlisted, or not-yet-implemented: never crash, never silently skip.
            raise RegistryError(
                "MH_RUNTIME_COLLECTOR_UNREGISTERED",
                "no collector is registered for the configured type",
            )
        collector = factory(config)
        return _require_collector(
            collector,
            "MH_RUNTIME_COLLECTOR_INVALID",
            "the collector factory returned an invalid collector",
        )

    def bind_plugin_collector(
        self, entry: PluginAllowlistEntry, *, plugins: PluginsConfig
    ) -> Collector:
        """Re-validate and bind one allowlisted third-party collector plugin, failing closed.

        The binding is the enforcement point that closes the plugins configuration TOCTOU: it
        re-runs the exact allowlist validation against installed metadata and then binds the
        concrete entry-point object, re-checking the installed version and object reference
        immediately before loading. It is invoked only at pipeline-resolve time, never at import.
        """

        if type(entry) is not PluginAllowlistEntry:
            raise RegistryError("MH_RUNTIME_PLUGIN_INVALID", "a plugin allowlist entry is required")
        if type(plugins) is not PluginsConfig:
            raise RegistryError("MH_RUNTIME_PLUGIN_INVALID", "a plugins configuration is required")
        if plugins.allow_third_party is not True:
            raise RegistryError("MH_RUNTIME_PLUGIN_DISABLED", "third-party plugins are not enabled")
        if entry not in plugins.allowed:
            raise RegistryError(
                "MH_RUNTIME_PLUGIN_NOT_ALLOWLISTED", "the plugin is not allowlisted"
            )
        if entry.group != _COLLECTOR_PLUGIN_GROUP:
            raise RegistryError("MH_RUNTIME_PLUGIN_GROUP", "the plugin is not a collector plugin")
        # Re-run the exact configuration-time allowlist validation against installed metadata; if
        # the installed distribution changed since configuration, this fails and we never load.
        try:
            validate_configured_plugins(plugins)
        except ConfigError:
            raise RegistryError(
                "MH_RUNTIME_PLUGIN_REJECTED",
                "the configured plugin no longer matches installed metadata",
            ) from None
        loaded = _load_plugin_object(entry)
        return _bind_plugin_collector(loaded)


def _load_plugin_object(entry: PluginAllowlistEntry) -> object:
    """Bind and load the exact allowlisted entry-point object, re-verifying its provenance."""

    try:
        distributions = list(importlib.metadata.distributions(name=entry.distribution))
    except Exception:
        raise RegistryError(
            "MH_RUNTIME_PLUGIN_REJECTED", "the plugin distribution could not be read"
        ) from None
    if len(distributions) != 1:
        raise RegistryError(
            "MH_RUNTIME_PLUGIN_REJECTED", "the plugin distribution is missing or ambiguous"
        )
    distribution = distributions[0]
    try:
        installed_version = distribution.version
    except Exception:
        installed_version = None
    # Re-check the version at bind time (not only at config validation): a distribution swapped
    # after validation must not be loaded.
    if installed_version != entry.version:
        raise RegistryError(
            "MH_RUNTIME_PLUGIN_REJECTED", "the installed plugin version changed after validation"
        )
    try:
        candidates = [
            candidate
            for candidate in distribution.entry_points
            if candidate.group == entry.group and candidate.value == entry.entry_point
        ]
    except Exception:
        raise RegistryError(
            "MH_RUNTIME_PLUGIN_REJECTED", "the plugin entry points could not be read"
        ) from None
    # Bind the EXACT object reference: zero or many matches means the installed entry point drifted
    # from the allowlisted one, so fail closed rather than load a different object.
    if len(candidates) != 1:
        raise RegistryError(
            "MH_RUNTIME_PLUGIN_REJECTED",
            "the installed plugin entry point changed after validation",
        )
    try:
        return candidates[0].load()
    except Exception:
        raise RegistryError(
            "MH_RUNTIME_PLUGIN_LOAD", "the plugin entry point could not be loaded"
        ) from None


def _bind_plugin_collector(loaded: object) -> Collector:
    """Accept a bound plugin object that is, or constructs, a valid collector; else fail closed."""

    # A class is routed to construction BEFORE the instance branch: a class whose body defines
    # class-level ``descriptor`` and ``collect`` satisfies the runtime_checkable ``Collector``
    # protocol un-instantiated, so an ``isinstance(..., Collector)`` check first would return the
    # class object itself rather than a usable instance. Only a constructed instance is ever bound.
    if isinstance(loaded, type):
        return _construct_plugin_collector(loaded)
    if isinstance(loaded, Collector):
        return loaded
    if callable(loaded):
        return _construct_plugin_collector(loaded)
    raise RegistryError(
        "MH_RUNTIME_PLUGIN_INVALID", "the plugin entry point is not a collector or factory"
    )


def _construct_plugin_collector(factory: Callable[..., object]) -> Collector:
    """Construct a collector from a plugin class or factory, failing closed on any error."""

    try:
        constructed = factory()
    except Exception:
        raise RegistryError(
            "MH_RUNTIME_PLUGIN_LOAD", "the plugin collector could not be constructed"
        ) from None
    return _require_collector(
        constructed,
        "MH_RUNTIME_PLUGIN_INVALID",
        "the plugin did not produce a valid collector",
    )


__all__ = ["Collector", "CollectorFactory", "CollectorRegistry"]
