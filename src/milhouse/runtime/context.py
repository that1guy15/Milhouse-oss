"""The immutable per-run context handed to a collector (W05, plan section 4.8).

A :class:`CollectorContext` is the single input a collector receives for one run. It carries only
non-sensitive, injected dependencies: the run instant from the injected clock, the installation id,
the collector's own descriptor, the target descriptor (for a target-scoped collector), the
request-timeout budget resolved from the collector configuration, and a redaction handle. It never
carries a secret, a credential, a provider payload, an environment reference, or a machine-local
path, so passing it to untrusted collector code cannot leak host state. Every field is validated on
construction and the value is frozen, so a collector cannot mutate the context it was given.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from milhouse.core.clock import TimeError, truncate_to_milliseconds
from milhouse.domain.records import CollectorDescriptorV1, TargetDescriptorV1
from milhouse.privacy.redact import LayeredRedactor
from milhouse.runtime.errors import PipelineError
from milhouse.spooling.reader import INSTALLATION_ID_PATTERN

# Matches the collector configuration bound (``_CollectorBase.request_timeout_seconds``): a request
# budget is a positive, bounded number of seconds so a collector cannot be handed an unbounded one.
_MIN_TIMEOUT_SECONDS = 1
_MAX_TIMEOUT_SECONDS = 300


@dataclass(frozen=True, slots=True)
class CollectorContext:
    """One collector's frozen per-run dependencies, validated and safe to hand to plugin code."""

    now: datetime
    installation_id: str
    collector: CollectorDescriptorV1
    target: TargetDescriptorV1 | None
    request_timeout_seconds: int
    redactor: LayeredRedactor

    def __post_init__(self) -> None:
        # Normalize and re-validate the run instant to an aware UTC millisecond value; the injected
        # clock already truncates, so this is a defensive gate against a naive or drifted instant.
        try:
            normalized = truncate_to_milliseconds(self.now)
        except TimeError:
            raise PipelineError(
                "MH_RUNTIME_CONTEXT_NOW", "the run instant must be an aware UTC instant"
            ) from None
        object.__setattr__(self, "now", normalized)
        if (
            type(self.installation_id) is not str
            or INSTALLATION_ID_PATTERN.fullmatch(self.installation_id) is None
        ):
            raise PipelineError(
                "MH_RUNTIME_CONTEXT_INSTALLATION", "a well-formed installation id is required"
            )
        if not isinstance(self.collector, CollectorDescriptorV1):
            raise PipelineError(
                "MH_RUNTIME_CONTEXT_COLLECTOR", "a collector descriptor is required"
            )
        if self.target is not None and not isinstance(self.target, TargetDescriptorV1):
            raise PipelineError(
                "MH_RUNTIME_CONTEXT_TARGET", "the target must be a target descriptor or absent"
            )
        if (
            type(self.request_timeout_seconds) is not int
            or not _MIN_TIMEOUT_SECONDS <= self.request_timeout_seconds <= _MAX_TIMEOUT_SECONDS
        ):
            raise PipelineError(
                "MH_RUNTIME_CONTEXT_TIMEOUT", "a bounded positive request timeout is required"
            )
        if type(self.redactor) is not LayeredRedactor:
            raise PipelineError(
                "MH_RUNTIME_CONTEXT_REDACTOR", "a layered redactor handle is required"
            )


__all__ = ["CollectorContext"]
