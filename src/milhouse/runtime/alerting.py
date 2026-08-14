"""The deterministic ``canary_state`` alert engine (W05 alerting, plan section 4.6).

The engine turns one availability sample for one rule into at most one alert-state transition. It is
pure and offline: given the loaded per-rule state, the sample outcome, the triggering availability
record id, the target, and the run instant, :func:`evaluate_canary_state_rule` returns the new state
to persist and — only when the derived state actually changes — one
:class:`~milhouse.domain.records.RecordDraftV1` alert transition. It never reads a clock or a random
source; the caller injects ``now``.

State is system-derived (plan section 4.6)::

    inactive -> firing -> resolved
    resolved -> firing   # a new recurrence re-fires under the same alert key

Opening uses the configured consecutive-failure threshold; recovery uses the consecutive-success
threshold. A firing is additionally gated by the cooldown window (``now`` must be at or past
``cooldown_until``), which suppresses a re-fire inside the window; recovery is not cooldown-gated.
The cooldown debounces RE-FIRING and is measured from the last FIRE: only a firing transition sets
``cooldown_until`` to ``now + cooldown_seconds``, and a resolve does NOT extend it, so a genuine new
outage shortly after a recovery is not over-suppressed. Repeated polls in the same state emit
nothing — a transition is emitted only when the state changes, never as a self-loop.

An evidence-less failure sample (a collector that reported ``failed`` with no availability record —
the site_canary no longer does this, but a generic collector still can) advances the counter, but
carries no privacy-safe record to cite as evidence, so it can never itself be the emitted trigger: a
transition is emitted only on a sample that carries a triggering record id. The counter still
accumulates, so the transition fires on the first evidence-bearing failure sample at or past the
threshold. Every emitted alert draft is
``producer="system"`` with no collector provenance, couples its envelope severity to its payload
severity, and cites exactly the one triggering availability record.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Literal

from milhouse.core.clock import format_timestamp
from milhouse.domain.identity import (
    ObservationCoordinateV1,
    derive_alert_key,
    derive_transition_id,
)
from milhouse.domain.records import (
    AlertDataV1,
    RecordDraftV1,
    SourceDescriptorV1,
    TargetDescriptorV1,
)
from milhouse.runtime.errors import PipelineError
from milhouse.state.alert_state import AlertRuleState

#: The fixed rule-logic version for the increment-3 canary alert engine. Config-declared rule
#: versioning is future work; the identity/state key reserves the ``(rule_id, rule_version)`` shape.
CANARY_STATE_RULE_VERSION = 1

AlertOutcome = Literal["success", "failure"]
_AlertState = Literal["inactive", "firing", "resolved"]
_Transition = Literal["firing", "resolved"]

_SOURCE_TYPE = "alert.canary_state"
_RECORD_NAME = "alert.canary_state"
_OBSERVATION_KIND = "alert.canary_state.transition"
#: A fixed v4-shaped namespace for system-derived alert identity; stable so records stay idempotent.
_ALERT_NAMESPACE = "mh_ns1_a1e77b2c3d404e5f8a0b1c2d3e4f5a6b"
#: Nominal record expiry; true retention is governed by the segment header and storage TTL.
_NOMINAL_EXPIRY = timedelta(days=365)

_SEVERITY_BY_STATE: dict[str, str] = {"firing": "error", "resolved": "info"}
_SUMMARY_BY_STATE: dict[str, str] = {
    "firing": (
        "Canary availability rule entered the firing state after reaching the configured "
        "consecutive-failure threshold."
    ),
    "resolved": (
        "Canary availability rule returned to the resolved state after reaching the configured "
        "consecutive-success threshold."
    ),
}


@dataclass(frozen=True, slots=True)
class AlertRuleSpec:
    """The resolved, validated inputs one canary_state rule contributes to the engine."""

    rule_id: str
    rule_version: int
    collector: str
    consecutive_failures: int
    consecutive_successes: int
    cooldown_seconds: int


@dataclass(frozen=True, slots=True)
class AlertStateUpdate:
    """The new per-rule state the caller persists after one sample (always, transition or not)."""

    consecutive_fail_count: int
    consecutive_success_count: int
    current_state: _AlertState
    cooldown_until: str | None
    last_sample_at: str
    last_transition_id: str | None
    expected_revision: int
    revision: int


@dataclass(frozen=True, slots=True)
class AlertEvaluation:
    """The engine's output for one sample: the state update and any emitted transition draft."""

    update: AlertStateUpdate
    draft: RecordDraftV1 | None
    transition: _Transition | None


def _source_generation_digest(spec: AlertRuleSpec) -> str:
    """Derive a stable 64-hex source-generation digest binding the rule id and its version."""

    material = f"{_SOURCE_TYPE}\x00{spec.rule_id}\x00{spec.rule_version}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _transition_observation(
    spec: AlertRuleSpec, target: TargetDescriptorV1, now_stamp: str, state: str
) -> ObservationCoordinateV1:
    """Build the deterministic observation coordinate identifying one alert transition sample."""

    return ObservationCoordinateV1(
        kind=_OBSERVATION_KIND,
        parts={
            "rule": spec.rule_id,
            "rule_version": spec.rule_version,
            "target": target.id,
            "scheduled_at": now_stamp,
            "state": state,
        },
    )


def _alert_draft(
    spec: AlertRuleSpec,
    target: TargetDescriptorV1,
    *,
    now: datetime,
    observation: ObservationCoordinateV1,
    alert_key: str,
    transition_id: str,
    previous_state: str,
    state: _Transition,
    revision: int,
    triggering_record_id: str,
) -> RecordDraftV1:
    """Build one system-produced, target-scoped alert transition draft with coupled severity.

    ``producer="system"`` with no collector provenance is the exact inverse of the site-canary
    availability draft: an alert is derived by the engine, not collected. The triggering coordinate
    is placed in ``source.observation`` so :func:`~milhouse.domain.records.finalize_record` derives
    a record identity that is idempotent for one transition and distinct across transitions. The
    summary is a fixed privacy-safe string — never an interpolated URL, target name, or payload.
    """

    stamp = format_timestamp(now)
    severity = _SEVERITY_BY_STATE[state]
    source = SourceDescriptorV1(
        id=spec.rule_id,
        type=_SOURCE_TYPE,
        producer="system",
        observation_namespace_id=_ALERT_NAMESPACE,
        source_generation_digest=_source_generation_digest(spec),
        observation=observation,
    )
    data = AlertDataV1(
        alert_key=alert_key,
        rule_id=spec.rule_id,
        rule_version=spec.rule_version,
        transition_id=transition_id,
        revision=revision,
        previous_state=previous_state,  # type: ignore[arg-type]
        state=state,
        triggering_observation=observation,
        severity=severity,  # type: ignore[arg-type]
        summary=_SUMMARY_BY_STATE[state],
        evidence_ids=[triggering_record_id],
    )
    return RecordDraftV1(
        record_type="alert",
        name=_RECORD_NAME,
        occurred_at=now,
        observed_at=now,
        ingested_at=now,
        expires_at=now + _NOMINAL_EXPIRY,
        operation_id=f"{spec.rule_id}:{stamp}",
        scope="target",
        source=source,
        target=target,
        severity=severity,  # type: ignore[arg-type]
        trust_level="system",
        privacy_class="internal",
        redaction_version="r1-e1",
        data=data,
    )


def evaluate_canary_state_rule(
    spec: AlertRuleSpec,
    *,
    outcome: AlertOutcome,
    triggering_record_id: str | None,
    target: TargetDescriptorV1,
    now: datetime,
    current: AlertRuleState | None,
) -> AlertEvaluation:
    """Evaluate one availability sample against a rule; return the state update and any transition.

    ``current`` is the loaded per-rule state (``None`` before the first sample). ``outcome`` maps a
    healthy event to ``success`` and a degraded event or a probe failure to ``failure``.
    ``triggering_record_id`` is the committed availability record's id, or ``None`` for a probe
    failure that produced no record. The returned :class:`AlertStateUpdate` is always persisted; the
    draft is present only when the state actually changed.
    """

    if not isinstance(target, TargetDescriptorV1):
        raise PipelineError("MH_RUNTIME_ALERT_TARGET", "a target descriptor is required")
    if outcome not in ("success", "failure"):
        raise PipelineError("MH_RUNTIME_ALERT_OUTCOME", "an alert sample outcome is required")

    base_state: _AlertState = "inactive"
    fail = 0
    success = 0
    cooldown_until: str | None = None
    revision = 0
    last_transition_id: str | None = None
    if current is not None:
        base_state = current.current_state  # type: ignore[assignment]
        fail = current.consecutive_fail_count
        success = current.consecutive_success_count
        cooldown_until = current.cooldown_until
        revision = current.revision
        last_transition_id = current.last_transition_id

    expected_revision = revision
    now_stamp = format_timestamp(now)

    # Increment the sampled counter and reset the opposite one on the flip.
    if outcome == "failure":
        fail += 1
        success = 0
    else:
        success += 1
        fail = 0

    new_state: _AlertState = base_state
    transition: _Transition | None = None
    previous_state: str | None = None
    if (
        outcome == "failure"
        and fail >= spec.consecutive_failures
        and base_state != "firing"
        and triggering_record_id is not None
        and (cooldown_until is None or now_stamp >= cooldown_until)
    ):
        previous_state = base_state  # inactive -> firing or resolved -> firing
        new_state = "firing"
        transition = "firing"
    elif (
        outcome == "success"
        and success >= spec.consecutive_successes
        and base_state == "firing"
        and triggering_record_id is not None
    ):
        previous_state = "firing"  # firing -> resolved
        new_state = "resolved"
        transition = "resolved"

    draft: RecordDraftV1 | None = None
    if transition is not None:
        assert triggering_record_id is not None and previous_state is not None
        if transition == "firing":
            # Cooldown debounces RE-FIRING and is measured from the last FIRE. Only a firing sets
            # it; a resolve must NOT extend the window (that would over-suppress a genuine new
            # outage shortly after a recovery), so the carried-forward value is left untouched.
            cooldown_until = format_timestamp(now + timedelta(seconds=spec.cooldown_seconds))
        alert_key = derive_alert_key(
            rule_id=spec.rule_id,
            rule_version=spec.rule_version,
            collector=spec.collector,
            target=target.id,
        )
        observation = _transition_observation(spec, target, now_stamp, new_state)
        transition_id = derive_transition_id(
            alert_key=alert_key,
            previous_state=previous_state,
            state=new_state,
            triggering_observation=observation,
        )
        last_transition_id = transition_id
        draft = _alert_draft(
            spec,
            target,
            now=now,
            observation=observation,
            alert_key=alert_key,
            transition_id=transition_id,
            previous_state=previous_state,
            state=transition,
            revision=revision + 1,
            triggering_record_id=triggering_record_id,
        )

    update = AlertStateUpdate(
        consecutive_fail_count=fail,
        consecutive_success_count=success,
        current_state=new_state,
        cooldown_until=cooldown_until,
        last_sample_at=now_stamp,
        last_transition_id=last_transition_id,
        expected_revision=expected_revision,
        revision=revision + 1,
    )
    return AlertEvaluation(update=update, draft=draft, transition=transition)


__all__ = [
    "CANARY_STATE_RULE_VERSION",
    "AlertEvaluation",
    "AlertOutcome",
    "AlertRuleSpec",
    "AlertStateUpdate",
    "evaluate_canary_state_rule",
]
