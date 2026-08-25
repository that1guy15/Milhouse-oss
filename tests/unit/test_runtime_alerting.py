"""Behavioural guarantees for the deterministic canary_state alert engine (W05 alerting).

The engine turns one availability sample into at most one alert-state transition. These tests pin
the state machine (first-failure firing, recovery, re-fire, cooldown suppression, no-op suppression,
probe-failure counting, threshold honouring), the draft shape (system producer, no collector
provenance, coupled severity, one evidence id, privacy-safe summary), and determinism (an identical
sample re-derives an identical record id and transition id).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from milhouse.domain.records import (
    AlertDataV1,
    RecordDraftV1,
    TargetDescriptorV1,
    finalize_record,
)
from milhouse.runtime.alerting import (
    CANARY_STATE_RULE_VERSION,
    AlertRuleSpec,
    evaluate_canary_state_rule,
)
from milhouse.runtime.errors import PipelineError
from milhouse.state.alert_state import AlertRuleState

_NOW = datetime(2026, 7, 21, 15, 0, tzinfo=UTC)
_INSTALLATION_ID = "mh_in1_00000000000040008000000000000000"
_EVIDENCE = "mh_g3hdcz3y6hf7wf5puc2h77nm554bfl3e45vrdfyyartayjdogdga"
_EVIDENCE_TWO = "mh_h4mpuxg5nvasjyknwae2vqvhbnqjeidjq3tfbgz7wm5ipenqxyzq"
_KNOWN_SECRET = "supersecretvalue123"

_TARGET = TargetDescriptorV1(id="t1", name="Example Target", kind="web_service", environment="test")


def _spec(*, failures: int = 1, successes: int = 1, cooldown: int = 0) -> AlertRuleSpec:
    return AlertRuleSpec(
        rule_id="canary-rule",
        rule_version=CANARY_STATE_RULE_VERSION,
        collector="canary1",
        consecutive_failures=failures,
        consecutive_successes=successes,
        cooldown_seconds=cooldown,
    )


def _state(**overrides: object) -> AlertRuleState:
    base: dict[str, object] = {
        "rule_id": "canary-rule",
        "rule_version": 1,
        "consecutive_fail_count": 0,
        "consecutive_success_count": 0,
        "current_state": "inactive",
        "cooldown_until": None,
        "last_sample_at": None,
        "last_transition_id": None,
        "revision": 0,
        "updated_at": "2026-07-21T15:00:00.000Z",
    }
    base.update(overrides)
    return AlertRuleState(**base)  # type: ignore[arg-type]


def _evaluate(spec, *, outcome, now=_NOW, current=None, record_id=_EVIDENCE):
    return evaluate_canary_state_rule(
        spec,
        outcome=outcome,
        triggering_record_id=record_id,
        target=_TARGET,
        now=now,
        current=current,
    )


def test_the_first_failure_fires_from_inactive() -> None:
    evaluation = _evaluate(_spec(), outcome="failure")
    assert evaluation.transition == "firing"
    assert evaluation.update.current_state == "firing"
    assert evaluation.update.revision == 1
    assert evaluation.update.expected_revision == 0
    draft = evaluation.draft
    assert isinstance(draft, RecordDraftV1)
    assert isinstance(draft.data, AlertDataV1)
    assert (draft.data.previous_state, draft.data.state) == ("inactive", "firing")


def test_consecutive_failures_are_required_before_firing() -> None:
    spec = _spec(failures=2)
    first = _evaluate(spec, outcome="failure")
    assert first.transition is None
    assert first.update.consecutive_fail_count == 1
    assert first.update.current_state == "inactive"
    second = _evaluate(
        spec,
        outcome="failure",
        now=_NOW + timedelta(minutes=1),
        current=_state(consecutive_fail_count=1, revision=1),
    )
    assert second.transition == "firing"


def test_a_probe_failure_counts_as_a_failure_sample_without_evidence() -> None:
    # A probe failure (no availability record) advances the counter but cannot itself be the cited
    # trigger; the firing is emitted on the next failure sample that carries a record.
    spec = _spec(failures=2)
    probe = _evaluate(spec, outcome="failure", record_id=None)
    assert probe.transition is None
    assert probe.draft is None
    assert probe.update.consecutive_fail_count == 1
    firing = _evaluate(
        spec,
        outcome="failure",
        now=_NOW + timedelta(minutes=1),
        current=_state(consecutive_fail_count=1, revision=1),
    )
    assert firing.transition == "firing"
    assert firing.draft is not None
    assert list(firing.draft.data.evidence_ids) == [_EVIDENCE]


def test_a_probe_failure_at_the_threshold_defers_firing_until_evidence() -> None:
    spec = _spec(failures=1)
    probe = _evaluate(spec, outcome="failure", record_id=None)
    assert probe.transition is None
    assert probe.update.current_state == "inactive"  # no evidence, so no state change yet
    assert probe.update.consecutive_fail_count == 1


def test_recovery_resolves_from_firing() -> None:
    spec = _spec(successes=1)
    firing = _state(consecutive_fail_count=1, current_state="firing", revision=1)
    evaluation = _evaluate(spec, outcome="success", record_id=_EVIDENCE_TWO, current=firing)
    assert evaluation.transition == "resolved"
    assert evaluation.draft is not None
    assert (evaluation.draft.data.previous_state, evaluation.draft.data.state) == (
        "firing",
        "resolved",
    )
    assert evaluation.update.consecutive_success_count == 1
    assert evaluation.update.consecutive_fail_count == 0


def test_a_resolved_alert_refires_on_a_new_recurrence() -> None:
    spec = _spec(failures=1, cooldown=0)
    resolved = _state(consecutive_success_count=1, current_state="resolved", revision=2)
    evaluation = _evaluate(spec, outcome="failure", current=resolved)
    assert evaluation.transition == "firing"
    assert (evaluation.draft.data.previous_state, evaluation.draft.data.state) == (
        "resolved",
        "firing",
    )


def test_cooldown_is_measured_from_the_fire_and_a_resolve_does_not_extend_it() -> None:
    spec = _spec(failures=1, successes=1, cooldown=300)
    # A fire at 15:00 sets cooldown_until to 15:05: the RE-FIRE debounce window, measured from here.
    fired = _evaluate(spec, outcome="failure")
    assert fired.transition == "firing"
    assert fired.update.cooldown_until == "2026-07-21T15:05:00.000Z"

    # A re-fire attempt at 15:03 (inside the window) is suppressed; the counter still advances.
    suppressed = _evaluate(
        spec,
        outcome="failure",
        now=_NOW + timedelta(minutes=3),
        current=_state(
            current_state="resolved",
            cooldown_until="2026-07-21T15:05:00.000Z",
            revision=2,
        ),
    )
    assert suppressed.transition is None
    assert suppressed.update.current_state == "resolved"
    assert suppressed.update.consecutive_fail_count == 1

    # A resolve inside the window is never cooldown-gated AND must NOT extend the window: the
    # cooldown_until stays at the firing's 15:05, never reset to 15:07. (The old bug reset it on
    # every transition, over-suppressing a genuine new outage shortly after a recovery.)
    resolved = _evaluate(
        spec,
        outcome="success",
        record_id=_EVIDENCE_TWO,
        now=_NOW + timedelta(minutes=2),
        current=_state(
            consecutive_fail_count=1,
            current_state="firing",
            cooldown_until="2026-07-21T15:05:00.000Z",
            revision=1,
        ),
    )
    assert resolved.transition == "resolved"
    assert resolved.update.cooldown_until == "2026-07-21T15:05:00.000Z"

    # A genuine new outage at 15:06 -- past the FIRE window, with that resolve in between -- fires,
    # because the resolve did not push the window out to 15:07.
    refired = _evaluate(
        spec,
        outcome="failure",
        now=_NOW + timedelta(minutes=6),
        current=_state(
            current_state="resolved",
            cooldown_until="2026-07-21T15:05:00.000Z",
            revision=3,
        ),
    )
    assert refired.transition == "firing"


def test_repeated_polls_in_the_same_state_emit_no_transition() -> None:
    spec = _spec(failures=1)
    firing = _state(consecutive_fail_count=1, current_state="firing", revision=1)
    steady = _evaluate(spec, outcome="failure", now=_NOW + timedelta(minutes=1), current=firing)
    assert steady.transition is None
    assert steady.draft is None
    # State still advances so the counter and revision stay durable.
    assert steady.update.revision == 2
    assert steady.update.consecutive_fail_count == 2


def test_a_success_below_threshold_does_not_resolve() -> None:
    spec = _spec(successes=2)
    firing = _state(consecutive_fail_count=1, current_state="firing", revision=1)
    partial = _evaluate(spec, outcome="success", record_id=_EVIDENCE_TWO, current=firing)
    assert partial.transition is None
    assert partial.update.current_state == "firing"
    assert partial.update.consecutive_success_count == 1
    assert partial.update.consecutive_fail_count == 0


def test_a_transition_sets_the_cooldown_and_last_transition_id() -> None:
    evaluation = _evaluate(_spec(cooldown=120), outcome="failure")
    assert evaluation.update.cooldown_until == "2026-07-21T15:02:00.000Z"
    assert evaluation.update.last_transition_id is not None
    assert evaluation.update.last_transition_id == evaluation.draft.data.transition_id


def test_the_firing_and_resolved_severities_differ_and_couple_the_envelope() -> None:
    firing = _evaluate(_spec(), outcome="failure").draft
    assert firing.severity == firing.data.severity == "error"
    resolved = _evaluate(
        _spec(successes=1),
        outcome="success",
        record_id=_EVIDENCE_TWO,
        current=_state(current_state="firing", revision=1),
    ).draft
    assert resolved.severity == resolved.data.severity == "info"


def test_the_alert_draft_is_system_produced_with_no_collector_provenance() -> None:
    draft = _evaluate(_spec(), outcome="failure").draft
    assert draft.source.producer == "system"
    assert draft.collector is None
    assert draft.collector_run_id is None
    assert draft.scope == "target"
    assert draft.target is not None and draft.target.id == "t1"
    assert draft.trust_level == "system"
    assert draft.privacy_class == "internal"
    assert list(draft.data.evidence_ids) == [_EVIDENCE]
    assert len(draft.data.evidence_ids) >= 1


def test_the_alert_summary_is_a_fixed_privacy_safe_string() -> None:
    draft = _evaluate(_spec(), outcome="failure").draft
    # No secret, URL, path, or target name is interpolated into the summary or observation parts.
    assert _KNOWN_SECRET not in draft.data.summary
    assert "http" not in draft.data.summary.lower()
    assert _TARGET.name not in draft.data.summary
    assert draft.data.triggering_observation.parts["target"] == "t1"


def test_an_identical_sample_rederives_an_identical_record_and_transition_id() -> None:
    one = _evaluate(_spec(), outcome="failure")
    two = _evaluate(_spec(), outcome="failure")
    assert one.draft.data.transition_id == two.draft.data.transition_id
    record_one = finalize_record(one.draft, installation_id=_INSTALLATION_ID)
    record_two = finalize_record(two.draft, installation_id=_INSTALLATION_ID)
    assert record_one.record_id == record_two.record_id
    assert record_one.dedupe_key == record_two.dedupe_key


def test_distinct_transitions_derive_distinct_ids() -> None:
    firing = _evaluate(_spec(cooldown=0), outcome="failure")
    refire = _evaluate(
        _spec(cooldown=0),
        outcome="failure",
        now=_NOW + timedelta(minutes=5),
        current=_state(current_state="resolved", revision=2),
    )
    assert firing.draft.data.transition_id != refire.draft.data.transition_id
    # The alert key is stable across transitions of the same rule; only the transition id moves.
    assert firing.draft.data.alert_key == refire.draft.data.alert_key


def test_an_invalid_target_or_outcome_fails_closed() -> None:
    with pytest.raises(PipelineError) as captured:
        evaluate_canary_state_rule(
            _spec(),
            outcome="failure",
            triggering_record_id=_EVIDENCE,
            target=object(),  # type: ignore[arg-type]
            now=_NOW,
            current=None,
        )
    assert captured.value.code == "MH_RUNTIME_ALERT_TARGET"
    with pytest.raises(PipelineError) as captured:
        _evaluate(_spec(), outcome="maybe")  # type: ignore[arg-type]
    assert captured.value.code == "MH_RUNTIME_ALERT_OUTCOME"
