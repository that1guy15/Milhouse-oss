"""Deterministic derivation and fail-closed validation for alert identity wires (W05 alerting).

``derive_alert_key`` and ``derive_transition_id`` are domain-separated digests: identical inputs
yield identical bounded ``OpaqueIdV1`` tokens, any input change yields a distinct token, and a
malformed input fails closed with a stable code that never renders the rejected value.
"""

from __future__ import annotations

import pytest

from milhouse.domain.identity import (
    IdentityError,
    ObservationCoordinateV1,
    derive_alert_key,
    derive_transition_id,
)


def _observation(state: str = "firing", scheduled_at: str = "2026-07-21T15:00:00.000Z"):
    return ObservationCoordinateV1(
        kind="alert.canary_state.transition",
        parts={
            "rule": "canary-rule",
            "rule_version": 1,
            "target": "t1",
            "scheduled_at": scheduled_at,
            "state": state,
        },
    )


def _is_opaque_id(value: str) -> bool:
    # OpaqueIdV1 is a single-line string of 1..256 UTF-8 bytes with no control characters.
    return (
        bool(value)
        and "\n" not in value
        and "\t" not in value
        and len(value.encode("utf-8")) <= 256
    )


def test_the_alert_key_is_deterministic_and_a_valid_opaque_id() -> None:
    first = derive_alert_key(
        rule_id="canary-rule", rule_version=1, collector="canary1", target="t1"
    )
    second = derive_alert_key(
        rule_id="canary-rule", rule_version=1, collector="canary1", target="t1"
    )
    assert first == second
    assert first.startswith("mh_ak1_")
    assert _is_opaque_id(first)


def test_the_alert_key_changes_with_any_component() -> None:
    base = derive_alert_key(rule_id="canary-rule", rule_version=1, collector="canary1", target="t1")
    assert base != derive_alert_key(
        rule_id="other-rule", rule_version=1, collector="canary1", target="t1"
    )
    assert base != derive_alert_key(
        rule_id="canary-rule", rule_version=2, collector="canary1", target="t1"
    )
    assert base != derive_alert_key(
        rule_id="canary-rule", rule_version=1, collector="canary2", target="t1"
    )
    assert base != derive_alert_key(
        rule_id="canary-rule", rule_version=1, collector="canary1", target="t2"
    )


def test_the_transition_id_is_deterministic_and_a_valid_opaque_id() -> None:
    key = derive_alert_key(rule_id="canary-rule", rule_version=1, collector="canary1", target="t1")
    obs = _observation()
    first = derive_transition_id(
        alert_key=key, previous_state="inactive", state="firing", triggering_observation=obs
    )
    second = derive_transition_id(
        alert_key=key, previous_state="inactive", state="firing", triggering_observation=obs
    )
    assert first == second
    assert first.startswith("mh_atr1_")
    assert _is_opaque_id(first)


def test_the_transition_id_distinguishes_the_edge_and_the_coordinate() -> None:
    key = derive_alert_key(rule_id="canary-rule", rule_version=1, collector="canary1", target="t1")
    firing = derive_transition_id(
        alert_key=key,
        previous_state="inactive",
        state="firing",
        triggering_observation=_observation(state="firing"),
    )
    refire = derive_transition_id(
        alert_key=key,
        previous_state="resolved",
        state="firing",
        triggering_observation=_observation(
            state="firing", scheduled_at="2026-07-21T15:05:00.000Z"
        ),
    )
    assert firing != refire


@pytest.mark.parametrize("bad", ["", "with\nnewline", "a" * 257])
def test_a_malformed_alert_key_input_fails_closed(bad: str) -> None:
    with pytest.raises(IdentityError) as captured:
        derive_alert_key(rule_id=bad, rule_version=1, collector="canary1", target="t1")
    assert captured.value.code == "MH_IDENTITY_ALERT_INPUT"


@pytest.mark.parametrize("bad", [0, -1, True, "1"])
def test_a_malformed_rule_version_fails_closed(bad: object) -> None:
    with pytest.raises(IdentityError) as captured:
        derive_alert_key(rule_id="canary-rule", rule_version=bad, collector="canary1", target="t1")  # type: ignore[arg-type]
    assert captured.value.code == "MH_IDENTITY_ALERT_INPUT"


def test_a_malformed_transition_input_fails_closed() -> None:
    key = derive_alert_key(rule_id="canary-rule", rule_version=1, collector="canary1", target="t1")
    with pytest.raises(IdentityError):
        derive_transition_id(
            alert_key=key,
            previous_state="",
            state="firing",
            triggering_observation=_observation(),
        )
