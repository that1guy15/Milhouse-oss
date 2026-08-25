"""Unit tests for the ``CursorAdvanceV1`` post-commit sidecar validation (W07 increment 2b).

The sidecar has exactly two valid shapes -- a complete advance or a loss-only short-circuit -- and
its ``__post_init__`` fails closed on anything else. These tests pin every validation branch: the
high-water guard (checked in BOTH shapes), the loss-signal type guard, the "a loss carries no
advance instruction" guard, and the "an advance must be complete" guard.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from milhouse.outbox import CursorAdvanceV1, OutboxAckV1
from milhouse.outbox.errors import OutboxError
from milhouse.outbox.reader import OutboxLossSignal

_TS = datetime(2026, 1, 1, tzinfo=UTC)
_SHA = "0" * 64


def _loss() -> OutboxLossSignal:
    return OutboxLossSignal(
        code="MH_OUTBOX_LOSS_TRUNCATED",
        cursor_device=1,
        cursor_inode=2,
        cursor_offset=0,
        cursor_sha256=_SHA,
    )


def _ack() -> OutboxAckV1:
    return OutboxAckV1(
        producer_id="producer",
        file_device=1,
        file_inode=2,
        committed_offset=0,
        content_sha256=_SHA,
        acknowledged_at=_TS,
    )


def _advance_kwargs() -> dict[str, object]:
    return {
        "next_position": "pos",
        "ack_directory": "/tmp/.milhouse",
        "ack_filename": "outbox-ack.json",
        "ack": _ack(),
    }


# --- valid shapes -------------------------------------------------------------------------------


def test_valid_loss_only_sidecar_is_accepted() -> None:
    sidecar = CursorAdvanceV1(loss_signal=_loss())
    assert sidecar.loss_signal is not None
    assert sidecar.next_position is None
    assert sidecar.ack is None


def test_valid_advance_sidecar_is_accepted() -> None:
    sidecar = CursorAdvanceV1(**_advance_kwargs(), max_observed_sequence=3)
    assert sidecar.ack is not None
    assert sidecar.next_position == "pos"
    assert sidecar.loss_signal is None


def test_valid_advance_without_high_water_is_accepted() -> None:
    sidecar = CursorAdvanceV1(**_advance_kwargs())
    assert sidecar.max_observed_sequence is None


# --- the high-water guard (validated in BOTH shapes) --------------------------------------------


@pytest.mark.parametrize("bad", [-1, "x", 1.5])
def test_invalid_max_observed_sequence_raises_in_loss_shape(bad: object) -> None:
    with pytest.raises(OutboxError) as err:
        CursorAdvanceV1(loss_signal=_loss(), max_observed_sequence=bad)  # type: ignore[arg-type]
    assert err.value.code == "MH_OUTBOX_ADVANCE"


def test_invalid_max_observed_sequence_raises_in_advance_shape() -> None:
    with pytest.raises(OutboxError) as err:
        CursorAdvanceV1(**_advance_kwargs(), max_observed_sequence=-5)
    assert err.value.code == "MH_OUTBOX_ADVANCE"


# --- the loss-signal type guard and the "loss carries no advance" guard -------------------------


def test_non_loss_signal_object_raises() -> None:
    with pytest.raises(OutboxError) as err:
        CursorAdvanceV1(loss_signal="not-a-loss-signal")  # type: ignore[arg-type]
    assert err.value.code == "MH_OUTBOX_ADVANCE"


@pytest.mark.parametrize(
    "extra",
    [
        {"next_position": "pos"},
        {"ack": _ack()},
        {"ack_directory": "/tmp/.milhouse"},
        {"ack_filename": "outbox-ack.json"},
    ],
)
def test_loss_sidecar_carrying_an_advance_field_raises(extra: dict[str, object]) -> None:
    with pytest.raises(OutboxError) as err:
        CursorAdvanceV1(loss_signal=_loss(), **extra)  # type: ignore[arg-type]
    assert err.value.code == "MH_OUTBOX_ADVANCE"


# --- the "an advance must be complete" guard ----------------------------------------------------


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("next_position", None),
        ("next_position", ""),
        ("ack_directory", None),
        ("ack_directory", ""),
        ("ack_filename", None),
        ("ack_filename", ""),
        ("ack", None),
    ],
)
def test_incomplete_advance_raises(field: str, value: object) -> None:
    kwargs = _advance_kwargs()
    kwargs[field] = value
    with pytest.raises(OutboxError) as err:
        CursorAdvanceV1(**kwargs)  # type: ignore[arg-type]
    assert err.value.code == "MH_OUTBOX_ADVANCE"


def test_empty_sidecar_is_neither_a_valid_loss_nor_advance() -> None:
    with pytest.raises(OutboxError) as err:
        CursorAdvanceV1()
    assert err.value.code == "MH_OUTBOX_ADVANCE"
