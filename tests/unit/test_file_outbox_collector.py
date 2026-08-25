"""Unit tests for the ``file_outbox`` collector's construction, factory, and helper guards (W07).

These pin the fail-closed paths the end-to-end pipeline tests do not exercise: the constructor's
config-type guard, the monotonic rotation-high-water fold, and the registry factory's "no resolved
path bound for this collector" guard.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from milhouse.collectors.errors import CollectorError
from milhouse.collectors.file_outbox import (
    _fold_high_water,
    build_collector,
    register_file_outbox,
)
from milhouse.config._models import FileOutboxCollector as FileOutboxConfig
from milhouse.runtime import CollectorRegistry


def _config(collector_id: str = "app-outbox") -> FileOutboxConfig:
    return FileOutboxConfig.model_validate(
        {
            "id": collector_id,
            "target": "t1",
            "type": "file_outbox",
            "path": "feedback-outbox.jsonl",
            "producer_allowlist": [],
            "ack_filename": "outbox-ack.json",
        }
    )


def test_build_collector_rejects_a_non_file_outbox_config() -> None:
    with pytest.raises(CollectorError) as err:
        build_collector(
            object(),  # type: ignore[arg-type]
            outbox_path=Path("/tmp/.milhouse/feedback-outbox.jsonl"),
            ack_directory=Path("/tmp/.milhouse"),
        )
    assert err.value.code == "MH_COLLECTOR_CONFIG"


@pytest.mark.parametrize(
    ("prior", "observed", "expected"),
    [
        (None, None, None),
        (None, 5, 5),
        (5, None, 5),
        (3, 7, 7),
        (7, 3, 7),
    ],
)
def test_fold_high_water_is_monotonic(
    prior: int | None, observed: int | None, expected: int | None
) -> None:
    assert _fold_high_water(prior, observed) == expected


def test_register_file_outbox_factory_rejects_an_unbound_collector() -> None:
    registry = CollectorRegistry()
    register_file_outbox(registry, outbox_paths={})  # no bindings resolved
    with pytest.raises(CollectorError) as err:
        registry.resolve(_config("not-bound"))
    assert err.value.code == "MH_COLLECTOR_CONFIG"
