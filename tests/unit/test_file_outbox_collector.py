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
    _redact_attributes,
    build_collector,
    register_file_outbox,
)
from milhouse.config._models import FileOutboxCollector as FileOutboxConfig
from milhouse.privacy.pseudonym import Pseudonymizer
from milhouse.privacy.redact import LayeredRedactor
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


def test_redaction_replaces_identifiers_but_only_sanitizes_a_url() -> None:
    """Pin the redaction contract the collector documents, class by class.

    An email, a local path, and a known secret are REPLACED by an opaque marker. A URL is only
    SANITIZED -- credentials and query string stripped, scheme/host/path preserved -- because an
    observability record has to say which endpoint was involved. That asymmetry is deliberate and
    load-bearing (a producer's internal host name does reach durable storage), so it is pinned here
    rather than left to a docstring that can drift away from the redactor.
    """

    redactor = LayeredRedactor(Pseudonymizer(key=b"k" * 32))
    attributes = {
        "mail": "page ops@example.com now",
        "endpoint": "https://user:secret@api.internal.example.com/v2/pay?token=abc&page=2",
        "file": "see /var/lib/example/notes.txt",
        "count": 7,
    }

    redacted = _redact_attributes(attributes, redactor=redactor)

    # Replaced outright: the original value is gone.
    assert "ops@example.com" not in redacted["mail"]
    assert "[email:" in redacted["mail"]
    assert "/var/lib/example/notes.txt" not in redacted["file"]
    assert "local-path:" in redacted["file"]

    # Sanitized, not replaced: credentials and query are stripped, the endpoint survives.
    endpoint = redacted["endpoint"]
    assert "secret" not in endpoint
    assert "token=abc" not in endpoint
    assert endpoint == "https://api.internal.example.com/v2/pay"

    # Non-string scalars pass through untouched.
    assert redacted["count"] == 7
