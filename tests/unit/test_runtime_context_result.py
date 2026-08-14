"""Validation of the per-run collector context and result value objects (W05).

Both are frozen and validated on construction so a collector receives, and returns, only well-formed
non-sensitive data. Every rejection is a fixed ``PipelineError`` code.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone

import pytest
from _record_factories import INSTALLATION_ID, NOW, event_record
from _runtime_harness import make_redactor

from milhouse.domain.records import CollectorDescriptorV1, TargetDescriptorV1
from milhouse.runtime import CollectorContext, CollectorResult
from milhouse.runtime.errors import PipelineError

_COLLECTOR = CollectorDescriptorV1(id="canary1", type="site.canary", implementation_version="1.0.0")
_TARGET = TargetDescriptorV1(id="t1", name="Example", kind="web_service", environment="test")


def _context(**overrides: object) -> CollectorContext:
    values: dict[str, object] = {
        "now": NOW,
        "installation_id": INSTALLATION_ID,
        "collector": _COLLECTOR,
        "target": _TARGET,
        "request_timeout_seconds": 30,
        "redactor": make_redactor(),
    }
    values.update(overrides)
    return CollectorContext(**values)  # type: ignore[arg-type]


# --- context -----------------------------------------------------------------------------------


def test_a_valid_context_normalizes_and_freezes() -> None:
    context = _context()
    assert context.now == NOW
    assert context.installation_id == INSTALLATION_ID
    with pytest.raises(AttributeError):
        context.request_timeout_seconds = 5  # type: ignore[misc]


def test_a_naive_run_instant_fails_closed() -> None:
    with pytest.raises(PipelineError) as caught:
        _context(now=datetime(2026, 7, 21, 15, 0))  # no tzinfo
    assert caught.value.code == "MH_RUNTIME_CONTEXT_NOW"


def test_a_non_utc_run_instant_is_normalized_to_utc() -> None:
    # A genuinely offset-aware instant (+05:00) is accepted and CONVERTED to canonical UTC: the same
    # instant, but the wall-clock hour actually changes (20:00+05:00 -> 15:00Z) and tzinfo is UTC.
    aware = datetime(2026, 7, 21, 20, 0, tzinfo=timezone(timedelta(hours=5)))
    context = _context(now=aware)
    assert context.now == aware  # the same absolute instant is preserved ...
    assert context.now == datetime(2026, 7, 21, 15, 0, tzinfo=UTC)  # ... normalized to UTC
    assert context.now.tzinfo == UTC
    assert context.now.hour == 15  # the offset conversion changed the wall-clock hour


def test_a_malformed_installation_id_fails_closed() -> None:
    with pytest.raises(PipelineError) as caught:
        _context(installation_id="not-an-installation")
    assert caught.value.code == "MH_RUNTIME_CONTEXT_INSTALLATION"


def test_a_missing_collector_descriptor_fails_closed() -> None:
    with pytest.raises(PipelineError) as caught:
        _context(collector=object())
    assert caught.value.code == "MH_RUNTIME_CONTEXT_COLLECTOR"


def test_an_invalid_target_fails_closed() -> None:
    with pytest.raises(PipelineError) as caught:
        _context(target=object())
    assert caught.value.code == "MH_RUNTIME_CONTEXT_TARGET"


def test_an_installation_scoped_context_allows_no_target() -> None:
    assert _context(target=None).target is None


def test_an_out_of_range_timeout_fails_closed() -> None:
    for bad in (0, 301, True):
        with pytest.raises(PipelineError) as caught:
            _context(request_timeout_seconds=bad)
        assert caught.value.code == "MH_RUNTIME_CONTEXT_TIMEOUT"


def test_a_non_redactor_handle_fails_closed() -> None:
    with pytest.raises(PipelineError) as caught:
        _context(redactor=object())
    assert caught.value.code == "MH_RUNTIME_CONTEXT_REDACTOR"


# --- result ------------------------------------------------------------------------------------


def test_a_valid_result_freezes_its_diagnostics() -> None:
    result = CollectorResult(status="ok", drafts=(event_record(),), diagnostics={"samples": 1})
    assert result.status == "ok"
    assert result.diagnostics == {"samples": 1}
    with pytest.raises(TypeError):
        result.diagnostics["samples"] = 2  # type: ignore[index]


def test_an_invalid_status_fails_closed() -> None:
    with pytest.raises(PipelineError) as caught:
        CollectorResult(status="weird")  # type: ignore[arg-type]
    assert caught.value.code == "MH_RUNTIME_RESULT_STATUS"


def test_non_draft_entries_fail_closed() -> None:
    with pytest.raises(PipelineError) as caught:
        CollectorResult(status="ok", drafts=(object(),))  # type: ignore[arg-type]
    assert caught.value.code == "MH_RUNTIME_RESULT_DRAFTS"


def test_a_non_tuple_drafts_collection_fails_closed() -> None:
    with pytest.raises(PipelineError) as caught:
        CollectorResult(status="ok", drafts=[event_record()])  # type: ignore[arg-type]
    assert caught.value.code == "MH_RUNTIME_RESULT_DRAFTS"


def test_a_non_machine_diagnostic_key_fails_closed() -> None:
    with pytest.raises(PipelineError) as caught:
        CollectorResult(status="ok", diagnostics={"Not A Key": 1})
    assert caught.value.code == "MH_RUNTIME_RESULT_DIAGNOSTICS"


def test_a_non_integer_diagnostic_value_fails_closed() -> None:
    for bad in ({"samples": "one"}, {"samples": -1}, {"flag": True}):
        with pytest.raises(PipelineError) as caught:
            CollectorResult(status="ok", diagnostics=bad)  # type: ignore[arg-type]
        assert caught.value.code == "MH_RUNTIME_RESULT_DIAGNOSTICS"


def test_a_non_mapping_diagnostics_collection_fails_closed() -> None:
    with pytest.raises(PipelineError) as caught:
        CollectorResult(status="ok", diagnostics=[("samples", 1)])  # type: ignore[arg-type]
    assert caught.value.code == "MH_RUNTIME_RESULT_DIAGNOSTICS"
