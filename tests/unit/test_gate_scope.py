"""Gate-to-dependency consistency: G02 must not own a surface a dependency-blocked package owns.

Per plan section 4.15, the concrete structured-log file, CLI/stderr/diagnostics, and
generated-report surfaces are owned by later work packages (W03, W06, W09) whose gates
transitively depend on G02. A G02 assertion that required one of those concrete surfaces would be a
gate cycle. Rather than only matching a phrase, these tests reconstruct the package dependency graph
from the status ledger and prove each deferred gate transitively depends on G02, so the
owner-approved amendment A04 re-scope cannot silently regress even if the wording is reworded.
"""

from __future__ import annotations

import re
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
_PLAN = (_REPO / "docs/implementation-plan.md").read_text(encoding="utf-8")
_ADR = (_REPO / "docs/adr/0016-local-structured-log-persistence.md").read_text(encoding="utf-8")
_STATUS = (_REPO / "docs/implementation-status.md").read_text(encoding="utf-8")

# Concrete surface phrase -> the gate that must validate it, per section 4.15 (amendment A04).
_DEFERRED_SURFACES = {
    "structured-log file surface": "G03",
    "diagnostics bundle": "G06",
    "generated-report surface": "G09",
}

# Pre-correction G02 wordings that required a dependency-blocked concrete surface at G02.
_FORBIDDEN_G02_REQUIREMENTS = (
    "tool output to files, stderr",
    "secret values never appear in exceptions, logs, CLI, records, reports, or diagnostics",
)


def _plan_g02_scope() -> str:
    start = _PLAN.index("Gate G02:")
    return _PLAN[start : _PLAN.index("### W03", start)]


def _adr_revised_validation() -> str:
    start = _ADR.index("## Revised validation")
    return _ADR[start : _ADR.index("## Amendment A05", start)]


def _gate_prerequisites() -> dict[str, set[str]]:
    """Map each package gate G0N (produced by package W0N) to the gates in its dependency cell."""

    prerequisites: dict[str, set[str]] = {}
    for match in re.finditer(r"^\| W(\d{2}) [^|]*\|([^|]*)\|", _STATUS, flags=re.MULTILINE):
        gate = f"G{match.group(1)}"
        prerequisites[gate] = set(re.findall(r"G\d{2}", match.group(2)))
    return prerequisites


def _transitive_prerequisites(gate: str, graph: dict[str, set[str]]) -> set[str]:
    seen: set[str] = set()
    stack = list(graph.get(gate, set()))
    while stack:
        current = stack.pop()
        if current in seen:
            continue
        seen.add(current)
        stack.extend(graph.get(current, set()))
    return seen


def test_each_deferred_gate_transitively_depends_on_g02_so_requiring_it_would_cycle() -> None:
    graph = _gate_prerequisites()
    assert graph.get("G02") == {"G01"}, "the status graph must show G02 depends on G01"
    for surface, gate in _DEFERRED_SURFACES.items():
        assert gate in graph, f"the status package table must define {gate} (for {surface!r})"
        closure = _transitive_prerequisites(gate, graph)
        assert "G02" in closure, (
            f"{gate} must transitively depend on G02 for deferring the {surface!r} to avoid a real "
            f"gate cycle; its dependency closure was {sorted(closure)}"
        )


def test_plan_and_adr_defer_each_surface_to_its_owning_gate() -> None:
    plan = _plan_g02_scope()
    adr = _adr_revised_validation()
    for surface, gate in _DEFERRED_SURFACES.items():
        assert surface in plan, f"plan G02 must name the deferred {surface!r}"
        assert gate in plan, f"plan G02 must defer {surface!r} to {gate}"
        assert gate in adr, f"ADR 0016 revised validation must defer {surface!r} evidence to {gate}"


def test_g02_does_not_require_a_dependency_blocked_concrete_surface() -> None:
    scope = _plan_g02_scope()
    for forbidden in _FORBIDDEN_G02_REQUIREMENTS:
        assert forbidden not in scope, (
            "G02 must not require a concrete surface owned by a dependency-blocked package: "
            f"{forbidden!r}"
        )


def test_correction_is_traceable_in_the_registers() -> None:
    # The re-scope is recorded as a numbered amendment in the plan section 1 register...
    assert "Plan amendment A04" in _PLAN, "plan section 1 must record amendment A04"
    # ...and both the D02 defect and the A04 amendment appear in the status register, so the
    # correction cannot be dropped without failing a test.
    assert re.search(r"^\| D02 \|", _STATUS, flags=re.MULTILINE), "status must record defect D02"
    assert re.search(r"^\| A04 \|", _STATUS, flags=re.MULTILINE), "status must record amendment A04"
