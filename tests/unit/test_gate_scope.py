"""Gate-to-dependency consistency: G02 must not own a surface a dependency-blocked package owns.

Per plan section 4.15, the concrete report, structured-log file, and CLI/stderr/diagnostics surfaces
are owned by later work packages (W09, W03, W06) whose gates depend on G02. A G02 assertion that
required one of those concrete surfaces would create a gate cycle. These tests lock the
owner-approved amendment A04 re-scope so the regression cannot silently return.
"""

from __future__ import annotations

from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]

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
    plan = (_REPO / "docs/implementation-plan.md").read_text(encoding="utf-8")
    start = plan.index("Gate G02:")
    return plan[start : plan.index("### W03", start)]


def _adr_0016_revised_validation() -> str:
    adr = (_REPO / "docs/adr/0016-local-structured-log-persistence.md").read_text(encoding="utf-8")
    start = adr.index("## Revised validation")
    return adr[start : adr.index("## Plan references", start)]


def test_g02_defers_each_dependency_blocked_surface_to_its_owning_gate() -> None:
    plan = _plan_g02_scope()
    adr = _adr_0016_revised_validation()
    for surface, gate in _DEFERRED_SURFACES.items():
        # the authoritative plan gate names the concrete surface and its owning gate
        assert surface in plan, f"plan G02 must name the deferred {surface!r}"
        assert gate in plan, f"plan G02 must defer {surface!r} to {gate}"
        # ADR 0016's revised validation must route that gate's evidence downstream too
        assert gate in adr, f"ADR 0016 revised validation must defer evidence to {gate}"


def test_g02_does_not_require_a_dependency_blocked_concrete_surface() -> None:
    scope = _plan_g02_scope()
    for forbidden in _FORBIDDEN_G02_REQUIREMENTS:
        assert forbidden not in scope, (
            "G02 must not require a concrete surface owned by a dependency-blocked package: "
            f"{forbidden!r}"
        )
