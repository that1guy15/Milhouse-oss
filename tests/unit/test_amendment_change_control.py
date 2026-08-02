"""Change-control guardrail for numbered plan amendments (amendment A07 / defects D08(A), D08).

Plan section 1 rule 3 requires a numbered amendment that changes a locked contract to record its
reason, alternatives, compatibility/migration impact, security impact, and revised tests, and an
ADR-ratified amendment to be registered against its ADR in the index. An earlier guard was vacuous —
it validated fields only for amendments that already contained a template phrase, capped IDs at one
digit, and hard-coded the amendment/ADR lists — so a fieldless, unregistered synthetic amendment
passed (D08). This guard is a PURE checker over the plan register and ADR index: it enumerates every
amendment dynamically (any width), classifies process amendments by an EXPLICIT allowlist, and
requires every contract-changing amendment to record every field and (when ADR-ratified) be named on
its ADR's index row. The checker is exercised against the real files (which must be clean) and
against adversarial synthetic inputs (which must be rejected), so an omission cannot pass silently.
"""

from __future__ import annotations

import re
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
_PLAN = (_REPO / "docs/implementation-plan.md").read_text(encoding="utf-8")
_ADR_INDEX = (_REPO / "docs/adr/README.md").read_text(encoding="utf-8")

_REGISTER_START = "The following rules apply during implementation:"
_REGISTER_END = "## 2. Product contract"

# EXPLICIT allowlist of amendments that change no locked contract and so are exempt from the field
# and index requirements. Membership is explicit (not inferred from whether a template happens to be
# present), so an amendment that omits the whole template is caught, not silently exempted. A01 is
# a process adaptation (ADR 0015) and A03 records a bounded historical DCO disposition (ADR 0017);
# neither introduces or changes a locked public, stored, lifecycle, or release contract. A test
# proves each exempt entry actually reads as a process/disposition amendment.
_PROCESS_EXEMPT = frozenset({"A01", "A03"})

# Required change-control fields (plan section 1 rule 3) as case-insensitive LABEL markers — the
# labels every compliant amendment uses, so a fieldless block that merely mentions "migration" or
# "security" in prose is not mistaken for a completed field. "Compatibility and migration:" is the
# template's combined label for the compatibility and migration impacts.
_REQUIRED_FIELDS: dict[str, str] = {
    "reason": r"\breason:",
    "alternatives considered": r"\balternatives considered:",
    "compatibility and migration": r"\bcompatibility and migration:",
    "security impact": r"\bsecurity(?: impact)?:",
    "revised tests": r"\brevised tests\b",
}

# An amendment ratified by (or amending) an ADR. Captures the four-digit ADR number.
_ADR_RATIFIED = re.compile(r"ratified by (?:an?\s+)?adr\s+(\d{4})", re.IGNORECASE)
# Every amendment reference of any width. The first occurrence of an id opens its block.
_AMENDMENT_REF = re.compile(r"(?:process |plan )?amendment (A\d+)", re.IGNORECASE)


def _register(plan_text: str) -> str:
    start = plan_text.index(_REGISTER_START)
    end = plan_text.index(_REGISTER_END, start)
    return plan_text[start:end]


def _amendment_blocks(register: str) -> dict[str, str]:
    """Return {amendment id: block text}, the block running from an id's first reference to the next
    reference of a DIFFERENT amendment (or the register end)."""

    spans = [(m.start(), m.group(1)) for m in _AMENDMENT_REF.finditer(register)]
    blocks: dict[str, str] = {}
    for index, (start, aid) in enumerate(spans):
        if aid in blocks:
            continue
        end = len(register)
        for next_start, next_id in spans[index + 1 :]:
            if next_id != aid:
                end = next_start
                break
        blocks[aid] = register[start:end]
    return blocks


def evaluate(plan_text: str, adr_index_text: str) -> list[str]:
    """Return every change-control violation in the register/index (empty == compliant).

    A contract-changing amendment (any id not in the explicit process allowlist) must record every
    required field; and when its block declares ADR ratification, the id must appear on that
    ADR's own index row (the line linking the ADR file), so a missing/wrong-ADR registration fails.
    """

    blocks = _amendment_blocks(_register(plan_text))
    index_lines = adr_index_text.splitlines()
    violations: list[str] = []
    for aid, block in sorted(blocks.items()):
        if aid in _PROCESS_EXEMPT:
            continue
        low = block.lower()
        missing = [name for name, pat in _REQUIRED_FIELDS.items() if re.search(pat, low) is None]
        if missing:
            violations.append(f"{aid} omits change-control fields: {missing}")
        ratified = _ADR_RATIFIED.search(block)
        if ratified is not None:
            adr = ratified.group(1)
            row = next((line for line in index_lines if f"{adr}-" in line), "")
            if aid not in row:
                violations.append(f"{aid} is not registered on ADR {adr}'s index row")
    return violations


# --- The real register/index must be clean --------------------------------------------------------


def test_the_real_register_and_index_are_compliant() -> None:
    assert evaluate(_PLAN, _ADR_INDEX) == []


def test_every_expected_amendment_is_enumerated() -> None:
    blocks = _amendment_blocks(_register(_PLAN))
    for amendment in ("A01", "A02", "A03", "A04", "A05", "A06", "A07"):
        assert amendment in blocks, f"{amendment} is not enumerated from the section-1 register"


def test_the_process_allowlist_reads_as_process_or_disposition() -> None:
    # The exempt set must be genuinely non-contract, not a convenient escape hatch.
    blocks = _amendment_blocks(_register(_PLAN))
    signals = ("process ", "disposition", "without changing", "changes no", "without weakening")
    for amendment in _PROCESS_EXEMPT:
        block = blocks[amendment].lower()
        assert any(signal in block for signal in signals), (
            f"{amendment} is exempt but does not read as a process/disposition amendment"
        )


# --- Adversarial synthetic inputs must be rejected ------------------------------------------------

_ALL_FIELDS = (
    "Reason: it changes a locked contract. Alternatives considered: none. "
    "Compatibility and migration: none. Security impact: none. Revised tests: a lock test."
)


def _synth_plan(amendment: str) -> str:
    return f"{_REGISTER_START}\nrules.\n\n{amendment}\n\n{_REGISTER_END}\nproduct.\n"


def _index_with(row: str) -> str:
    return f"# index\n\n| ADR | Ratified decision |\n|---|---|\n{row}\n"


def test_a_fieldless_contract_amendment_is_rejected() -> None:
    plan = _synth_plan(
        "Plan amendment A08, approved by the owner, changes a locked storage contract."
    )
    violations = evaluate(plan, _ADR_INDEX)
    assert any("A08" in v and "fields" in v for v in violations), violations


def test_each_required_field_missing_individually_is_rejected() -> None:
    for dropped in _REQUIRED_FIELDS:
        kept = "; ".join(f"{name}: ok" for name in _REQUIRED_FIELDS if name != dropped)
        plan = _synth_plan(
            f"Plan amendment A08, approved by the owner, changes a contract. {kept}."
        )
        violations = evaluate(plan, _ADR_INDEX)
        assert any("A08" in v and "fields" in v for v in violations), (
            f"dropping {dropped!r} was not rejected: {violations}"
        )


def test_a_multi_digit_amendment_id_is_enumerated_and_checked() -> None:
    plan = _synth_plan("Plan amendment A10, approved by the owner, changes a locked contract.")
    blocks = _amendment_blocks(_register(plan))
    assert "A10" in blocks  # no one-digit ceiling
    assert any("A10" in v for v in evaluate(plan, _ADR_INDEX))


def test_a_missing_adr_index_registration_is_rejected() -> None:
    amendment = f"Plan amendment A08, ratified by ADR 0099, changes a contract. {_ALL_FIELDS}"
    index = _index_with("| [0099](0099-thing.md) | A thing with no amendment named |")
    violations = evaluate(_synth_plan(amendment), index)
    assert any("A08" in v and "0099" in v for v in violations), violations


def test_a_wrong_adr_registration_is_rejected() -> None:
    # A08 declares ADR 0099 but is named only on ADR 0088's row: the 0099 row must still fail.
    amendment = f"Plan amendment A08, ratified by ADR 0099, changes a contract. {_ALL_FIELDS}"
    index = _index_with(
        "| [0088](0088-other.md) | Other (amendment A08) |\n| [0099](0099-thing.md) | A thing |"
    )
    violations = evaluate(_synth_plan(amendment), index)
    assert any("A08" in v and "0099" in v for v in violations), violations


def test_a_complete_registered_contract_amendment_passes() -> None:
    amendment = f"Plan amendment A08, ratified by ADR 0099, changes a contract. {_ALL_FIELDS}"
    index = _index_with("| [0099](0099-thing.md) | A thing (amendment A08) |")
    assert evaluate(_synth_plan(amendment), index) == []
