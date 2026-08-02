"""Change-control guardrail for numbered plan amendments (amendment A07 / defect D08(A)).

Plan section 1 rule 3 requires a numbered plan amendment that changes a locked contract to record
its reason, alternatives, compatibility impact, migration impact, security impact, and revised
tests, and an ADR-ratifying amendment to be registered in the ADR index. D08(A) found amendment A07
ratified WITHOUT those fields and without ADR-index registration — an evidence-integrity defect.
Rather than match one amendment's wording, these tests rebuild the section-1 amendment register from
the plan and prove that any amendment using the change-control template records every required
field, so a future amendment cannot be ratified with a partial record even if reworded.
"""

from __future__ import annotations

import re
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
_PLAN = (_REPO / "docs/implementation-plan.md").read_text(encoding="utf-8")
_ADR_INDEX = (_REPO / "docs/adr/README.md").read_text(encoding="utf-8")

# The section-1 amendment register runs from the change-control rules to the product section.
_REGISTER_START = "The following rules apply during implementation:"
_REGISTER_END = "## 2. Product contract"

# A block using the change-control template announces itself with one of these distinctive labels;
# the brief process/deferral amendments (A01-A03) use none of them. Any block that trips a trigger
# must then carry every required field marker below.
_TEMPLATE_TRIGGERS = ("reason:", "alternatives considered:", "revised tests")

# Required change-control fields (plan section 1 rule 3), as case-insensitive markers.
# "compatibility" and "migration" both appear in the template's combined "Compatibility and
# migration:" field; the security field label is written either "Security:" or "Security impact:".
_REQUIRED_FIELDS: dict[str, str] = {
    "reason": r"reason:",
    "alternatives": r"alternatives considered:",
    "compatibility": r"compatibility",
    "migration": r"migration",
    "security": r"security(?: impact)?:",
    "revised tests": r"revised tests",
}

# Amendments ratified by (or amending) an ADR must be named in the ADR index README.
_ADR_RATIFIED_AMENDMENTS = ("A06", "A07")


def _register_section() -> str:
    start = _PLAN.index(_REGISTER_START)
    end = _PLAN.index(_REGISTER_END, start)
    return _PLAN[start:end]


def _amendment_blocks() -> dict[str, str]:
    """Return {amendment id: lowercased block text} for each section-1 register amendment block.

    Blocks are delimited by the "Process amendment A0N" / "Plan amendment A0N" headings that open a
    template amendment. A brief non-template amendment written inline after another (A03 follows
    A02) folds into the preceding block; that is fine, because only template amendments are checked.
    """

    blocks: dict[str, str] = {}
    parts = re.split(r"(?=(?:Process|Plan) amendment A0\d)", _register_section())
    for part in parts:
        match = re.match(r"(?:Process|Plan) amendment (A0\d)", part)
        if match is not None:
            blocks[match.group(1)] = part.lower()
    return blocks


def _missing_fields(block: str) -> list[str]:
    return [name for name, pattern in _REQUIRED_FIELDS.items() if re.search(pattern, block) is None]


def test_section_1_register_lists_the_expected_amendments() -> None:
    # Sanity anchor: the register must name every amendment through A07, so the guardrail below
    # cannot pass vacuously by the register having been emptied or renamed.
    section = _register_section().lower()
    for amendment in ("a01", "a02", "a03", "a04", "a05", "a06", "a07"):
        assert f"amendment {amendment}" in section, (
            f"{amendment} is missing from the section-1 amendment register"
        )


def test_every_template_amendment_records_all_change_control_fields() -> None:
    # Any amendment that uses the change-control template (trips a trigger) must record every
    # required field — this is what D08(A) proved A07 had skipped.
    blocks = _amendment_blocks()
    triggered = {
        amendment: block
        for amendment, block in blocks.items()
        if any(trigger in block for trigger in _TEMPLATE_TRIGGERS)
    }
    # A04, A05, A06, and A07 are the contract-change amendments that adopted the template.
    for expected in ("A04", "A05", "A06", "A07"):
        assert expected in triggered, f"{expected} no longer uses the change-control template"
    for amendment, block in triggered.items():
        missing = _missing_fields(block)
        assert not missing, f"amendment {amendment} omits change-control fields: {missing}"


def test_a07_records_every_required_change_control_field() -> None:
    # A direct, non-vacuous assertion for the amendment D08(A) flagged.
    block = _amendment_blocks()["A07"]
    missing = _missing_fields(block)
    assert not missing, f"A07 omits required change-control fields: {missing}"


def test_adr_ratified_amendments_are_registered_in_the_adr_index() -> None:
    # D08(A): "the ADR index does not mention A07". Every ADR-ratifying amendment must be named.
    for amendment in _ADR_RATIFIED_AMENDMENTS:
        assert amendment in _ADR_INDEX, f"{amendment} is not registered in the ADR index README"


def test_a07_is_bound_to_adr_0007_in_the_index() -> None:
    # A07 amends ADR 0007; the index must tie it to that ADR, not merely mention the id in passing.
    adr_0007_row = next(
        (line for line in _ADR_INDEX.splitlines() if "0007-privacy-identity" in line),
        "",
    )
    assert "A07" in adr_0007_row, "the ADR 0007 index row does not name the A07 addendum"
