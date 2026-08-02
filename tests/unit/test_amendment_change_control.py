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

# An amendment ratified by (or amending) an ADR. Every match matters: one amendment may ratify
# multiple ADRs, and every associated ADR row must name it.
_ADR_RATIFIED = re.compile(r"ratified by (?:an?\s+)?adr\s+(\d{4})", re.IGNORECASE)
# A declaration starts either a register paragraph/line or a new sentence. Capturing the raw token
# lets the checker reject Markdown-styled or otherwise malformed identifiers instead of skipping
# them. Bare ``Amendment A03`` is retained for the historical register spelling.
_AMENDMENT_DECLARATION = re.compile(
    r"(?:^|(?<=\.\s))"
    r"(?P<kind>process amendment|plan amendment|amendment)\s+"
    r"(?P<token>\S+)",
    flags=re.IGNORECASE | re.MULTILINE,
)
_CANONICAL_ID = re.compile(r"A(?P<number>0[1-9]|[1-9][0-9]+),?", re.IGNORECASE)
_AMENDMENT_REFERENCE = re.compile(r"\bamendment\s+[*_`]*(?P<aid>A[1-9][0-9]*)[*_`]*", re.IGNORECASE)
_ADR_ROW = re.compile(
    r"^\|\s*\[(?P<adr>[0-9]{4})\]\([^)]+\)\s*\|(?P<decision>.*?)\|\s*$",
    flags=re.MULTILINE,
)

# Process exemptions are integrity-bound to the approved declaration, not merely to an identifier.
# A duplicate/reused id is rejected separately before this exemption can apply.
_PROCESS_EXEMPT_DECLARATIONS: dict[str, tuple[str, str]] = {
    "A01": ("process amendment", "establishes the agent engineering workflow"),
    "A03": ("amendment", "records the exact bounded historical dco disposition"),
}


def _register(plan_text: str) -> str:
    start = plan_text.index(_REGISTER_START)
    end = plan_text.index(_REGISTER_END, start)
    return plan_text[start:end]


def _declarations(register: str) -> tuple[list[tuple[str, str, str]], list[str]]:
    """Return canonical ``(id, kind, block)`` declarations and malformed-id violations."""

    matches = list(_AMENDMENT_DECLARATION.finditer(register))
    declarations: list[tuple[str, str, str]] = []
    violations: list[str] = []
    for index, match in enumerate(matches):
        token = match.group("token")
        canonical = _CANONICAL_ID.fullmatch(token)
        if canonical is None:
            referenced = re.search(r"A[0-9]+", token, flags=re.IGNORECASE)
            subject = referenced.group(0).upper() if referenced is not None else token
            violations.append(f"{subject} has a malformed amendment identifier token {token!r}")
            continue
        aid = f"A{int(canonical.group('number')):02d}"
        start = match.start("kind")
        end = matches[index + 1].start("kind") if index + 1 < len(matches) else len(register)
        declarations.append((aid, match.group("kind").lower(), register[start:end]))
    return declarations, violations


def _amendment_blocks(register: str) -> dict[str, str]:
    """Return the first canonical block for each declared amendment id."""

    declarations, _ = _declarations(register)
    blocks: dict[str, str] = {}
    for aid, _kind, block in declarations:
        blocks.setdefault(aid, block)
    return blocks


def _adr_rows(index_text: str) -> tuple[dict[str, str], list[str]]:
    """Parse the ADR Markdown table structurally and reject duplicate ADR rows."""

    grouped: dict[str, list[str]] = {}
    for match in _ADR_ROW.finditer(index_text):
        grouped.setdefault(match.group("adr"), []).append(match.group("decision"))
    violations = [
        f"ADR {adr} has duplicate index rows" for adr, rows in grouped.items() if len(rows) > 1
    ]
    return {adr: rows[0] for adr, rows in grouped.items()}, violations


def evaluate(plan_text: str, adr_index_text: str) -> list[str]:
    """Return every change-control violation in the register/index (empty == compliant).

    A contract-changing amendment (any id not in the explicit process allowlist) must record every
    required field; and when its block declares ADR ratification, the id must appear on that
    ADR's own index row (the line linking the ADR file), so a missing/wrong-ADR registration fails.
    """

    register = _register(plan_text)
    declarations, violations = _declarations(register)
    rows, row_violations = _adr_rows(adr_index_text)
    violations.extend(row_violations)

    counts: dict[str, int] = {}
    for aid, _kind, _block in declarations:
        counts[aid] = counts.get(aid, 0) + 1
    for aid, count in sorted(counts.items()):
        if count > 1:
            violations.append(f"{aid} has duplicate amendment declarations")

    ordered = [int(aid[1:]) for aid, _kind, _block in declarations]
    unique_ordered = list(dict.fromkeys(ordered))
    if unique_ordered != sorted(unique_ordered):
        violations.append("amendment sequence is out of order")
    if len(unique_ordered) > 1 and sorted(unique_ordered) != list(
        range(min(unique_ordered), max(unique_ordered) + 1)
    ):
        violations.append("amendment sequence contains an unexpected gap")

    declared_ids = set(counts)
    for reference in _AMENDMENT_REFERENCE.finditer(register):
        aid = f"A{int(reference.group('aid')[1:]):02d}"
        if aid not in declared_ids:
            violations.append(f"{aid} reference has no canonical amendment declaration")

    first: dict[str, tuple[str, str]] = {}
    for aid, kind, block in declarations:
        first.setdefault(aid, (kind, block))
    for aid, (kind, block) in sorted(first.items()):
        exempt = _PROCESS_EXEMPT_DECLARATIONS.get(aid)
        if exempt is not None:
            expected_kind, required_text = exempt
            normalized_block = " ".join(block.lower().split())
            if counts[aid] != 1 or kind != expected_kind or required_text not in normalized_block:
                violations.append(
                    f"{aid} does not match its approved process-exemption declaration"
                )
            continue
        low = block.lower()
        missing = [name for name, pat in _REQUIRED_FIELDS.items() if re.search(pat, low) is None]
        if missing:
            violations.append(f"{aid} omits change-control fields: {missing}")
        ratified_adrs = {match.group(1) for match in _ADR_RATIFIED.finditer(block)}
        for adr in sorted(ratified_adrs):
            decision = rows.get(adr)
            if decision is None or re.search(rf"\b{re.escape(aid)}\b", decision) is None:
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
    for amendment in _PROCESS_EXEMPT_DECLARATIONS:
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


def test_a_styled_amendment_id_is_rejected_instead_of_skipped() -> None:
    plan = _synth_plan("Plan amendment **A08**, approved by the owner, changes a locked contract.")
    violations = evaluate(plan, _ADR_INDEX)
    assert any("A08" in v and "identifier" in v for v in violations), violations


def test_a_reused_process_exemption_is_rejected() -> None:
    plan = _synth_plan(
        "Process amendment A01, approved by the owner, changes no locked contract. "
        "Reason: process only. Amendment A01, approved by the owner, changes a locked "
        "storage contract."
    )
    violations = evaluate(plan, _ADR_INDEX)
    assert any("A01" in v and "duplicate" in v for v in violations), violations


def test_out_of_order_or_gapped_amendment_declarations_are_rejected() -> None:
    plan = _synth_plan(
        f"Plan amendment A02, approved by the owner, changes a contract. {_ALL_FIELDS} "
        f"Plan amendment A04, approved by the owner, changes a contract. {_ALL_FIELDS}"
    )
    violations = evaluate(plan, _ADR_INDEX)
    assert any("sequence" in v for v in violations), violations


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


def test_prose_outside_the_adr_table_cannot_satisfy_registration() -> None:
    amendment = f"Plan amendment A08, ratified by ADR 0099, changes a contract. {_ALL_FIELDS}"
    index = (
        "# index\n\nADR [0099](0099-thing.md) ratifies amendment A08.\n\n"
        "| ADR | Ratified decision |\n|---|---|\n"
        "| [0099](0099-thing.md) | A thing with no amendment named |\n"
    )
    violations = evaluate(_synth_plan(amendment), index)
    assert any("A08" in v and "0099" in v for v in violations), violations


def test_every_declared_adr_ratification_requires_its_own_row_binding() -> None:
    amendment = (
        f"Plan amendment A08, ratified by ADR 0099 and ratified by ADR 0088, "
        f"changes a contract. {_ALL_FIELDS}"
    )
    index = _index_with(
        "| [0099](0099-thing.md) | A thing (amendment A08) |\n"
        "| [0088](0088-other.md) | Other decision |"
    )
    violations = evaluate(_synth_plan(amendment), index)
    assert any("A08" in v and "0088" in v for v in violations), violations


def test_duplicate_adr_rows_are_rejected() -> None:
    amendment = f"Plan amendment A08, ratified by ADR 0099, changes a contract. {_ALL_FIELDS}"
    index = _index_with(
        "| [0099](0099-thing.md) | A thing (amendment A08) |\n"
        "| [0099](0099-copy.md) | A duplicate (amendment A08) |"
    )
    violations = evaluate(_synth_plan(amendment), index)
    assert any("0099" in v and "duplicate" in v for v in violations), violations


def test_an_adr_addendum_ratification_is_structurally_bound() -> None:
    amendment = (
        f"Plan amendment A08, ratified by an ADR 0099 addendum, changes a contract. {_ALL_FIELDS}"
    )
    missing = evaluate(_synth_plan(amendment), _index_with("| [0099](0099-thing.md) | A thing |"))
    assert any("A08" in violation and "0099" in violation for violation in missing), missing
    registered = _index_with("| [0099](0099-thing.md) | A thing (amendment A08) |")
    assert evaluate(_synth_plan(amendment), registered) == []


def test_a_complete_registered_contract_amendment_passes() -> None:
    amendment = f"Plan amendment A08, ratified by ADR 0099, changes a contract. {_ALL_FIELDS}"
    index = _index_with("| [0099](0099-thing.md) | A thing (amendment A08) |")
    assert evaluate(_synth_plan(amendment), index) == []
