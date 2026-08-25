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

import html
import re
import unicodedata
from pathlib import Path

import pytest

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

# Required change-control fields (plan section 1 rule 3) in their canonical order. Presence alone is
# insufficient: each label must occur exactly once, in order, and own a non-empty bounded value up
# to the next label/block boundary. That prevents ``Reason: Alternatives considered: ...`` from
# certifying a content-free amendment.
_REQUIRED_FIELDS: tuple[tuple[str, str], ...] = (
    ("reason", r"\breason\s*:"),
    ("alternatives considered", r"\balternatives considered\s*:"),
    ("compatibility and migration", r"\bcompatibility and migration\s*:"),
    ("security impact", r"\bsecurity(?: impact)?\s*:"),
    ("revised tests", r"\brevised tests\s*:"),
)
_FIELD_LABEL = re.compile(
    "|".join(f"(?P<f{index}>{pattern})" for index, (_name, pattern) in enumerate(_REQUIRED_FIELDS)),
    flags=re.IGNORECASE,
)
_MAX_FIELD_VALUE_CHARS = 20_000

# An amendment ratified by (or amending) an ADR. Every match matters: one amendment may ratify
# multiple ADRs, and every associated ADR row must name it.
_ADR_RATIFIED = re.compile(r"ratified by (?:an?\s+)?adr\s+(\d{4})", re.IGNORECASE)
# The register uses one machine-checkable declaration per Markdown paragraph. A declaration is
# canonical only when its raw paragraph starts with one of these literal phrases and ASCII
# whitespace before the identifier. Markdown links/emphasis, HTML/comments, blockquotes, list or
# heading prefixes, Unicode whitespace, and any other wrapper therefore cannot silently normalize
# into authority: the broader paragraph classifier below treats every A-ID-bearing register
# paragraph as declaration-shaped and rejects it unless the raw paragraph is canonical.
_AMENDMENT_DECLARATION = re.compile(
    r"^(?P<kind>process amendment|plan amendment|amendment)[ \t\r\n]+(?P<token>\S+)",
    flags=re.IGNORECASE,
)
_CANONICAL_ID = re.compile(r"A(?P<number>0[1-9]|[1-9][0-9]+),?")
_AMENDMENT_ID_LIKE = re.compile(r"(?<![A-Za-z0-9])A[0-9]+", re.IGNORECASE)
_HTML_COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)
_HTML_TAG = re.compile(r"</?[A-Za-z][^>]*>")
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

    declarations: list[tuple[str, str, str]] = []
    violations: list[str] = []
    # ASCII-only blank-line splitting is deliberate: a Unicode-whitespace separator cannot hide a
    # second declaration; it leaves both A-IDs in one paragraph and the exact-one check rejects it.
    paragraphs = re.split(r"(?:\r?\n[ \t]*){2,}", register)
    for paragraph in paragraphs:
        # Classification happens on a conservative rendered-text approximation BEFORE canonical
        # raw parsing. HTML comments cannot split a token, character references are decoded, HTML
        # tags are removed, and NFKC exposes compatibility/confusable forms such as full-width
        # A/0/8.
        # This view is used only to decide that a paragraph MUST be rejected or parsed; it can never
        # make a malformed raw declaration authoritative.
        rendered = _HTML_COMMENT.sub("", paragraph)
        rendered = html.unescape(rendered)
        rendered = _HTML_TAG.sub("", rendered)
        rendered = unicodedata.normalize("NFKC", rendered)
        ids = _AMENDMENT_ID_LIKE.findall(rendered)
        # Any rendered A-ID or amendment-shaped register paragraph must be one raw canonical
        # declaration. A malformed/confusable declaration therefore becomes a violation instead of
        # disappearing at an ASCII-only early continue.
        rendered_declaration = _AMENDMENT_DECLARATION.match(rendered)
        if not ids and rendered_declaration is None:
            continue
        match = _AMENDMENT_DECLARATION.match(paragraph)
        if match is None:
            aid = f"A{int(ids[0][1:]):02d}" if ids else "amendment"
            violations.append(
                f"{aid} has an amendment/A-ID paragraph that is not one canonical declaration"
            )
            continue
        unique_ids = {identifier.upper() for identifier in ids}
        if len(unique_ids) != 1:
            aid = f"A{int(ids[0][1:]):02d}"
            violations.append(
                f"{aid} amendment paragraph must contain exactly one unique amendment identifier"
            )
            continue
        token = match.group("token")
        canonical = _CANONICAL_ID.fullmatch(token)
        if canonical is None:
            referenced = re.search(r"A[0-9]+", token, flags=re.IGNORECASE)
            subject = referenced.group(0).upper() if referenced is not None else token
            violations.append(f"{subject} has a malformed amendment identifier token {token!r}")
            continue
        aid = f"A{int(canonical.group('number')):02d}"
        declarations.append((aid, match.group("kind").lower(), paragraph))
    return declarations, violations


def _field_violations(aid: str, block: str) -> list[str]:
    """Validate one contract amendment's exact field structure and substantive values."""

    matches = list(_FIELD_LABEL.finditer(block))
    observed: list[str] = []
    violations: list[str] = []
    for match in matches:
        index = next(i for i in range(len(_REQUIRED_FIELDS)) if match.group(f"f{i}") is not None)
        observed.append(_REQUIRED_FIELDS[index][0])
    expected = [name for name, _pattern in _REQUIRED_FIELDS]
    if observed != expected:
        missing = [name for name in expected if name not in observed]
        violations.append(
            f"{aid} change-control fields have invalid order/count; "
            f"missing={missing}, observed={observed}"
        )
        return violations
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(block)
        value = block[match.end() : end].strip()
        name = expected[index]
        if not value or re.search(r"[A-Za-z0-9]", value, flags=re.ASCII) is None:
            violations.append(f"{aid} has an empty change-control field: {name}")
        elif len(value) > _MAX_FIELD_VALUE_CHARS:
            violations.append(f"{aid} has an overlong change-control field: {name}")
    return violations


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
        violations.extend(_field_violations(aid, block))
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
    for amendment in ("A01", "A02", "A03", "A04", "A05", "A06", "A07", "A08", "A09"):
        assert amendment in blocks, f"{amendment} is not enumerated from the section-1 register"


def test_each_real_amendment_maps_to_exactly_one_canonical_paragraph() -> None:
    declarations, violations = _declarations(_register(_PLAN))
    assert violations == []
    ids = [aid for aid, _kind, _block in declarations]
    assert ids == ["A01", "A02", "A03", "A04", "A05", "A06", "A07", "A08", "A09"]


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
    for dropped, _pattern in _REQUIRED_FIELDS:
        kept = "; ".join(f"{name}: ok" for name, _candidate in _REQUIRED_FIELDS if name != dropped)
        plan = _synth_plan(
            f"Plan amendment A08, approved by the owner, changes a contract. {kept}."
        )
        violations = evaluate(plan, _ADR_INDEX)
        assert any("A08" in v and "fields" in v for v in violations), (
            f"dropping {dropped!r} was not rejected: {violations}"
        )


def test_each_required_field_with_an_empty_value_is_rejected() -> None:
    for empty, _pattern in _REQUIRED_FIELDS:
        fields = " ".join(
            f"{name}: {'   ' if name == empty else 'substantive value.'}"
            for name, _candidate in _REQUIRED_FIELDS
        )
        plan = _synth_plan(
            f"Plan amendment A08, approved by the owner, changes a contract. {fields}"
        )
        violations = evaluate(plan, _ADR_INDEX)
        assert any("A08" in v and "empty" in v and empty in v for v in violations), (
            f"empty {empty!r} was not rejected: {violations}"
        )


def test_reordered_or_duplicated_field_labels_are_rejected() -> None:
    cases = (
        "Reason: value. Compatibility and migration: value. "
        "Alternatives considered: value. Security impact: value. Revised tests: value.",
        "Reason: value. Reason: duplicate. Alternatives considered: value. "
        "Compatibility and migration: value. Security impact: value. Revised tests: value.",
    )
    for fields in cases:
        plan = _synth_plan(
            f"Plan amendment A08, approved by the owner, changes a contract. {fields}"
        )
        violations = evaluate(plan, _ADR_INDEX)
        assert any("A08" in v and "order/count" in v for v in violations), violations


def test_an_overlong_field_value_is_rejected() -> None:
    overlong = "x" * (_MAX_FIELD_VALUE_CHARS + 1)
    plan = _synth_plan(
        "Plan amendment A08, approved by the owner, changes a contract. "
        f"Reason: {overlong} Alternatives considered: value. "
        "Compatibility and migration: value. Security impact: value. Revised tests: value."
    )
    violations = evaluate(plan, _ADR_INDEX)
    assert any("A08" in v and "overlong" in v and "reason" in v for v in violations), violations


def test_a_multi_digit_amendment_id_is_enumerated_and_checked() -> None:
    plan = _synth_plan("Plan amendment A10, approved by the owner, changes a locked contract.")
    blocks = _amendment_blocks(_register(plan))
    assert "A10" in blocks  # no one-digit ceiling
    assert any("A10" in v for v in evaluate(plan, _ADR_INDEX))


def test_a_styled_amendment_id_is_rejected_instead_of_skipped() -> None:
    plan = _synth_plan("Plan amendment **A08**, approved by the owner, changes a locked contract.")
    violations = evaluate(plan, _ADR_INDEX)
    assert any("A08" in v and ("not one canonical" in v or "malformed" in v) for v in violations), (
        violations
    )


def test_styled_heading_or_list_declarations_are_rejected_instead_of_hidden() -> None:
    cases = (
        f"**Plan amendment** A08, approved by the owner, changes a contract. {_ALL_FIELDS}",
        f"## Plan amendment A08, approved by the owner, changes a contract. {_ALL_FIELDS}",
        f"- Plan amendment A08, approved by the owner, changes a contract. {_ALL_FIELDS}",
    )
    for amendment in cases:
        violations = evaluate(_synth_plan(amendment), _ADR_INDEX)
        assert any("A08" in v and "not one canonical declaration" in v for v in violations), (
            amendment,
            violations,
        )


@pytest.mark.parametrize(
    "amendment",
    (
        "[Plan amendment](https://example.invalid/policy) A08, changes a contract.",
        "`[Plan amendment](https://example.invalid/policy)` A08, changes a contract.",
        "<strong>Plan amendment</strong> A08, changes a contract.",
        "Plan amendment<!-- policy --> A08, changes a contract.",
        "Plan amend<span>ment</span> A08, changes a contract.",
        "Plan amend&#x6d;ent A08, changes a contract.",
        "> Plan amendment A08, changes a contract.",
        "Plan amendment\u00a0A08, changes a contract.",
        "***Plan _amendment_*** **A08**, changes a contract.",
        "> - **[Plan amendment](https://example.invalid/policy)** `A08`, changes a contract.",
    ),
)
def test_markdown_html_and_unicode_wrappers_cannot_hide_a_declaration(amendment: str) -> None:
    violations = evaluate(_synth_plan(f"{amendment} {_ALL_FIELDS}"), _ADR_INDEX)
    assert any("A08" in v and "not one canonical declaration" in v for v in violations), (
        amendment,
        violations,
    )


@pytest.mark.parametrize(
    "token",
    (
        "A&#48;8",
        "&#65;08",
        "A0&#56;",
        "<!--x-->A08",
        "A<!--x-->08",
        "A0<!--x-->8",
        "A08<!--x-->",
        "\uff2108",
        "A\uff10\uff18",
        "\uff21\uff10\uff18",
    ),
)
def test_rendered_or_confusable_amendment_ids_are_rejected_before_ascii_parsing(
    token: str,
) -> None:
    plan = _synth_plan(f"Plan amendment {token}, approved by the owner. {_ALL_FIELDS}")
    violations = evaluate(plan, _ADR_INDEX)
    assert violations, token
    assert any(
        "A08" in violation or "malformed amendment identifier" in violation
        for violation in violations
    ), (
        token,
        violations,
    )


def test_a_prose_reference_cannot_create_or_hide_a_declaration() -> None:
    plan = _synth_plan(
        "This paragraph changes a contract and points to amendment A08 without declaring it. "
        f"{_ALL_FIELDS}"
    )
    violations = evaluate(plan, _ADR_INDEX)
    assert any("A08" in v and "not one canonical declaration" in v for v in violations), violations


def test_a_reused_process_exemption_is_rejected() -> None:
    plan = _synth_plan(
        "Process amendment A01, approved by the owner, changes no locked contract. "
        "Reason: process only.\n\nAmendment A01, approved by the owner, changes a locked "
        "storage contract."
    )
    violations = evaluate(plan, _ADR_INDEX)
    assert any("A01" in v and "duplicate" in v for v in violations), violations


def test_out_of_order_or_gapped_amendment_declarations_are_rejected() -> None:
    plan = _synth_plan(
        f"Plan amendment A02, approved by the owner, changes a contract. {_ALL_FIELDS} "
        f"\n\nPlan amendment A04, approved by the owner, changes a contract. {_ALL_FIELDS}"
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
