"""Structural exact-artifact guard for the live W03/G03 remediation review inventory."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
_G03 = (_REPO / "docs/gate-evidence/G03.md").read_text(encoding="utf-8")
_STATUS = (_REPO / "docs/implementation-status.md").read_text(encoding="utf-8")

_INVENTORY_START = "<!-- BEGIN CURRENT W03/G03 REVIEW INVENTORY -->"
_INVENTORY_END = "<!-- END CURRENT W03/G03 REVIEW INVENTORY -->"
_ARTIFACT_LINE = re.compile(
    r"^- REVIEW-ARTIFACT \| PR #(?P<pr>[0-9]+) \| "
    r"HEAD `(?P<head>[0-9a-f]{40})` \| "
    r"COMMENT \[(?P<comment>[0-9]+)\]"
    r"\(https://github\.com/that1guy15/Milhouse-oss/pull/(?P<link_pr>[0-9]+)"
    r"#issuecomment-(?P<link_comment>[0-9]+)\) \| "
    r"VERDICT \*\*(?P<verdict>PASS|FAIL)\*\*$"
)


@dataclass(frozen=True, order=True)
class ReviewArtifact:
    pr: int
    head: str
    comment: str
    verdict: str


# Sanitized, immutable inputs reconstructed from qualifying GitHub comments. New qualifying
# artifacts must be added here and to both current-inventory sections in the same correction commit.
_LATEST_REMEDIATION_REVIEWS = (
    ReviewArtifact(
        pr=78,
        head="800617594f7d755eb077481a1b27092dabad377e",
        comment="5162094078",
        verdict="FAIL",
    ),
    ReviewArtifact(
        pr=78,
        head="09708871d1d3fd90ad3a7ec6294d30f1e72f31a4",
        comment="5161910990",
        verdict="FAIL",
    ),
    ReviewArtifact(
        pr=78,
        head="f9e67870a54daa20971065bce74448eddd16d364",
        comment="5160141657",
        verdict="FAIL",
    ),
    ReviewArtifact(
        pr=78,
        head="aac8fc92085a81d1069145e6b9dd6fb677b7d68b",
        comment="5159451366",
        verdict="FAIL",
    ),
    ReviewArtifact(
        pr=79,
        head="9c08351962ba2af0521cef41a6e07c7e83df798b",
        comment="5157727285",
        verdict="FAIL",
    ),
    ReviewArtifact(
        pr=79,
        head="fde0cc6f5fac43da137e9a6eb39aef825623a325",
        comment="5159628362",
        verdict="FAIL",
    ),
    ReviewArtifact(
        pr=79,
        head="644b57dffb92038390f81cd5697c0bfbfb539275",
        comment="5160178919",
        verdict="FAIL",
    ),
)


def _current_status_snapshot(text: str) -> str:
    start = text.index("## Current snapshot")
    match = re.search(r"^## ", text[start + 1 :], flags=re.MULTILINE)
    end = len(text) if match is None else start + 1 + match.start()
    return text[start:end]


def _current_gate_summary(text: str) -> str:
    marker = "\n## Open findings"
    end = text.index(marker)
    return text[:end]


def _inventory(text: str) -> tuple[set[ReviewArtifact], list[str]]:
    if text.count(_INVENTORY_START) != 1 or text.count(_INVENTORY_END) != 1:
        return set(), ["current review inventory markers must occur exactly once"]
    start = text.index(_INVENTORY_START) + len(_INVENTORY_START)
    end = text.index(_INVENTORY_END, start)
    artifacts: list[ReviewArtifact] = []
    violations: list[str] = []
    for line in text[start:end].splitlines():
        if not line.strip():
            continue
        match = _ARTIFACT_LINE.fullmatch(line)
        if match is None:
            violations.append(f"malformed current review inventory record: {line!r}")
            continue
        if match.group("pr") != match.group("link_pr"):
            violations.append(f"review PR/link mismatch: {line!r}")
            continue
        if match.group("comment") != match.group("link_comment"):
            violations.append(f"review comment/link mismatch: {line!r}")
            continue
        artifacts.append(
            ReviewArtifact(
                pr=int(match.group("pr")),
                head=match.group("head"),
                comment=match.group("comment"),
                verdict=match.group("verdict"),
            )
        )
    if len(artifacts) != len(set(artifacts)):
        violations.append("current review inventory contains duplicate exact tuples")
    return set(artifacts), violations


def _missing(text: str) -> list[str]:
    observed, violations = _inventory(text)
    expected = set(_LATEST_REMEDIATION_REVIEWS)
    for artifact in sorted(expected - observed):
        violations.append(
            f"missing exact review tuple: PR #{artifact.pr} {artifact.head} "
            f"comment {artifact.comment} {artifact.verdict}"
        )
    for artifact in sorted(observed - expected):
        violations.append(
            f"unexpected exact review tuple: PR #{artifact.pr} {artifact.head} "
            f"comment {artifact.comment} {artifact.verdict}"
        )
    return violations


def _record(artifact: ReviewArtifact) -> str:
    return (
        f"- REVIEW-ARTIFACT | PR #{artifact.pr} | HEAD `{artifact.head}` | "
        f"COMMENT [{artifact.comment}]"
        f"(https://github.com/that1guy15/Milhouse-oss/pull/{artifact.pr}"
        f"#issuecomment-{artifact.comment}) | VERDICT **{artifact.verdict}**"
    )


def _section(*artifacts: ReviewArtifact) -> str:
    return (
        f"{_INVENTORY_START}\n"
        + "\n".join(_record(artifact) for artifact in artifacts)
        + f"\n{_INVENTORY_END}"
    )


def test_gate_packet_contains_each_exact_review_tuple_in_its_current_summary() -> None:
    assert _missing(_current_gate_summary(_G03)) == []


def test_status_ledger_contains_each_exact_review_tuple_in_the_current_snapshot() -> None:
    assert _missing(_current_status_snapshot(_STATUS)) == []


def test_scattered_or_reordered_tokens_do_not_form_an_artifact() -> None:
    artifact = _LATEST_REMEDIATION_REVIEWS[0]
    scattered = (
        f"{_INVENTORY_START}\n"
        f"PR #{artifact.pr} {artifact.verdict} issuecomment-{artifact.comment} {artifact.head}\n"
        f"{_INVENTORY_END}"
    )
    violations = _missing(scattered)
    assert any("malformed current review inventory record" in item for item in violations)
    assert any("missing exact review tuple" in item for item in violations)


def test_mismatched_link_cannot_bind_otherwise_correct_tokens() -> None:
    artifact = _LATEST_REMEDIATION_REVIEWS[0]
    bad = _record(artifact).replace(f"issuecomment-{artifact.comment}", "issuecomment-0000000000")
    violations = _missing(f"{_INVENTORY_START}\n{bad}\n{_INVENTORY_END}")
    assert any("review comment/link mismatch" in item for item in violations)


def test_historical_inventory_does_not_satisfy_the_current_snapshot() -> None:
    historical = _section(*_LATEST_REMEDIATION_REVIEWS)
    text = f"## Current snapshot\n\nNo current inventory.\n\n## Defects\n\n{historical}\n"
    violations = _missing(_current_status_snapshot(text))
    assert violations[0] == "current review inventory markers must occur exactly once"


def test_exact_current_inventory_passes_only_as_complete_structured_records() -> None:
    assert _missing(_section(*_LATEST_REMEDIATION_REVIEWS)) == []
