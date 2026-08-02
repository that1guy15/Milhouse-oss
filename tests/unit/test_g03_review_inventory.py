"""Exact-artifact guard for the live W03/G03 remediation review inventory."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
_G03 = (_REPO / "docs/gate-evidence/G03.md").read_text(encoding="utf-8")
_STATUS = (_REPO / "docs/implementation-status.md").read_text(encoding="utf-8")


@dataclass(frozen=True)
class ReviewArtifact:
    pr: int
    head: str
    comment: str
    verdict: str


# Sanitized, immutable inputs reconstructed from the qualifying GitHub comments. New qualifying
# artifacts must be added here and to both authority documents in the same correction commit.
_LATEST_REMEDIATION_REVIEWS = (
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
)


def _missing(text: str) -> list[str]:
    missing: list[str] = []
    for artifact in _LATEST_REMEDIATION_REVIEWS:
        required = (
            f"PR #{artifact.pr}",
            artifact.head,
            f"issuecomment-{artifact.comment}",
            artifact.verdict,
        )
        absent = [value for value in required if value not in text]
        if absent:
            missing.append(f"PR #{artifact.pr} {artifact.head}: {absent}")
    return missing


def test_gate_packet_contains_each_latest_exact_review_artifact() -> None:
    assert _missing(_G03) == []


def test_status_ledger_contains_each_latest_exact_review_artifact() -> None:
    assert _missing(_STATUS) == []


def test_fixture_rejects_the_stale_two_head_snapshot() -> None:
    stale = (
        "PR #78 aac8fc92085a81d1069145e6b9dd6fb677b7d68b issuecomment-5159451366 FAIL; "
        "PR #79 9c08351962ba2af0521cef41a6e07c7e83df798b issuecomment-5157727285 FAIL"
    )
    missing = _missing(stale)
    assert missing == [
        "PR #79 fde0cc6f5fac43da137e9a6eb39aef825623a325: "
        "['fde0cc6f5fac43da137e9a6eb39aef825623a325', "
        "'issuecomment-5159628362']"
    ]
