# ADR 0017: D01 historical DCO disposition

- Status: Accepted (process adaptation)
- Date: 2026-07-22
- Authority: Owner-approved amendment A03 (2026-07-22) under plan section 1 change control

## Context

Defect D01 records that the PR #21 protected squash merge
`76511d5c63e4509765b3ad3ceabefba251e559c7` embedded literal escaped newlines in its custom squash
body, so its intended `Signed-off-by` text is not a parseable Git trailer and
`scripts/check_dco.py` correctly rejects the commit. Its DCO-signed source
`74ca504c9483e6af983e829e2e831af6b00d9061` has the same author identity and the identical reviewed
tree `9629b5116e6351cee94c5385a9a5a20ed93abf69`. Immediate recovery is complete at signed protected
commit `c0f9f2a8a1300eef18e651a20b6e2111d9cbd6a5`, but the permanent historical disposition of the
noncompliant squash required explicit owner approval through plan change control.

## Decision

Amendment A03 recognizes only this exact bounded remediation:

- The malformed protected squash `76511d5c63e4509765b3ad3ceabefba251e559c7` (parent
  `15eb96dc23fb25b7787f1f6d3c7563a9ccd525cf`; tree `9629b5116e6351cee94c5385a9a5a20ed93abf69`) remains
  explicitly and permanently noncompliant.
- The matching author's protected signed follow-up commit
  `c0f9f2a8a1300eef18e651a20b6e2111d9cbd6a5` supplies the narrow retroactive DCO attestation for the
  identical contribution (signed source `74ca504c9483e6af983e829e2e831af6b00d9061`; durable evidence
  closure `ce0aaecbf05f14b566d45446f756aeda24bfe1f3`).
- The disposition binds only that single squash SHA, its parent, tree, signed source SHA, matching
  author identity, and protected recovery commit. It grants no generic DCO exception, no
  squash-message bypass, no DCO-checker weakening, no history rewrite, and no force push or protection
  bypass.
- Every future commit remains under unchanged strict DCO enforcement; an author-matching
  `Signed-off-by` trailer is required and unsigned commits cannot merge.

## Alternatives considered

- **Generic DCO exception or checker weakening:** rejected because it would erode enforcement for
  every future contribution.
- **History rewrite or force push of the affected squash:** rejected because protected `main`
  disallows it and it would break the durable evidence chain.
- **Decline the exception:** the recorded fallback is to revert the retained PR #21 change and re-land
  it through protected, correctly signed squash commits; the owner instead approved the bounded
  disposition above.

## Compatibility, security, and validation

A03 changes no public API, stored schema, product scope, retention rule, migration, or Plan 1.0
privacy promise. It records a bounded historical fact and preserves strict DCO enforcement. The
durable evidence, exact ranges, and checker exit codes are in
[gate-evidence/PR21-DCO.md](../gate-evidence/PR21-DCO.md); `scripts/check_dco.py` continues to reject
the affected range and pass the recovery range.

## References

- [gate-evidence/PR21-DCO.md](../gate-evidence/PR21-DCO.md)
- [Defect D01 and amendment A03](../implementation-status.md#defects-amendments-and-stop-conditions)
- [Section 1: authority and change control](../implementation-plan.md#1-authority-and-change-control)
