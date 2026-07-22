# PR #21 squash DCO incident and remediation

## Status

Immediate recovery is complete at protected-main commit
`c0f9f2a8a1300eef18e651a20b6e2111d9cbd6a5`. This record does not amend the authoritative plan,
classify the affected commit as DCO compliant, or weaken the DCO checker. Permanent historical
disposition remains owner-pending.

## Exact affected contribution

- Protected squash merge: `76511d5c63e4509765b3ad3ceabefba251e559c7` from
  [PR #21](https://github.com/that1guy15/Milhouse-oss/pull/21).
- Protected parent: `15eb96dc23fb25b7787f1f6d3c7563a9ccd525cf`.
- Merged tree: `9629b5116e6351cee94c5385a9a5a20ed93abf69`.
- DCO-signed PR source commit: `74ca504c9483e6af983e829e2e831af6b00d9061`.
- Reviewed source tree: `9629b5116e6351cee94c5385a9a5a20ed93abf69`.
- The source and squash commits have the same author identity and exact tree.

The merge command supplied escaped newline characters in its custom squash body. GitHub retained
those characters literally, so the intended `Signed-off-by` text is embedded in the preceding
paragraph instead of being a parseable Git trailer. The source commit has a real, author-matching
trailer; the protected squash commit does not.

## Failure evidence

The repository checker returns exit 1 for the exact protected-main range:

```text
python scripts/check_dco.py --range \
  15eb96dc23fb25b7787f1f6d3c7563a9ccd525cf..76511d5c63e4509765b3ad3ceabefba251e559c7
dco: commit(s) lack an author-matching Signed-off-by trailer: 76511d5c63e4
```

It returns exit 0 for the exact source-commit range:

```text
python scripts/check_dco.py --range \
  74ca504c9483e6af983e829e2e831af6b00d9061^..74ca504c9483e6af983e829e2e831af6b00d9061
dco: 1 commit(s) passed
```

Post-merge Required CI run
[`29902382356`](https://github.com/that1guy15/Milhouse-oss/actions/runs/29902382356)
correctly failed. Its `dco` job rejected the squash commit, and `required-ci` propagated that
failure. Every other job passed: quality, test coverage, Python 3.11-3.14 compatibility, macOS
identity portability on Python 3.11 and 3.14, package build, four artifact-smoke jobs, audit,
dependency review, gitleaks, and CodeQL.

## Bounded recovery evidence

Recovery [PR #22](https://github.com/that1guy15/Milhouse-oss/pull/22) retained final signed source
head `3ac1a330fad9cf9216fd78a2f0220404c3be8b5a` and tree
`6c8e6d11c36ed88989a4adafefa59d91a33aa837`. Required CI run
[`29903357994`](https://github.com/that1guy15/Milhouse-oss/actions/runs/29903357994) and the
separate GitHub Advanced Security CodeQL check passed at that exact head. Independent report-only
review found no actionable P0-P3 issue after D01 was added to the defects ledger.

Protected squash merge produced `c0f9f2a8a1300eef18e651a20b6e2111d9cbd6a5` with the exact
reviewed tree. Direct inspection found real line breaks and one parsed, author-matching trailer.
The strict checker passes the exact
`76511d5c63e4509765b3ad3ceabefba251e559c7..c0f9f2a8a1300eef18e651a20b6e2111d9cbd6a5`
recovery range and continues to reject the original affected range.

Post-merge Required CI run
[`29903480661`](https://github.com/that1guy15/Milhouse-oss/actions/runs/29903480661) first failed
because the pinned uv setup action in the `gitleaks` job timed out after five seconds while fetching
its public version manifest; neither secret scanner started. Every other constituent job passed,
and `required-ci` correctly propagated the setup failure. The failed-jobs-only second attempt ran
both secret scans successfully and then passed `required-ci`; the completed run conclusion is
success.

No history rewrite, force push, protection bypass, checker weakening, generic squash exception, or
rerun of the correctly failed PR #21 workflow occurred.

## Durable disposition boundary

This remediation restores enforcement for subsequent protected-main ranges but cannot alter the
historical commit. A permanent exact historical exception requires explicit owner approval through
the plan's numbered change-control process. Such an amendment must bind only the affected squash
SHA, parent, tree, signed source SHA, matching author identity, and protected recovery commit while
leaving all future DCO enforcement unchanged. If the owner declines that exception, the retained
PR #21 change must be reverted and re-landed through protected, correctly signed squash commits.
