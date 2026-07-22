# PR #21 squash DCO incident and remediation

## Status

Recovery is in progress. This record does not amend the authoritative plan, classify the affected
commit as DCO compliant, or weaken the DCO checker. It preserves the exact incident evidence and
the bounded recovery path while protected `main` remains immutable.

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

## Bounded recovery

The same author is submitting this record in a DCO-signed remediation commit whose message applies
the sign-off retroactively to the exact affected contribution and binds it to the signed,
identical-tree source commit. Recovery must proceed through a protected pull request. Its squash
body must contain real line breaks and an author-matching trailer. After merge, validation must:

1. inspect the protected commit message rather than trusting the merge command;
2. pass `scripts/check_dco.py` for the exact old-main-to-new-main range;
3. continue to reject the original affected-commit range; and
4. pass the recovery PR and post-merge aggregate Required CI runs.

No history rewrite, force push, protection bypass, checker weakening, generic squash exception, or
rerun of the correctly failed workflow is permitted.

## Durable disposition boundary

This remediation restores enforcement for subsequent protected-main ranges but cannot alter the
historical commit. A permanent exact historical exception requires explicit owner approval through
the plan's numbered change-control process. Such an amendment must bind only the affected squash
SHA, parent, tree, signed source SHA, matching author identity, and protected recovery commit while
leaving all future DCO enforcement unchanged. If the owner declines that exception, the retained
PR #21 change must be reverted and re-landed through protected, correctly signed squash commits.
