# Pull-request Lifecycle

Use these terminal states:

- `engineering`: local implementation or correction is active.
- `review_pending`: report-only gate review or required conversation is unresolved.
- `checks_pending`: required hosted checks have not reached a current terminal result.
- `fix_required`: a required check, P0/P1 finding, provenance review, or mergeability check failed.
- `externally_pending`: engineering is complete but a named authority or host action is outstanding.
- `merge_ready`: the current head is authorized, reviewed, mergeable, and all required checks pass.
- `merged_verified`: protected `main` contains the merge and its post-merge checks and state were read
  back.

A moving PR head invalidates older review and check conclusions. Poll with bounded backoff, reread the
head and required contexts, and stop in `externally_pending` rather than watching forever when the
remaining condition requires another actor or elapsed-time change.
