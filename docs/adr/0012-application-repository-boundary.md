# ADR 0012: Application-repository boundary

- Status: Accepted (ratification)
- Date: 2026-07-18

## Context

Milhouse must make feedback available inside application repositories without gaining broad write authority or destroying producer-owned data.

## Decision

Milhouse may write only inside the exact configured `<repo>/.milhouse` directory after canonical-path and symlink checks. The rest of every application repository is read-only.

Ownership is fixed:

- the application or CI appends `feedback-outbox.jsonl`;
- Milhouse reads but never truncates, rotates, or rewrites that outbox;
- Milhouse atomically owns `outbox-ack.json`, `FEEDBACK.md`, and `AGENT_FEEDBACK.md`;
- the application team owns `TEAM_WORKFLOW.md`; initialization creates it only when absent and never overwrites it;
- cursors and inode/offset state remain in Milhouse SQLite.

Generated files use atomic replacement and mode `0600`. Output is deterministic apart from declared generation metadata. Integration artifacts are ignored by default unless the application owner intentionally commits schema/readme material.

Outbox records use the versioned schema and stable producer IDs. Producers fsync complete lines, rotate to monotonically named immutable files, and retain rotations until the acknowledgement covers EOF. Removal or truncation of unacknowledged bytes is detected as P1 data loss; Milhouse does not claim recovery of deleted bytes.

## Consequences

`milhouse repo init|status TARGET` validates schemas, boundaries, safe ignore rules, acknowledgement state, and generic producer examples without overwriting team content. Contract tests cover traversal, symlinks, rotations, truncation, partial/corrupt lines, duplicates, and deterministic regeneration.

## Plan references

- [Section 4.9: application-repository contract](../implementation-plan.md#49-application-repository-contract)
- [W07: outbox ingestion](../implementation-plan.md#w07--generic-file-and-authenticated-ingestion)
- [W09: generated briefs and ownership](../implementation-plan.md#w09--complete-query-service-reports-and-milhouse-briefs)
