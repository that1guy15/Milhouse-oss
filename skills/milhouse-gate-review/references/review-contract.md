# Gate Review Contract

## Lenses

- **Correctness:** Find a concrete failing path, invariant violation, or false claim.
- **Gate completeness:** Map every assertion to current, reproducible evidence; reject skipped or
  stale evidence.
- **Privacy/security:** Check trust boundaries, first-write redaction, secret handling, path and URL
  bounds, egress, and authorization.
- **Durability/concurrency:** Check crash boundaries, replay, idempotency, ownership, leases, and
  checkpoints.
- **Migration/recovery:** Check compatibility, partial failure, rollback, backups, restore, and
  destructive confirmation.
- **Interface:** Check config, records, CLI JSON, MCP, plugin, receiver, and lifecycle contracts.
- **Provider:** Check pagination, cursors, revisions, rate limits, drift, and degraded behavior.
- **Packaging/supply chain:** Check artifacts, resources, pins, permissions, provenance, and scans.
- **Documentation/evidence:** Check commands, links, status truth, support labels, and reproducibility.

## Severity

- `P0`: exploitable security or privacy breach, destructive behavior, or release-wide data loss.
- `P1`: acknowledged-data loss or corruption, locked-contract violation, unusable primary path, or
  false gate pass.
- `P2`: bounded correctness, resilience, compatibility, or maintainability defect needing correction.
- `P3`: low-risk improvement with concrete value.

Do not report style preferences without an impact path. `Change` is a demonstrated defect, `Verify`
is required evidence not yet proven, and `Consider` is a bounded non-blocking improvement.
