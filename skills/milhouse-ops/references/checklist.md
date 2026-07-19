# Milhouse Ops Checklist

Before changing internals:

- Identify one authorized work package and exact gate assertions.
- Confirm dependencies and current status.
- Read the relevant plan clauses, ADRs, source, and tests.
- Define the behavioral proof and synthetic fixtures.
- Identify privacy, durability, migration, and compatibility risk.
- Assign non-overlapping ownership before parallel writes.

Before reporting complete:

- Reproduce and explain the causal root of every corrected defect.
- Inspect the integrated diff and simplify without contract drift.
- Confirm redaction-before-persistence and spool-before-export where applicable.
- Run the active package gate and record evidence.
- Run `make test`, `make docs-check`, and `make skill-check`.
- List unverified live behavior and externally pending evidence.
- Obtain report-only `milhouse-gate-review`; resolve every P0/P1.
- Do not mark the gate passed from agent confidence.
