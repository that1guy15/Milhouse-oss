# Work-package Execution Contract

## Readiness

Implementation is ready only when the active work package, dependencies, exact files, acceptance
behavior, tests, privacy impact, migration impact, and external prerequisites are known. If a public
contract or stored schema is unresolved, stop that workstream and use the plan-amendment process.

## Delegation

Pass paths and bounded questions to subagents rather than copying source or logs into prompts.
Assume all subagents share the checkout unless the current runtime explicitly proves isolation.
The primary agent owns integration, resolves overlap, inspects every diff, and runs authoritative
tests against the combined tree.

Hidden contention includes configuration contracts, migrations, dependency files, generated
artifacts, stateful services, databases, browsers, ports, external APIs, and rate limits. Serialize
work that touches any shared source of truth.

## Causal debugging

Record the observed failure, the suspected causal chain, and a prediction that would be false if the
hypothesis were wrong. Change one causal variable at a time. A fix is complete only when the original
failure is reproduced by a regression test, the test passes after the correction, and neighboring
failure paths remain covered.

## Completion

Completion requires an integrated diff, targeted and gate-level commands with exit results, updated
truthful docs, provenance where relevant, and a report-only gate review. External evidence remains
`externally pending`; it is never converted to `passed` by inference.
