# Gate evidence

These records preserve the exact commands, environments, artifacts, hosted runs, reviews, and
remaining boundaries used to decide Milhouse implementation gates. They supplement, but do not
amend, the [authoritative plan](../implementation-plan.md). The concise package state remains in
[implementation status](../implementation-status.md).

A record may describe an in-progress candidate. Only an explicit conclusion tied to an exact
commit and every required result marks a gate passed.

- [G01 package and quality-toolchain foundation](G01.md) — passed 2026-07-19
- [G02 domain, configuration, identity, trust, and privacy](G02.md) — accepted 2026-07-24
- [G03 SQLite control plane, durable spool, replay, and retention](G03.md) — candidate, not yet
  accepted (pending independent review and supported-host physical-crash evidence)
  - [G03 supported-host physical-crash test procedure](G03-physical-crash-procedure.md) — specified,
    not yet executed
- [PR #21 squash DCO incident and remediation](PR21-DCO.md) — immediate recovery complete;
  historical disposition recorded by amendment A03 (2026-07-22)
