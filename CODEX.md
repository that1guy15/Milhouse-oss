# Codex Host Guide

Read and follow `AGENTS.md`; it is the canonical repository instruction. Invoke the five project
skills as `$milhouse-ops`, `$milhouse-feedback`, `$milhouse-gate-review`, `$milhouse-compound`, and
`$milhouse-oss-maintainer` through the relative aliases in `.agents/skills/`.

Use bounded subagents only under the ownership rules in `milhouse-ops` or the read-only rules in
`milhouse-gate-review`. In the Codex shared workspace, do not assume subagent filesystem isolation.
Use `apply_patch` for manual source edits. GitHub and other external mutations remain governed by
`AGENTS.md` and `docs/implementation-status.md`.
