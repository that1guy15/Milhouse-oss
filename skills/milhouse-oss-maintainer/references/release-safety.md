# Release Safety Reference

Block a merge or release if any of these are present:

- real tokens or credentials
- account IDs, private domains, or provider tags
- private local paths or identifiers
- generated telemetry, reports, state, logs, or backups
- raw feedback, agent sessions, prompts, responses, transcripts, or tool output
- private incidents or application-specific documentation
- hardcoded user names in examples
- missing or uncertain donor or third-party provenance
- skipped, stale, missing, or failed required checks
- unresolved P0/P1 findings
- a gate marked passed without its required evidence
- a mutation outside the current status-ledger authority

Before a release candidate, inspect the full history and built artifacts, verify licenses, SBOM, and
hashes, install the exact wheel and sdist on supported clean hosts, and obtain the independent review
and protected-release approvals required by G17/G18.
