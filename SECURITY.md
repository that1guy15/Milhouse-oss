# Security Policy

Milhouse observes operational systems and AI-assisted workflows. Treat every input, local state file, backup, report, and diagnostic as potentially sensitive.

## Supported versions

Milhouse is pre-alpha and has no supported public release yet. Security fixes apply to the active development branch. The 1.x support policy becomes effective only after `1.0.0` is published.

## Report a vulnerability privately

Do **not** open a public issue or discussion for credential exposure, private-data disclosure, unsafe filesystem/repository writes, remote code execution, authentication bypass, acknowledged-record loss, or replay corruption.

Preferred reporting path:

1. Open a private report through [GitHub Private Vulnerability Reporting](https://github.com/that1guy15/Milhouse-oss/security/advisories/new).
2. Include the affected commit/version, minimal synthetic reproduction, impact, and suggested mitigation if known.
3. Never include a live credential, raw telemetry, customer/user data, private path, or production dump. Replace sensitive values with typed placeholders and safe fingerprints.

If the private-report form is unavailable, contact the repository owner through their GitHub profile **without vulnerability details** and request a private channel. Do not use a public issue as a fallback.

Enabling and exercising GitHub Private Vulnerability Reporting with a draft test report is an owner-controlled G00 requirement. Repository documentation does not claim that setting is active until the evidence is recorded in `docs/implementation-status.md`.

## Response and severity

- **P0:** credential/data exposure, remote code execution, or uncontrolled external mutation.
- **P1:** acknowledged data loss, unsafe filesystem/application writes, replay corruption, or broken recovery.
- **P2:** materially incorrect or degraded behavior.
- **P3:** minor defect.

P0/P1 reports block release. Maintainers will acknowledge a valid private report as soon as practical, coordinate remediation and disclosure privately, and publish an advisory/CVE when appropriate. Exact response-time commitments will be added with the maintainer support policy before 1.0.

## Security invariants

- Redaction and trust classification precede every persistence and egress surface.
- Restricted data is rejected; only safe metadata may survive.
- Public domain validation and mutation failures retain only fixed error metadata, never rejected
  input or nested exception details; frozen models reject declared, unknown, and underscore state,
  repeated initialization, initialized validator targets, and pickle state APIs.
- Marked local paths, complete file URIs, and decoded-sensitive URL path components are
  keyed-pseudonymized before retained text crosses a persistence or output boundary.
- Redaction policy revisions are identity-bearing. Policy `r2` enforces the registered-secret
  invariant after generated pseudonyms, handles two-layer encoded forms without letting malformed
  percent/hex neighbors or MIME whitespace hide a valid registered span, covers unbracketed IPv6, and
  returns collision-safe whole-path/whole-URL markers when canonical output would otherwise leak or
  become malformed.
- Raw prompts, responses, transcripts, and tool output are never persisted in 1.0.
- When persisted (the section 4.15 `local_log` sink lands in W02 and is gated by G02), local
  operational logs will use the fail-closed `local_log` surface: installation-scoped metadata only,
  with no arbitrary-text or exception-detail field and no secret, path, prompt, transcript, or
  tool-output content in files, stderr, or tracebacks.
- Acknowledged records are durably spooled before export.
- ClickHouse and the ingestion receiver are loopback-only by default.
- MCP is local stdio, bounded, and read-only by default.
- Third-party plugins are explicitly installed, exactly metadata-allowlisted, trusted in-process
  code—not sandboxed. Configuration validation directly reads only configured, path-backed
  distribution metadata under pre-parse byte caps; it does not import plugin code or inspect
  unlisted distributions, and unsupported metadata backends fail closed. A metadata match is not a
  code-safety or provenance verdict. W05 must revalidate and bind the exact entry-point object it
  will load.
- External notifications and writes are disabled by default and require preview/confirmation policy.

See [PRIVACY.md](PRIVACY.md), [the threat model](docs/threat-model.md), and [the implementation plan](docs/implementation-plan.md).
