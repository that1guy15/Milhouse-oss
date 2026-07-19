# OSS Source Boundary

Milhouse OSS is a fresh, sanitized implementation. The exact build and reuse decisions are normative in [the implementation plan](implementation-plan.md), especially sections 1, 7, 8, and 14.

## Public baseline

The tracked public baseline at `that1guy15/Milhouse-oss@fb81a7faf2c101e8bb3f08ef9120d82c2b20600b` supplies project intent, community scaffolding, and skills. Existing runtime files are pre-alpha scaffolding and are replaced only through their owning work-package gates.

## Private donor boundary

The private baseline at `that1guy15/milhouse@18ee9514ee11413812fde8fe361405b3686e025f` remains read-only. It may inform algorithms and provider-format behavior only through the file-level disposition in `docs/provenance.md` and section 7 of the plan.

Never transfer private history, generated telemetry, state, logs, reports, credentials, local paths, account IDs, incidents, configuration, fixtures, prompts, responses, transcripts, or tool output. Every intentional code/algorithm adaptation receives a fresh public implementation, provenance entry, synthetic tests, and independent review.

## Public completion

The repository is not ready for publication merely because source work compiles. Engineering completion, release-candidate readiness, and release completion are separate states. All W00-W18 gates, clean-host checks, security/provenance review, artifact validation, soak periods, and separately authorized publication steps must pass.
