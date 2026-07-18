# Release Safety Reference

Block public release if any of these are present:

- real tokens or credentials
- account IDs or RUM tags
- private domains
- private local paths
- generated telemetry or reports
- raw agent transcripts
- private incidents
- application-specific docs not intentionally generalized
- hardcoded user names in examples

Recommended release path:

1. Keep the GitHub repo private.
2. Push a clean initial commit.
3. Enable GitHub secret scanning.
4. Review Actions output.
5. Run one fresh clone quickstart.
6. Approve public visibility change.
