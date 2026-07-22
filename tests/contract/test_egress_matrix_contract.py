from __future__ import annotations

import pytest

from milhouse.privacy import EgressDisposition, EgressSurface, PrivacyError, require_egress

_CLASSIFICATIONS = ("public", "internal", "sensitive", "restricted")
_EXTERNAL_ALLOWLISTS = {
    EgressSurface.TELEGRAM: frozenset({"public", "internal"}),
    EgressSurface.GITHUB_ISSUES: frozenset({"public", "internal"}),
    EgressSurface.HOSTED_CLICKHOUSE: frozenset({"public", "internal", "sensitive"}),
}
_EXPECTED = {
    EgressSurface.LOCAL_SPOOL: {
        "public": EgressDisposition.REDACTED_RECORD,
        "internal": EgressDisposition.REDACTED_RECORD,
        "sensitive": EgressDisposition.REDACTED_RECORD,
    },
    EgressSurface.LOCAL_SQLITE: {
        "public": EgressDisposition.REDACTED_RECORD,
        "internal": EgressDisposition.REDACTED_RECORD,
        "sensitive": EgressDisposition.REDACTED_RECORD,
    },
    EgressSurface.LOCAL_CLICKHOUSE: {
        "public": EgressDisposition.REDACTED_RECORD,
        "internal": EgressDisposition.REDACTED_RECORD,
        "sensitive": EgressDisposition.REDACTED_RECORD,
    },
    EgressSurface.CLI_QUERY: {
        "public": EgressDisposition.REDACTED_RECORD,
        "internal": EgressDisposition.REDACTED_RECORD,
        "sensitive": EgressDisposition.POLICY_FILTERED_SUMMARY,
    },
    EgressSurface.LOCAL_MCP: {
        "public": EgressDisposition.REDACTED_RECORD,
        "internal": EgressDisposition.REDACTED_RECORD,
        "sensitive": EgressDisposition.POLICY_FILTERED_SUMMARY,
    },
    EgressSurface.REPO_BRIEF: {
        "public": EgressDisposition.POLICY_FILTERED_SUMMARY,
        "internal": EgressDisposition.POLICY_FILTERED_SUMMARY,
    },
    EgressSurface.TELEGRAM: {
        "public": EgressDisposition.POLICY_FILTERED_SUMMARY,
        "internal": EgressDisposition.POLICY_FILTERED_SUMMARY,
    },
    EgressSurface.GITHUB_ISSUES: {
        "public": EgressDisposition.POLICY_FILTERED_SUMMARY,
        "internal": EgressDisposition.POLICY_FILTERED_SUMMARY,
    },
    EgressSurface.HOSTED_CLICKHOUSE: {
        "public": EgressDisposition.REDACTED_RECORD,
        "internal": EgressDisposition.REDACTED_RECORD,
        "sensitive": EgressDisposition.REDACTED_RECORD,
    },
    EgressSurface.DIAGNOSTICS: {
        "public": EgressDisposition.METADATA,
        "internal": EgressDisposition.REDACTED_METADATA,
    },
    EgressSurface.LOCAL_LOG: {
        "public": EgressDisposition.METADATA,
        "internal": EgressDisposition.REDACTED_METADATA,
    },
}


@pytest.mark.contract
@pytest.mark.parametrize("surface", tuple(EgressSurface))
@pytest.mark.parametrize("privacy_class", _CLASSIFICATIONS)
def test_binding_v1_surface_matrix(surface: EgressSurface, privacy_class: str) -> None:
    expected = _EXPECTED[surface].get(privacy_class)
    kwargs: dict[str, object] = {}
    if surface in _EXTERNAL_ALLOWLISTS:
        kwargs = {
            "explicitly_enabled": True,
            "allowed_classifications": _EXTERNAL_ALLOWLISTS[surface],
        }

    if expected is None:
        with pytest.raises(PrivacyError):
            require_egress(surface=surface, privacy_class=privacy_class, **kwargs)  # type: ignore[arg-type]
        return

    assert (
        require_egress(surface=surface, privacy_class=privacy_class, **kwargs)  # type: ignore[arg-type]
        is expected
    )


@pytest.mark.contract
def test_public_api_uses_stable_string_values() -> None:
    assert {surface.value for surface in EgressSurface} == {
        "local_spool",
        "local_sqlite",
        "local_clickhouse",
        "cli_query",
        "local_mcp",
        "repo_brief",
        "telegram",
        "github_issues",
        "hosted_clickhouse",
        "diagnostics",
        "local_log",
    }
    assert {disposition.value for disposition in EgressDisposition} == {
        "redacted_record",
        "policy_filtered_summary",
        "metadata",
        "redacted_metadata",
    }
