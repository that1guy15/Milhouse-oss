"""Fail-closed privacy authorization for every planned persistence and egress surface."""

from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum
from types import MappingProxyType
from typing import cast

from milhouse.domain.records import PrivacyClassV1
from milhouse.privacy.pseudonym import PrivacyError


class EgressSurface(StrEnum):
    """A persistence or output boundary governed by the binding v1 egress matrix."""

    LOCAL_SPOOL = "local_spool"
    LOCAL_SQLITE = "local_sqlite"
    LOCAL_CLICKHOUSE = "local_clickhouse"
    CLI_QUERY = "cli_query"
    LOCAL_MCP = "local_mcp"
    REPO_BRIEF = "repo_brief"
    TELEGRAM = "telegram"
    GITHUB_ISSUES = "github_issues"
    HOSTED_CLICKHOUSE = "hosted_clickhouse"
    DIAGNOSTICS = "diagnostics"
    LOCAL_LOG = "local_log"


class EgressDisposition(StrEnum):
    """The most detailed content shape a caller may render for one authorization."""

    REDACTED_RECORD = "redacted_record"
    POLICY_FILTERED_SUMMARY = "policy_filtered_summary"
    METADATA = "metadata"
    REDACTED_METADATA = "redacted_metadata"


_PRIVACY_CLASSES = frozenset({"public", "internal", "sensitive", "restricted"})
_EXTERNAL_SURFACES = frozenset(
    {
        EgressSurface.TELEGRAM,
        EgressSurface.GITHUB_ISSUES,
        EgressSurface.HOSTED_CLICKHOUSE,
    }
)
_EXTERNAL_CLASS_CEILINGS: Mapping[EgressSurface, frozenset[PrivacyClassV1]] = MappingProxyType(
    {
        EgressSurface.TELEGRAM: frozenset({"public", "internal"}),
        EgressSurface.GITHUB_ISSUES: frozenset({"public", "internal"}),
        EgressSurface.HOSTED_CLICKHOUSE: frozenset({"public", "internal", "sensitive"}),
    }
)
_MATRIX: Mapping[
    EgressSurface,
    Mapping[PrivacyClassV1, EgressDisposition],
] = MappingProxyType(
    {
        EgressSurface.LOCAL_SPOOL: MappingProxyType(
            {
                "public": EgressDisposition.REDACTED_RECORD,
                "internal": EgressDisposition.REDACTED_RECORD,
                "sensitive": EgressDisposition.REDACTED_RECORD,
            }
        ),
        EgressSurface.LOCAL_SQLITE: MappingProxyType(
            {
                "public": EgressDisposition.REDACTED_RECORD,
                "internal": EgressDisposition.REDACTED_RECORD,
                "sensitive": EgressDisposition.REDACTED_RECORD,
            }
        ),
        EgressSurface.LOCAL_CLICKHOUSE: MappingProxyType(
            {
                "public": EgressDisposition.REDACTED_RECORD,
                "internal": EgressDisposition.REDACTED_RECORD,
                "sensitive": EgressDisposition.REDACTED_RECORD,
            }
        ),
        EgressSurface.CLI_QUERY: MappingProxyType(
            {
                "public": EgressDisposition.REDACTED_RECORD,
                "internal": EgressDisposition.REDACTED_RECORD,
                "sensitive": EgressDisposition.POLICY_FILTERED_SUMMARY,
            }
        ),
        EgressSurface.LOCAL_MCP: MappingProxyType(
            {
                "public": EgressDisposition.REDACTED_RECORD,
                "internal": EgressDisposition.REDACTED_RECORD,
                "sensitive": EgressDisposition.POLICY_FILTERED_SUMMARY,
            }
        ),
        EgressSurface.REPO_BRIEF: MappingProxyType(
            {
                "public": EgressDisposition.POLICY_FILTERED_SUMMARY,
                "internal": EgressDisposition.POLICY_FILTERED_SUMMARY,
            }
        ),
        EgressSurface.TELEGRAM: MappingProxyType(
            {
                "public": EgressDisposition.POLICY_FILTERED_SUMMARY,
                "internal": EgressDisposition.POLICY_FILTERED_SUMMARY,
            }
        ),
        EgressSurface.GITHUB_ISSUES: MappingProxyType(
            {
                "public": EgressDisposition.POLICY_FILTERED_SUMMARY,
                "internal": EgressDisposition.POLICY_FILTERED_SUMMARY,
            }
        ),
        EgressSurface.HOSTED_CLICKHOUSE: MappingProxyType(
            {
                "public": EgressDisposition.REDACTED_RECORD,
                "internal": EgressDisposition.REDACTED_RECORD,
                "sensitive": EgressDisposition.REDACTED_RECORD,
            }
        ),
        EgressSurface.DIAGNOSTICS: MappingProxyType(
            {
                "public": EgressDisposition.METADATA,
                "internal": EgressDisposition.REDACTED_METADATA,
            }
        ),
        EgressSurface.LOCAL_LOG: MappingProxyType(
            {
                "public": EgressDisposition.METADATA,
                "internal": EgressDisposition.REDACTED_METADATA,
            }
        ),
    }
)


def _validate_privacy_class(value: object) -> PrivacyClassV1:
    if type(value) is not str or value not in _PRIVACY_CLASSES:
        raise PrivacyError(
            "MH_EGRESS_PRIVACY_CLASS",
            "egress privacy classification is invalid",
        )
    return cast(PrivacyClassV1, value)


def _validate_allowlist(value: object) -> frozenset[PrivacyClassV1]:
    if type(value) is not frozenset:
        raise PrivacyError("MH_EGRESS_ALLOWLIST", "egress classification allowlist is invalid")
    validated: set[PrivacyClassV1] = set()
    for item in value:
        validated.add(_validate_privacy_class(item))
    return frozenset(validated)


def require_egress(
    *,
    surface: EgressSurface,
    privacy_class: PrivacyClassV1,
    explicitly_enabled: bool = False,
    allowed_classifications: frozenset[PrivacyClassV1] = frozenset(),
) -> EgressDisposition:
    """Authorize one boundary and return its mandatory maximum content disposition.

    The caller-controlled allowlist may narrow an external surface, but it cannot expand the
    hard-coded v1 matrix. This function intentionally accepts no content or destination value.
    """

    if type(surface) is not EgressSurface:
        raise PrivacyError("MH_EGRESS_SURFACE", "egress surface is invalid")
    classification = _validate_privacy_class(privacy_class)
    if classification == "restricted":
        raise PrivacyError(
            "MH_EGRESS_RESTRICTED",
            "restricted input cannot reach persistence or egress",
        )
    if type(explicitly_enabled) is not bool:
        raise PrivacyError("MH_EGRESS_ENABLED", "egress enablement flag is invalid")
    allowlist = _validate_allowlist(allowed_classifications)

    is_external = surface in _EXTERNAL_SURFACES
    if not is_external and (explicitly_enabled or allowlist):
        raise PrivacyError(
            "MH_EGRESS_POLICY",
            "external egress policy is invalid for a local surface",
        )

    if is_external:
        ceiling = _EXTERNAL_CLASS_CEILINGS[surface]
        if not allowlist <= ceiling:
            raise PrivacyError(
                "MH_EGRESS_POLICY",
                "egress allowlist exceeds the surface classification ceiling",
            )
        if not explicitly_enabled:
            raise PrivacyError("MH_EGRESS_DISABLED", "external egress surface is disabled")
        if classification not in allowlist:
            raise PrivacyError(
                "MH_EGRESS_NOT_ALLOWLISTED",
                "privacy classification is not allowlisted for external egress",
            )

    disposition = _MATRIX[surface].get(classification)
    if disposition is None:
        raise PrivacyError(
            "MH_EGRESS_CLASS_DENIED",
            "privacy classification is denied for the egress surface",
        )
    return disposition


__all__ = ["EgressDisposition", "EgressSurface", "require_egress"]
