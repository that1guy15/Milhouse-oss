from __future__ import annotations

from typing import Any

import pytest

from milhouse.privacy import EgressDisposition, EgressSurface, PrivacyError, require_egress


@pytest.mark.parametrize(
    "surface",
    (
        EgressSurface.TELEGRAM,
        EgressSurface.GITHUB_ISSUES,
        EgressSurface.HOSTED_CLICKHOUSE,
    ),
)
def test_external_surfaces_are_disabled_by_default(surface: EgressSurface) -> None:
    with pytest.raises(PrivacyError) as captured:
        require_egress(surface=surface, privacy_class="public")

    assert captured.value.code == "MH_EGRESS_DISABLED"


def test_external_allowlist_can_narrow_but_not_expand_matrix() -> None:
    assert (
        require_egress(
            surface=EgressSurface.TELEGRAM,
            privacy_class="public",
            explicitly_enabled=True,
            allowed_classifications=frozenset({"public"}),
        )
        is EgressDisposition.POLICY_FILTERED_SUMMARY
    )

    with pytest.raises(PrivacyError) as missing:
        require_egress(
            surface=EgressSurface.TELEGRAM,
            privacy_class="internal",
            explicitly_enabled=True,
            allowed_classifications=frozenset({"public"}),
        )
    assert missing.value.code == "MH_EGRESS_NOT_ALLOWLISTED"

    with pytest.raises(PrivacyError) as expansion:
        require_egress(
            surface=EgressSurface.TELEGRAM,
            privacy_class="public",
            explicitly_enabled=True,
            allowed_classifications=frozenset({"public", "sensitive"}),
        )
    assert expansion.value.code == "MH_EGRESS_POLICY"


def test_hosted_clickhouse_sensitive_data_requires_both_controls() -> None:
    arguments = {
        "surface": EgressSurface.HOSTED_CLICKHOUSE,
        "privacy_class": "sensitive",
        "allowed_classifications": frozenset({"sensitive"}),
    }
    with pytest.raises(PrivacyError) as disabled:
        require_egress(**arguments)  # type: ignore[arg-type]
    assert disabled.value.code == "MH_EGRESS_DISABLED"

    assert (
        require_egress(**arguments, explicitly_enabled=True)  # type: ignore[arg-type]
        is EgressDisposition.REDACTED_RECORD
    )


def test_external_policy_parameters_are_rejected_for_local_surfaces() -> None:
    with pytest.raises(PrivacyError) as enabled:
        require_egress(
            surface=EgressSurface.LOCAL_SPOOL,
            privacy_class="public",
            explicitly_enabled=True,
        )
    assert enabled.value.code == "MH_EGRESS_POLICY"

    with pytest.raises(PrivacyError) as allowlisted:
        require_egress(
            surface=EgressSurface.LOCAL_SPOOL,
            privacy_class="public",
            allowed_classifications=frozenset({"public"}),
        )
    assert allowlisted.value.code == "MH_EGRESS_POLICY"


def test_restricted_input_uses_one_fail_closed_refusal() -> None:
    for surface in EgressSurface:
        kwargs: dict[str, Any] = {}
        if surface in {
            EgressSurface.TELEGRAM,
            EgressSurface.GITHUB_ISSUES,
            EgressSurface.HOSTED_CLICKHOUSE,
        }:
            kwargs = {
                "explicitly_enabled": True,
                "allowed_classifications": frozenset({"restricted"}),
            }
        with pytest.raises(PrivacyError) as captured:
            require_egress(surface=surface, privacy_class="restricted", **kwargs)
        assert captured.value.code == "MH_EGRESS_RESTRICTED"


def test_restricted_refusal_precedes_untrusted_external_policy_values() -> None:
    with pytest.raises(PrivacyError) as captured:
        require_egress(
            surface=EgressSurface.TELEGRAM,
            privacy_class="restricted",
            explicitly_enabled=1,  # type: ignore[arg-type]
            allowed_classifications=frozenset({"untrusted"}),  # type: ignore[arg-type]
        )

    assert captured.value.code == "MH_EGRESS_RESTRICTED"


@pytest.mark.parametrize(
    ("arguments", "code"),
    (
        ({"surface": "local_spool", "privacy_class": "public"}, "MH_EGRESS_SURFACE"),
        (
            {"surface": EgressSurface.LOCAL_SPOOL, "privacy_class": "unknown"},
            "MH_EGRESS_PRIVACY_CLASS",
        ),
        (
            {
                "surface": EgressSurface.TELEGRAM,
                "privacy_class": "public",
                "explicitly_enabled": 1,
            },
            "MH_EGRESS_ENABLED",
        ),
        (
            {
                "surface": EgressSurface.TELEGRAM,
                "privacy_class": "public",
                "allowed_classifications": {"public"},
            },
            "MH_EGRESS_ALLOWLIST",
        ),
        (
            {
                "surface": EgressSurface.TELEGRAM,
                "privacy_class": "public",
                "allowed_classifications": frozenset({"unknown"}),
            },
            "MH_EGRESS_PRIVACY_CLASS",
        ),
    ),
)
def test_runtime_types_are_strict_and_value_safe(arguments: dict[str, Any], code: str) -> None:
    with pytest.raises(PrivacyError) as captured:
        require_egress(**arguments)

    assert captured.value.code == code
    assert "unknown" not in str(captured.value)


def test_local_log_surface_is_metadata_only() -> None:
    assert (
        require_egress(surface=EgressSurface.LOCAL_LOG, privacy_class="public")
        is EgressDisposition.METADATA
    )
    assert (
        require_egress(surface=EgressSurface.LOCAL_LOG, privacy_class="internal")
        is EgressDisposition.REDACTED_METADATA
    )

    with pytest.raises(PrivacyError) as sensitive:
        require_egress(surface=EgressSurface.LOCAL_LOG, privacy_class="sensitive")
    assert sensitive.value.code == "MH_EGRESS_CLASS_DENIED"

    with pytest.raises(PrivacyError) as restricted:
        require_egress(surface=EgressSurface.LOCAL_LOG, privacy_class="restricted")
    assert restricted.value.code == "MH_EGRESS_RESTRICTED"


def test_local_log_is_a_local_surface_and_rejects_external_policy() -> None:
    with pytest.raises(PrivacyError) as enabled:
        require_egress(
            surface=EgressSurface.LOCAL_LOG,
            privacy_class="public",
            explicitly_enabled=True,
        )
    assert enabled.value.code == "MH_EGRESS_POLICY"

    with pytest.raises(PrivacyError) as allowlisted:
        require_egress(
            surface=EgressSurface.LOCAL_LOG,
            privacy_class="public",
            allowed_classifications=frozenset({"public"}),
        )
    assert allowlisted.value.code == "MH_EGRESS_POLICY"


def test_hard_matrix_denial_is_distinct_from_external_policy_denial() -> None:
    with pytest.raises(PrivacyError) as hard_denial:
        require_egress(surface=EgressSurface.REPO_BRIEF, privacy_class="sensitive")
    assert hard_denial.value.code == "MH_EGRESS_CLASS_DENIED"

    with pytest.raises(PrivacyError) as allowlist_denial:
        require_egress(
            surface=EgressSurface.HOSTED_CLICKHOUSE,
            privacy_class="sensitive",
            explicitly_enabled=True,
            allowed_classifications=frozenset({"public"}),
        )
    assert allowlist_denial.value.code == "MH_EGRESS_NOT_ALLOWLISTED"
