from __future__ import annotations

from typing import cast

import pytest
from hypothesis import given
from hypothesis import strategies as st

from milhouse.domain.records import PrivacyClassV1
from milhouse.privacy import EgressDisposition, EgressSurface, PrivacyError, require_egress

_CLASSES = ("public", "internal", "sensitive", "restricted")
_CLASS_SETS = st.sets(st.sampled_from(_CLASSES), max_size=len(_CLASSES)).map(frozenset)


@pytest.mark.property
@given(st.sampled_from(tuple(EgressSurface)), _CLASS_SETS)
def test_restricted_is_always_denied(surface: EgressSurface, allowlist: frozenset[str]) -> None:
    with pytest.raises(PrivacyError) as captured:
        require_egress(
            surface=surface,
            privacy_class="restricted",
            explicitly_enabled=surface
            in {
                EgressSurface.TELEGRAM,
                EgressSurface.GITHUB_ISSUES,
                EgressSurface.HOSTED_CLICKHOUSE,
            },
            allowed_classifications=cast(frozenset[PrivacyClassV1], allowlist),
        )

    assert captured.value.code == "MH_EGRESS_RESTRICTED"


@pytest.mark.property
@given(
    st.sampled_from(
        (EgressSurface.TELEGRAM, EgressSurface.GITHUB_ISSUES, EgressSurface.REPO_BRIEF)
    ),
    _CLASS_SETS,
)
def test_sensitive_never_reaches_summary_destinations(
    surface: EgressSurface,
    allowlist: frozenset[str],
) -> None:
    with pytest.raises(PrivacyError):
        require_egress(
            surface=surface,
            privacy_class="sensitive",
            explicitly_enabled=surface is not EgressSurface.REPO_BRIEF,
            allowed_classifications=cast(frozenset[PrivacyClassV1], allowlist)
            if surface is not EgressSurface.REPO_BRIEF
            else frozenset(),
        )


@pytest.mark.property
@given(
    st.sampled_from(
        (
            EgressSurface.TELEGRAM,
            EgressSurface.GITHUB_ISSUES,
            EgressSurface.HOSTED_CLICKHOUSE,
        )
    ),
    st.sampled_from(_CLASSES[:-1]),
    _CLASS_SETS,
)
def test_disabled_external_surfaces_never_authorize(
    surface: EgressSurface,
    privacy_class: str,
    allowlist: frozenset[str],
) -> None:
    with pytest.raises(PrivacyError):
        require_egress(
            surface=surface,
            privacy_class=cast(PrivacyClassV1, privacy_class),
            allowed_classifications=cast(frozenset[PrivacyClassV1], allowlist),
        )


@pytest.mark.property
@given(_CLASS_SETS)
def test_arbitrary_allowlists_cannot_elevate_telegram(allowlist: frozenset[str]) -> None:
    try:
        result = require_egress(
            surface=EgressSurface.TELEGRAM,
            privacy_class="public",
            explicitly_enabled=True,
            allowed_classifications=cast(frozenset[PrivacyClassV1], allowlist),
        )
    except PrivacyError:
        return

    assert result is EgressDisposition.POLICY_FILTERED_SUMMARY
    assert "public" in allowlist
    assert allowlist <= {"public", "internal"}
