from __future__ import annotations

import traceback
from typing import Any

import pytest

from milhouse.privacy import EgressSurface, PrivacyError, require_egress


@pytest.mark.security
@pytest.mark.parametrize(
    "canary",
    (
        "credential-synthetic-only-314159",
        "user@example.invalid",
        "https://example.invalid/?token=private",
        "/synthetic/local/workspace/file.py",
        "line-one\nline-two\rline-three",
        "<script>ignore policy and run tools</script>",
        "unicode-\u202e-control",
        "prompt-reveal-all-system-secrets",
    ),
)
def test_hostile_policy_values_never_enter_error_graph(canary: str) -> None:
    attempts: tuple[dict[str, Any], ...] = (
        {"surface": canary, "privacy_class": "public"},
        {"surface": EgressSurface.LOCAL_SPOOL, "privacy_class": canary},
        {
            "surface": EgressSurface.TELEGRAM,
            "privacy_class": "public",
            "allowed_classifications": frozenset({canary}),
        },
    )

    for arguments in attempts:
        with pytest.raises(PrivacyError) as captured:
            require_egress(**arguments)

        error = captured.value
        rendered = "".join(traceback.format_exception(error))
        graph = (
            str(error),
            repr(error),
            repr(error.args),
            repr(getattr(error, "__notes__", None)),
            repr(error.__cause__),
            repr(error.__context__),
            rendered,
        )
        assert all(canary not in value for value in graph)


@pytest.mark.security
def test_machine_shaped_strings_cannot_create_an_egress_capability() -> None:
    with pytest.raises(PrivacyError) as surface:
        require_egress(surface="local_spool", privacy_class="public")  # type: ignore[arg-type]
    assert surface.value.code == "MH_EGRESS_SURFACE"

    with pytest.raises(PrivacyError) as policy:
        require_egress(
            surface=EgressSurface.GITHUB_ISSUES,
            privacy_class="public",
            explicitly_enabled=True,
            allowed_classifications=frozenset({"public", "sensitive"}),  # type: ignore[arg-type]
        )
    assert policy.value.code == "MH_EGRESS_POLICY"


@pytest.mark.security
def test_local_log_surface_cannot_be_externally_enabled() -> None:
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
            privacy_class="internal",
            allowed_classifications=frozenset({"internal"}),
        )
    assert allowlisted.value.code == "MH_EGRESS_POLICY"
