import math

import pytest

from milhouse.privacy import (
    FieldAllowlist,
    FieldRule,
    LayeredRedactor,
    PrivacyError,
    Pseudonymizer,
    apply_field_allowlist,
)

KEY = bytes(range(32))


def make_redactor() -> LayeredRedactor:
    return LayeredRedactor(Pseudonymizer(KEY))


def test_exact_nested_allowlist_discards_unknown_fields_and_redacts_every_string() -> None:
    private_value = "fixture-value-not-for-output"
    policy = FieldAllowlist(
        (
            FieldRule(("active",), "scalar", required=True),
            FieldRule(("metadata", "endpoint"), "url"),
            FieldRule(("metadata", "message"), "text"),
            FieldRule(("metadata", "workspace"), "path"),
        )
    )
    source = {
        "active": True,
        "metadata": {
            "endpoint": f"https://operator:{private_value}@example.test/x?token={private_value}",
            "message": f"contact user@example.test; token={private_value}",
            "workspace": f"/Users/example/{private_value}/project",
            "unlisted_nested": private_value,
        },
        "unlisted_top": private_value,
    }

    result = apply_field_allowlist(source, allowlist=policy, redactor=make_redactor())

    assert result.value["active"] is True
    metadata = result.value["metadata"]
    assert isinstance(metadata, dict)
    assert metadata["endpoint"] == "https://example.test/x"
    assert "user@example.test" not in metadata["message"]
    assert metadata["workspace"].startswith("local-path:mh_ps1_e1_path_")
    assert "unlisted_nested" not in metadata
    assert "unlisted_top" not in result.value
    assert private_value not in repr(result.value)
    assert result.discarded_fields == 2
    assert result.redactions["credential"] == 1
    assert result.redactions["email"] == 1
    assert result.redactions["path"] == 1
    assert result.redactions["url_query"] == 1
    assert result.redactions["url_userinfo"] == 1


def test_url_field_can_retain_only_explicit_safe_query_keys() -> None:
    policy = FieldAllowlist(
        (
            FieldRule(
                ("endpoint",),
                "url",
                allowed_query_keys=frozenset({"region"}),
            ),
        )
    )

    result = apply_field_allowlist(
        {"endpoint": "https://example.test/x?private=drop&region=us-east-1"},
        allowlist=policy,
        redactor=make_redactor(),
    )

    assert result.value == {"endpoint": "https://example.test/x?region=us-east-1"}
    assert result.redactions == {"url": 1, "url_query": 1}


def test_safe_url_field_requires_no_redaction_counts() -> None:
    policy = FieldAllowlist((FieldRule(("endpoint",), "url"),))

    result = apply_field_allowlist(
        {"endpoint": "https://example.test/health"},
        allowlist=policy,
        redactor=make_redactor(),
    )

    assert result.value == {"endpoint": "https://example.test/health"}
    assert result.redactions == {}


@pytest.mark.parametrize("secret", ["mh_ps1_e", "local-pa"])
def test_typed_path_allowlist_cannot_emit_registered_pseudonym_fragments(secret: str) -> None:
    redactor = LayeredRedactor(Pseudonymizer(KEY), known_secrets=(secret,))
    policy = FieldAllowlist((FieldRule(("workspace",), "path"),))

    result = apply_field_allowlist(
        {"workspace": "/home/operator/private/app.py"},
        allowlist=policy,
        redactor=redactor,
    )

    assert result.value == {"workspace": "[mh:p]"}
    assert secret not in repr(result)
    assert result.redactions == {"path": 1, "secret": 1}
    assert redactor.pseudonymize_path("/home/operator/private/app.py") == "[mh:p]"


@pytest.mark.parametrize("value", [True, 0, 42, 1.5, "safe text"])
def test_scalar_fields_preserve_canonical_types(value: object) -> None:
    policy = FieldAllowlist((FieldRule(("value",), "scalar"),))

    result = apply_field_allowlist({"value": value}, allowlist=policy, redactor=make_redactor())

    assert result.value == {"value": value}


@pytest.mark.parametrize(
    "value",
    [None, [], {}, math.inf, math.nan, -(2**63) - 1, 2**63],
)
def test_scalar_fields_reject_noncanonical_values_without_echoing(value: object) -> None:
    policy = FieldAllowlist((FieldRule(("value",), "scalar"),))

    with pytest.raises(PrivacyError, match="MH_PRIVACY_FIELD_VALUE") as captured:
        apply_field_allowlist({"value": value}, allowlist=policy, redactor=make_redactor())

    assert repr(value) not in str(captured.value)


def test_required_nested_fields_fail_closed_without_source_values() -> None:
    policy = FieldAllowlist((FieldRule(("metadata", "message"), "text", required=True),))
    private_value = "fixture-value-not-for-output"

    with pytest.raises(PrivacyError, match="MH_PRIVACY_FIELD_MISSING") as captured:
        apply_field_allowlist(
            {"metadata": {"other": private_value}},
            allowlist=policy,
            redactor=make_redactor(),
        )

    assert private_value not in str(captured.value)


def test_optional_nested_object_is_omitted_when_no_allowlisted_leaf_is_present() -> None:
    policy = FieldAllowlist((FieldRule(("metadata", "message"), "text"),))

    result = apply_field_allowlist(
        {"metadata": {"other": "discarded"}},
        allowlist=policy,
        redactor=make_redactor(),
    )

    assert result.value == {}
    assert result.discarded_fields == 1

    missing_parent = apply_field_allowlist({}, allowlist=policy, redactor=make_redactor())
    assert missing_parent.value == {}
    assert missing_parent.discarded_fields == 0


@pytest.mark.parametrize("kind", ["text", "url", "path"])
def test_privacy_text_fields_reject_nontext_values(kind: object) -> None:
    policy = FieldAllowlist((FieldRule(("value",), kind),))  # type: ignore[arg-type]

    with pytest.raises(PrivacyError, match="MH_PRIVACY_FIELD_VALUE"):
        apply_field_allowlist({"value": 42}, allowlist=policy, redactor=make_redactor())


def test_allowlist_output_is_deeply_immutable() -> None:
    policy = FieldAllowlist((FieldRule(("metadata", "message"), "text"),))
    result = apply_field_allowlist(
        {"metadata": {"message": "safe"}},
        allowlist=policy,
        redactor=make_redactor(),
    )

    with pytest.raises(TypeError):
        result.value["other"] = "value"
    metadata = result.value["metadata"]
    assert isinstance(metadata, dict)
    with pytest.raises(TypeError):
        metadata["message"] = "changed"
    with pytest.raises(TypeError):
        result.redactions["email"] = 1


@pytest.mark.parametrize(
    ("rules", "code"),
    [
        ((), "MH_PRIVACY_FIELD_RULES"),
        ((object(),), "MH_PRIVACY_FIELD_RULES"),
        (
            (FieldRule(("message",), "text"), FieldRule(("message",), "text")),
            "MH_PRIVACY_FIELD_DUPLICATE",
        ),
        (
            (
                FieldRule(("metadata",), "text"),
                FieldRule(("metadata", "message"), "text"),
            ),
            "MH_PRIVACY_FIELD_OVERLAP",
        ),
        (
            (
                FieldRule(("metadata", "message"), "text"),
                FieldRule(("metadata",), "text"),
            ),
            "MH_PRIVACY_FIELD_OVERLAP",
        ),
    ],
)
def test_field_allowlist_rejects_invalid_rule_sets(rules: object, code: str) -> None:
    with pytest.raises(PrivacyError) as captured:
        FieldAllowlist(rules)  # type: ignore[arg-type]

    assert captured.value.code == code


@pytest.mark.parametrize(
    ("arguments", "code"),
    [
        ({"path": (), "kind": "text"}, "MH_PRIVACY_FIELD_PATH"),
        ({"path": ("Bad Field",), "kind": "text"}, "MH_PRIVACY_FIELD_PATH"),
        ({"path": ("message",) * 9, "kind": "text"}, "MH_PRIVACY_FIELD_PATH"),
        ({"path": ("message",), "kind": "unknown"}, "MH_PRIVACY_FIELD_KIND"),
        (
            {"path": ("message",), "kind": "text", "required": 1},
            "MH_PRIVACY_FIELD_REQUIRED",
        ),
        (
            {
                "path": ("endpoint",),
                "kind": "url",
                "allowed_query_keys": ["q"],
            },
            "MH_PRIVACY_FIELD_QUERY_ALLOWLIST",
        ),
        (
            {
                "path": ("endpoint",),
                "kind": "url",
                "allowed_query_keys": frozenset({"bad key"}),
            },
            "MH_PRIVACY_FIELD_QUERY_ALLOWLIST",
        ),
        (
            {
                "path": ("message",),
                "kind": "text",
                "allowed_query_keys": frozenset({"q"}),
            },
            "MH_PRIVACY_FIELD_QUERY_ALLOWLIST",
        ),
    ],
)
def test_field_rules_are_strict(arguments: dict[str, object], code: str) -> None:
    with pytest.raises(PrivacyError) as captured:
        FieldRule(**arguments)  # type: ignore[arg-type]

    assert captured.value.code == code


def test_apply_policy_and_nested_object_inputs_are_strict_and_bounded() -> None:
    policy = FieldAllowlist((FieldRule(("metadata", "message"), "text"),))

    with pytest.raises(PrivacyError, match="MH_PRIVACY_FIELD_INPUT"):
        apply_field_allowlist([], allowlist=policy, redactor=make_redactor())  # type: ignore[arg-type]
    with pytest.raises(PrivacyError, match="MH_PRIVACY_FIELD_POLICY"):
        apply_field_allowlist(
            {},
            allowlist=object(),  # type: ignore[arg-type]
            redactor=make_redactor(),
        )
    with pytest.raises(PrivacyError, match="MH_PRIVACY_FIELD_OBJECT"):
        apply_field_allowlist(
            {"metadata": "not-an-object"},
            allowlist=policy,
            redactor=make_redactor(),
        )
    with pytest.raises(PrivacyError, match="MH_PRIVACY_FIELD_OBJECT_LARGE"):
        apply_field_allowlist(
            {"metadata": {f"field{index}": index for index in range(1_001)}},
            allowlist=policy,
            redactor=make_redactor(),
        )


def test_allowlist_repr_exposes_only_rule_count() -> None:
    policy = FieldAllowlist((FieldRule(("message",), "text"),))

    assert repr(policy) == "FieldAllowlist(rule_count=1)"
    assert policy.rules == (FieldRule(("message",), "text"),)
