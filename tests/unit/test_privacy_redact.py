import base64
import html
import json
from urllib.parse import quote

import pytest

from milhouse.privacy import LayeredRedactor, PrivacyError, Pseudonymizer

KEY = bytes(range(32))


def make_redactor(*private_values: str) -> LayeredRedactor:
    return LayeredRedactor(Pseudonymizer(KEY, epoch=4), known_secrets=private_values)


def test_known_values_and_common_encodings_are_removed() -> None:
    private_value = 'fixture/value+"not-output"'
    encoded = private_value.encode()
    variants = tuple(
        sorted(
            {
                private_value,
                quote(private_value, safe=""),
                quote(quote(private_value, safe=""), safe=""),
                base64.b64encode(encoded).decode(),
                base64.b64encode(encoded).decode().rstrip("="),
                base64.urlsafe_b64encode(encoded).decode().rstrip("="),
                encoded.hex(),
                encoded.hex().upper(),
                html.escape(private_value, quote=True),
                json.dumps(private_value, ensure_ascii=True)[1:-1],
            }
        )
    )

    result = make_redactor(private_value).redact(" | ".join(variants))

    for variant in variants:
        assert variant not in result.value
    assert result.value.count("[redacted:secret]") == len(variants)
    assert result.counts["secret"] == len(variants)
    assert result.changed is True
    assert result.total == len(variants)


def test_credential_headers_assignments_and_private_key_blocks_are_removed() -> None:
    private_key_label = "".join(("PRIVATE", " KEY"))
    source = (
        "Authorization: Bearer opaque-value\n"
        "Cookie: session=opaque-value\n"
        "password = opaque-value\n"
        f"-----BEGIN {private_key_label}-----\nopaque-value\n"
        f"-----END {private_key_label}-----"
    )

    result = make_redactor().redact(source)

    assert "opaque-value" not in result.value
    assert "Bearer" not in result.value
    assert result.value.count("[redacted:credential]") == 3
    assert result.value.endswith("[redacted:private-key]")
    assert result.counts == {"credential": 3, "private_key": 1}


def test_urls_drop_credentials_queries_fragments_and_normalize_hosts() -> None:
    source = (
        "probe HTTPS://operator:opaque@example.test:443/health?token=opaque#fragment, "
        "then https://example.test/status."
    )

    result = make_redactor().redact(source)

    assert result.value == ("probe https://example.test/health, then https://example.test/status.")
    assert "operator" not in result.value
    assert "opaque" not in result.value
    assert "fragment" not in result.value
    assert result.counts["url"] >= 1
    assert result.counts["url_userinfo"] == 1
    assert result.counts["url_query"] == 1
    assert result.counts["url_fragment"] == 1


def test_explicit_url_query_allowlist_keeps_only_safe_values() -> None:
    private_value = "fixture-value-not-for-output"
    result = make_redactor(private_value).redact_url(
        f"https://example.test/{private_value}?region=us-east-1&cursor={private_value}",
        allowed_query_keys=frozenset({"cursor", "region"}),
    )

    assert private_value not in result.value
    assert "region=us-east-1" in result.value
    assert "cursor=" not in result.value
    assert result.counts["secret"] >= 2
    assert result.counts["url_query"] == 1


def test_invalid_url_candidates_fail_closed_and_invalid_ip_shapes_are_unchanged() -> None:
    result = make_redactor().redact("bad https://[broken and 999.999.999.999")

    assert result.value == "bad [redacted:url] and 999.999.999.999"
    assert result.counts == {"url": 1}


def test_bracketed_ipv6_addresses_are_pseudonymized() -> None:
    result = make_redactor().redact("peer [2001:db8::1]")

    assert "2001:db8::1" not in result.value
    assert "ip-mh-ps1-e4-ip-" in result.value
    assert result.counts == {"ip": 1}


def test_url_ip_hosts_ports_and_private_paths_remain_valid_after_pseudonymization() -> None:
    source = "literal MHURLPLACEHOLDER then https://192.0.2.42:8443/Users/example/private/file.txt"

    result = make_redactor().redact(source)

    assert "literal MHURLPLACEHOLDER" in result.value
    assert "192.0.2.42" not in result.value
    assert "/Users/example" not in result.value
    assert "https://ip-mh-ps1-e4-ip-" in result.value
    assert ".invalid:8443/local-path:mh_ps1_e4_path_" in result.value
    assert result.counts["ip"] == 1
    assert result.counts["path"] == 1


def test_redaction_bounds_the_number_of_embedded_urls() -> None:
    source = " ".join(f"https://example{index}.test/" for index in range(101))

    with pytest.raises(PrivacyError, match="MH_PRIVACY_REDACT_URLS"):
        make_redactor().redact(source)


def test_pii_and_local_paths_are_pseudonymized_by_category() -> None:
    source = (
        "user@example.test connected from 192.0.2.42 and +1 312-555-1212; "
        "read /Users/example/private/config.toml and C:\\Users\\example\\config.toml"
    )

    result = make_redactor().redact(source)

    for private_value in (
        "user@example.test",
        "192.0.2.42",
        "+1 312-555-1212",
        "/Users/example/private/config.toml",
        "C:\\Users\\example\\config.toml",
    ):
        assert private_value not in result.value
    assert "[email:mh_ps1_e4_email_" in result.value
    assert "ip-mh-ps1-e4-ip-" in result.value
    assert "[phone:mh_ps1_e4_phone_" in result.value
    assert result.value.count("local-path:mh_ps1_e4_path_") == 2
    assert result.counts == {"email": 1, "ip": 1, "path": 2, "phone": 1}


def test_unicode_line_endings_and_unsafe_controls_are_normalized() -> None:
    result = make_redactor().redact("café\r\nline\u202e\x1b[31m")

    assert result.value == "café\nline[31m"
    assert result.counts == {"control": 2}


def test_redactor_metadata_and_results_do_not_expose_registered_values() -> None:
    private_value = "fixture-value-not-for-output"
    redactor = make_redactor(private_value)
    result = redactor.redact(private_value)

    assert redactor.version == "r1-e4"
    assert redactor.known_secret_count == 1
    assert private_value not in repr(redactor)
    assert private_value not in repr(result)
    with pytest.raises(TypeError):
        result.counts["secret"] = 0


@pytest.mark.parametrize(
    ("private_values", "code"),
    [
        (("short",), "MH_PRIVACY_SECRET_LENGTH"),
        (("x" * 4_097,), "MH_PRIVACY_SECRET_LENGTH"),
        (("bad\nvalue",), "MH_PRIVACY_SECRET_CONTROL"),
        (("bad\ud800value",), "MH_PRIVACY_SECRET_UNICODE"),
        (("duplicate-value", "duplicate-value"), "MH_PRIVACY_SECRET_DUPLICATE"),
        ((b"not-text",), "MH_PRIVACY_SECRET_TYPE"),
    ],
)
def test_invalid_known_values_fail_with_value_safe_errors(
    private_values: object, code: str
) -> None:
    with pytest.raises(PrivacyError) as captured:
        LayeredRedactor(
            Pseudonymizer(KEY),
            known_secrets=private_values,  # type: ignore[arg-type]
        )

    assert captured.value.code == code
    assert repr(private_values) not in str(captured.value)


@pytest.mark.parametrize(
    ("value", "code"),
    [
        (b"not-text", "MH_PRIVACY_REDACT_TYPE"),
        ("bad\ud800value", "MH_PRIVACY_REDACT_UNICODE"),
        ("x" * 65_537, "MH_PRIVACY_REDACT_INPUT_LARGE"),
        ("\x1b", "MH_PRIVACY_REDACT_EMPTY"),
    ],
)
def test_invalid_redaction_input_fails_without_echoing_values(value: object, code: str) -> None:
    with pytest.raises(PrivacyError) as captured:
        make_redactor().redact(value)  # type: ignore[arg-type]

    assert captured.value.code == code
    assert repr(value) not in str(captured.value)


def test_expanding_pseudonyms_cannot_exceed_retained_text_bound() -> None:
    source = " ".join("a@example.test" for _ in range(300))

    with pytest.raises(PrivacyError, match="MH_PRIVACY_REDACT_OUTPUT_LARGE"):
        make_redactor().redact(source)


def test_redactor_constructor_is_strict_and_bounded() -> None:
    with pytest.raises(PrivacyError, match="MH_PRIVACY_REDACTOR_PSEUDONYMIZER"):
        LayeredRedactor(object())  # type: ignore[arg-type]
    with pytest.raises(PrivacyError, match="MH_PRIVACY_SECRET_SET"):
        LayeredRedactor(Pseudonymizer(KEY), known_secrets=["private-value"])  # type: ignore[arg-type]
    with pytest.raises(PrivacyError, match="MH_PRIVACY_SECRET_SET"):
        LayeredRedactor(Pseudonymizer(KEY), known_secrets=("private-value",) * 129)
