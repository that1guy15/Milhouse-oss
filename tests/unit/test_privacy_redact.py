import base64
import html
import json
from time import perf_counter
from traceback import format_exception
from urllib.parse import quote

import pytest

from milhouse.privacy import (
    LayeredRedactor,
    PrivacyError,
    Pseudonymizer,
    render_untrusted_evidence,
    sanitize_url,
)

KEY = bytes(range(32))
APOSTROPHE_HOME = "/".join(("", "home", "O'Brien"))
PRIVILEGED_HOME = "/".join(("", "root"))
PRIVATE_PATH_CANARY = "private-canary-0123456789.txt"
FILESYSTEM_URL_ROOTS = (
    "Applications",
    "Library",
    "System",
    "Users",
    "Volumes",
    "__w",
    "bin",
    "boot",
    "dev",
    "etc",
    "home",
    "lib",
    "lib32",
    "lib64",
    "media",
    "mnt",
    "opt",
    "private",
    "proc",
    "root",
    "run",
    "sbin",
    "srv",
    "sys",
    "tmp",
    "usr",
    "var",
    "workspace",
    "workspaces",
)
RAW_PATH_GRAMMARS = (
    ("file:/home/operator", "/"),
    ("/home/operator", "/"),
    (r"C:\Users\operator", "\\"),
    ("./operator", "/"),
    ("../operator", "/"),
    ("~operator/private", "/"),
    (r"\\server\share\operator", "\\"),
    (r"\\?\UNC\server\share\operator", "\\"),
    (r"\\服务器\共享\operator", "\\"),
)
NATIVE_WINDOWS_PATH_PREFIXES = (
    r"C:\Users\operator",
    r"\\server\share\operator",
    r"\\?\UNC\server\share\operator",
    r"\\服务器\共享\operator",
)
PATH_SEGMENT_DELIMITERS = ("'", '"', "`", "``")
UNICODE_PATH_WHITESPACE = ("\u00a0", "\u1680", "\u2003", "\u2028", "\u2029", "\u3000")


def fully_percent_encode(value: str, *, mixed_case: bool = False) -> str:
    escapes: list[str] = []
    for index, byte in enumerate(value.encode("utf-8")):
        encoded = f"{byte:02X}"
        if mixed_case and index % 2:
            encoded = encoded.lower()
        escapes.append(f"%{encoded}")
    return "".join(escapes)


def mixed_case_hex_encode(value: str) -> str:
    encoded = value.encode("utf-8").hex()
    return "".join(
        character.upper() if character in "abcdef" and index % 2 else character
        for index, character in enumerate(encoded)
    )


def fully_json_encode(value: str) -> str:
    return "".join(f"\\u{ord(character):04X}" for character in value)


def fully_html_encode(value: str) -> str:
    return "".join(f"&#x{ord(character):X};" for character in value)


def encode_outer_codec(value: str, codec: str) -> str:
    if codec == "percent":
        return fully_percent_encode(value, mixed_case=True)
    if codec == "json":
        return fully_json_encode(value)
    if codec == "html":
        return fully_html_encode(value)
    if codec == "base64":
        return base64.b64encode(value.encode()).decode()
    if codec == "hex":
        return mixed_case_hex_encode(value)
    raise AssertionError("unknown synthetic codec")


def make_redactor(*private_values: str) -> LayeredRedactor:
    return LayeredRedactor(Pseudonymizer(KEY, epoch=4), known_secrets=private_values)


def assert_value_safe_delimiter_failure(source: str, canary: str) -> None:
    failures: list[PrivacyError] = []
    for _ in range(2):
        with pytest.raises(PrivacyError) as captured:
            make_redactor().redact(source)
        failures.append(captured.value)

    expected = "MH_PRIVACY_REDACT_DELIMITER: marked local path has no closing delimiter"
    for failure in failures:
        assert failure.code == "MH_PRIVACY_REDACT_DELIMITER"
        assert str(failure) == expected
        for surface in (
            str(failure),
            repr(failure),
            "".join(format_exception(failure)),
            render_untrusted_evidence(str(failure), format="markdown"),
            render_untrusted_evidence(str(failure), format="html"),
        ):
            assert canary not in surface
        assert failure.__cause__ is None
        assert failure.__context__ is None
    assert (failures[0].code, str(failures[0])) == (failures[1].code, str(failures[1]))


def assert_value_safe_continuation_failure(
    source: str,
    canary: str,
    *,
    known_secrets: tuple[str, ...] = (),
) -> None:
    failures: list[PrivacyError] = []
    for _ in range(2):
        with pytest.raises(PrivacyError) as captured:
            make_redactor(*known_secrets).redact(source)
        failures.append(captured.value)

    expected = (
        "MH_PRIVACY_REDACT_DELIMITER: marked local path has an ambiguous whitespace continuation"
    )
    for failure in failures:
        assert failure.code == "MH_PRIVACY_REDACT_DELIMITER"
        assert str(failure) == expected
        for surface in (
            str(failure),
            repr(failure),
            "".join(format_exception(failure)),
            render_untrusted_evidence(str(failure), format="markdown"),
            render_untrusted_evidence(str(failure), format="html"),
        ):
            assert canary not in surface
        assert failure.__cause__ is None
        assert failure.__context__ is None
    assert (failures[0].code, str(failures[0])) == (failures[1].code, str(failures[1]))


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
    assert result.value.count("[mh:s]") == len(variants)
    assert result.counts["secret"] == len(variants)
    assert result.changed is True
    assert result.total == len(variants)


@pytest.mark.parametrize(
    ("secret", "encoded"),
    [
        ("private-é-value", r"private-\u00E9-value"),
        ("private-é-value", r"private-\u0065\u0301-value"),
        ("private-😀-value", r"private-\uD83D\uDE00-value"),
        ("private-é-value", "private-&#101;&#769;-value"),
        ("private-é-value", "private-e%CC%81-value"),
        ("private-é-value", "707269766174652d65cc812d76616c7565"),
        ("private&value", "private&AMP;value"),
        ("private&value", "private&#38;value"),
        ("private&value", "private&#x26;value"),
        ("private-&-value", r"private-\u0026amp;-value"),
        ("private-&-value", "private-&#92;u0026-value"),
        ("private-&-value", "private-%5Cu0026-value"),
        ("private-&-value", "private-&#37;26-value"),
    ],
)
def test_json_html_percent_and_canonical_equivalent_secret_views_are_removed(
    secret: str,
    encoded: str,
) -> None:
    redactor = make_redactor(secret)

    first = redactor.redact(encoded)
    second = redactor.redact(first.value)

    assert secret not in first.value
    assert first.value == "[mh:s]"
    assert first.counts == {"secret": 1}
    assert second.value == first.value
    assert second.counts == {}


def test_every_ordered_pair_of_supported_secret_codecs_is_removed() -> None:
    secret = "private-&-value"
    encoders = {
        "percent": lambda value: quote(value, safe=""),
        "json": lambda value: json.dumps(value, ensure_ascii=True)[1:-1],
        "html": lambda value: html.escape(value, quote=True),
        "base64": lambda value: base64.b64encode(value.encode()).decode(),
        "hex": lambda value: value.encode().hex(),
    }
    redactor = make_redactor(secret)

    for outer_name, outer in encoders.items():
        for inner_name, inner in encoders.items():
            source = outer(inner(secret))
            first = redactor.redact(source)
            second = redactor.redact(first.value)

            assert secret not in first.value, (outer_name, inner_name)
            assert first.counts["secret"] >= 1, (outer_name, inner_name)
            assert second.value == first.value, (outer_name, inner_name)
            assert second.counts == {}, (outer_name, inner_name)


@pytest.mark.parametrize(
    ("secret", "encoded"),
    [
        ("private-value-123", "cHJpdmF0ZS12YWx1ZS0xMjM="),
        ("private-value", "cHJpdmF0ZS12YWx1ZR=="),
        ("private-éÿ-value", "cHJpdmF0ZS3DqcO/LXZhbHVl"),
        ("private-éÿ-value", "cHJpdmF0ZS3DqcO_LXZhbHVl"),
    ],
)
@pytest.mark.parametrize("whitespace", [" ", "\t", "\n"])
def test_percent_wrapped_mime_base64_aliases_are_removed(
    secret: str,
    encoded: str,
    whitespace: str,
) -> None:
    split = len(encoded) // 2
    mime_encoded = f"{encoded[:split]}{whitespace}{encoded[split:]}"
    source = quote(
        mime_encoded,
        safe="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/_-",
    )
    redactor = make_redactor(secret)

    first = redactor.redact(source)
    second = redactor.redact(first.value)

    assert first.value == "[mh:s]"
    assert first.counts == {"secret": 1}
    assert second.value == first.value
    assert second.counts == {}


@pytest.mark.parametrize("outer_codec", ["percent", "json", "html", "base64", "hex"])
@pytest.mark.parametrize(
    ("secret", "encoded"),
    [
        ("private-éÿ-value", "cHJpdmF0ZS3DqcO/LXZhbHVl"),
        ("private-éÿ-value", "cHJpdmF0ZS3DqcO_LXZhbHVl"),
        ("private-value", "cHJpdmF0ZS12YWx1ZQ=="),
        ("private-value", "cHJpdmF0ZS12YWx1ZR=="),
        ("private-value", "cHJpdmF0ZS12YWx1ZQ"),
    ],
)
@pytest.mark.parametrize(("prefix", "suffix"), [("", ""), ("A", ""), ("", "A")])
def test_every_outer_codec_removes_mime_base64_inner_values(
    outer_codec: str,
    secret: str,
    encoded: str,
    prefix: str,
    suffix: str,
) -> None:
    split = len(encoded) // 2
    inner = f"{prefix}{encoded[:split]}\n{encoded[split:]}{suffix}"
    source = encode_outer_codec(inner, outer_codec)
    redactor = make_redactor(secret)

    first = redactor.redact(source)
    second = redactor.redact(first.value)

    assert secret not in first.value
    assert encoded not in first.value
    assert first.counts["secret"] >= 1
    assert second.value == first.value
    assert second.counts == {}


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        (fully_percent_encode("private-value") + "%FF", "[mh:s]%FF"),
        ("%FF" + fully_percent_encode("private-value"), "%FF[mh:s]"),
        (fully_percent_encode("private-value", mixed_case=True) + "%C3", "[mh:s]%C3"),
        ("%80" + fully_percent_encode("private-value", mixed_case=True), "%80[mh:s]"),
        (b"private-value".hex() + "f", "[mh:s]f"),
        ("f" + b"private-value".hex(), "f[mh:s]"),
        ("ff" + b"private-value".hex(), "ff[mh:s]"),
        (b"private-value".hex() + "ff", "[mh:s]ff"),
    ],
)
def test_malformed_percent_and_hex_neighbors_cannot_hide_registered_values(
    source: str,
    expected: str,
) -> None:
    redactor = make_redactor("private-value")

    first = redactor.redact(source)
    second = redactor.redact(first.value)

    assert first.value == expected
    assert first.counts == {"secret": 1}
    assert second.value == first.value
    assert second.counts == {}


@pytest.mark.parametrize("outer_codec", ["percent", "json", "html", "base64", "hex"])
@pytest.mark.parametrize(
    "inner",
    [
        fully_percent_encode("private-value", mixed_case=True) + "%FF",
        b"private-value".hex() + "f",
    ],
)
def test_outer_codecs_cannot_restore_malformed_inner_secret_encodings(
    outer_codec: str,
    inner: str,
) -> None:
    source = encode_outer_codec(inner, outer_codec)
    redactor = make_redactor("private-value")

    first = redactor.redact(source)
    second = redactor.redact(first.value)

    assert "private-value" not in first.value
    assert fully_percent_encode("private-value") not in first.value
    assert b"private-value".hex() not in first.value
    assert first.counts["secret"] >= 1
    assert second.value == first.value
    assert second.counts == {}


@pytest.mark.parametrize(
    "source",
    [
        r"prefix-\uD83Dxxxxxx-suffix",
        r"prefix-\uD83D\u0041-suffix",
        r"prefix-\uDFFF-suffix",
        r"prefix-\uZZZZ-suffix",
        "0123456789abcdef0",
    ],
)
def test_malformed_json_surrogates_and_odd_hex_tokens_are_literal_near_misses(
    source: str,
) -> None:
    result = make_redactor("private-value").redact(source)

    assert result.value == source
    assert result.counts == {}


@pytest.mark.parametrize(
    "source",
    [
        fully_percent_encode("private-value-secret"),
        "private&#45;value&#45;secret",
    ],
)
def test_overlapping_encoded_registered_values_are_removed_as_one_raw_span(source: str) -> None:
    redactor = make_redactor("private-value", "value-secret")

    first = redactor.redact(source)
    second = redactor.redact(first.value)

    assert first.value == "[mh:s]"
    assert first.counts == {"secret": 1}
    assert second.value == first.value
    assert second.counts == {}


@pytest.mark.parametrize(
    "address",
    [
        "2001:db8:85a3::8a2e:370:7334",
        "2001:db8:0:0:0:0:2:1",
        "::ffff:192.0.2.128",
        "fe80::1%eth0",
    ],
)
def test_unbracketed_ipv6_is_pseudonymized_in_text_and_whole_url_paths(address: str) -> None:
    redactor = make_redactor()
    text_source = f"client {address} failed"
    url_source = f"https://example.test/api/{quote(address, safe=':.')}"

    text = redactor.redact(text_source)
    url = redactor.redact(url_source)

    assert address not in text.value
    assert text.counts == {"ip": 1}
    assert "local-path:mh_ps1_e4_path_" in url.value
    assert url.counts == {"ip": 1, "path": 1, "url": 1}


@pytest.mark.parametrize("candidate", ["12:30", "2001:::1", "face:value", "1:2"])
def test_invalid_ipv6_near_misses_are_preserved(candidate: str) -> None:
    source = f"status {candidate} ok"

    result = make_redactor().redact(source)

    assert result.value == source
    assert result.counts == {}


@pytest.mark.parametrize(
    "source",
    [
        "%2Fhome%2Foperator%2Fprivate-canary%2Ftail",
        "file%3A%2F%2F%2Fhome%2Foperator%2Fprivate-canary%2Ftail",
        "C%3A%5CUsers%5Coperator%5Cprivate-canary%5Ctail",
        "%5C%5Cserver%5Cshare%5Cprivate-canary%5Ctail",
        "%252Fhome%252Foperator%252Fprivate-canary%252Ftail",
        "%2Fhome%2Foperator%252Fprivate-canary%252Ftail",
    ],
)
def test_standalone_percent_encoded_local_paths_are_pseudonymized_whole(source: str) -> None:
    redactor = make_redactor()

    first = redactor.redact(source)
    second = redactor.redact(first.value)

    assert "private-canary" not in first.value
    assert first.value.startswith("local-path:mh_ps1_e4_path_")
    assert first.counts == {"path": 1}
    assert second.value == first.value
    assert second.counts == {}


@pytest.mark.parametrize("root", ["api", "app", "data"])
@pytest.mark.parametrize("suffix", ["%41", "%20space", "%C3%A9"])
def test_safe_http_control_paths_with_percent_text_remain_valid(root: str, suffix: str) -> None:
    source = f"note https://example.test/{root}/{suffix} ok"

    result = make_redactor().redact(source)

    assert result.value == source
    assert result.counts == {}


def test_invalid_utf8_in_url_path_is_pseudonymized_as_one_path() -> None:
    source = "https://example.test/api/%FF"

    result = make_redactor().redact_url(source)

    assert result.value.startswith("https://example.test/local-path:mh_ps1_e4_path_")
    assert "%FF" not in result.value
    assert result.counts == {"path": 1, "url": 1}


def test_separator_free_secret_after_plain_path_prose_remains_redactable() -> None:
    redactor = make_redactor("private-value")

    result = redactor.redact("/home/operator/file status private-value")

    assert result.value.startswith("local-path:mh_ps1_e4_path_")
    assert result.value.endswith(" status [mh:s]")
    assert result.counts == {"secret": 1, "path": 1}


@pytest.mark.parametrize(
    "encode",
    [
        lambda value: value.encode().hex(),
        lambda value: value.encode().hex().upper(),
        lambda value: base64.b64encode(value.encode()).decode(),
        lambda value: base64.urlsafe_b64encode(value.encode()).decode().rstrip("="),
    ],
)
def test_encoded_separator_secrets_cannot_hide_path_continuations(encode: object) -> None:
    secret = "secret/value"
    encoded = encode(secret)  # type: ignore[operator]
    canary = "PRIVATE-CANARY"

    assert_value_safe_continuation_failure(
        f"/home/operator/Private {canary}{encoded}",
        canary,
        known_secrets=(secret,),
    )


def test_registered_double_percent_separator_secret_preserves_path_boundary() -> None:
    secret = "secret%252Fvalue"
    canary = "PRIVATE-CANARY"

    assert_value_safe_continuation_failure(
        f"/home/operator/Private {canary}{secret}",
        canary,
        known_secrets=(secret,),
    )


@pytest.mark.parametrize(
    "encoded",
    [
        "cHJpdmF0ZS12YWx1ZQ==",
        "cHJpdmF0ZS12YWx1ZR==",
        "cHJpdmF0ZS12YWx1ZQ",
        "cHJp\ndmF0ZS12YWx1ZQ==",
    ],
)
def test_base64_alias_pad_bits_and_mime_whitespace_are_removed(encoded: str) -> None:
    redactor = make_redactor("private-value")

    first = redactor.redact(encoded)
    second = redactor.redact(first.value)

    assert first.value == "[mh:s]"
    assert first.counts == {"secret": 1}
    assert second.value == first.value
    assert second.counts == {}


def test_oversized_html_numeric_entity_is_a_bounded_literal_near_miss() -> None:
    source = "&#" + ("9" * 60_000) + "; private-value"

    started = perf_counter()
    with pytest.raises(PrivacyError, match="MH_PRIVACY_REDACT_OUTPUT_LARGE"):
        make_redactor("private-value").redact(source)
    elapsed = perf_counter() - started

    assert elapsed < 2.0


@pytest.mark.parametrize("secret", ["redacted", "credential", "private-key", "mh_ps1_e"])
def test_registered_values_cannot_collide_with_generated_markers_or_tokens(secret: str) -> None:
    redactor = make_redactor(secret)
    source = (
        "Authorization: Bearer value; contact user@example.test; path /home/operator/private/app.py"
    )

    first = redactor.redact(source)
    second = redactor.redact(first.value)

    assert secret not in first.value
    assert second.value == first.value
    assert second.counts == {}


@pytest.mark.parametrize(
    "encoded",
    [
        "private%2fvalue%3Ftoken",
        "private%2Fvalue%3ftoken",
        fully_percent_encode("private/value?token"),
        fully_percent_encode("private/value?token", mixed_case=True),
        quote(fully_percent_encode("private/value?token"), safe=""),
        fully_percent_encode(fully_percent_encode("private/value?token"), mixed_case=True),
    ],
)
@pytest.mark.parametrize("wrapper", ["{encoded}", "https://example.test/api/{encoded}"])
def test_percent_encoded_known_secrets_are_removed_across_two_decode_layers(
    encoded: str,
    wrapper: str,
) -> None:
    private_value = "private/value?token"
    source = wrapper.format(encoded=encoded)
    redactor = make_redactor(private_value)

    result = redactor.redact(source)
    markdown = render_untrusted_evidence(result.value, format="markdown")
    rendered_html = render_untrusted_evidence(result.value, format="html")

    for surface in (result.value, repr(result), markdown, rendered_html):
        assert private_value not in surface
        assert encoded not in surface
    assert result.counts["secret"] >= 1


def test_known_secret_literal_characters_remain_case_sensitive_when_percent_encoded() -> None:
    private_value = "Private-Value"
    lowercase = "private-value"
    encoded_lowercase = fully_percent_encode(lowercase, mixed_case=True)
    redactor = make_redactor(private_value)

    literal_result = redactor.redact(lowercase)
    encoded_result = redactor.redact(encoded_lowercase)
    hex_result = redactor.redact(mixed_case_hex_encode(lowercase))

    assert literal_result.value == lowercase
    assert literal_result.counts == {}
    assert encoded_result.value == encoded_lowercase
    assert encoded_result.counts == {}
    assert hex_result.value == mixed_case_hex_encode(lowercase)
    assert hex_result.counts == {}


@pytest.mark.parametrize("wrapper", ["{encoded}", "https://example.test/api/{encoded}"])
def test_mixed_case_hex_known_secrets_are_removed(wrapper: str) -> None:
    private_value = "private-value"
    encoded = mixed_case_hex_encode(private_value)
    source = wrapper.format(encoded=encoded)
    redactor = make_redactor(private_value)

    result = redactor.redact(source)

    assert private_value not in result.value
    assert encoded not in result.value
    assert result.counts["secret"] == 1


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
    assert result.value.count("[mh:c]") == 3
    assert result.value.endswith("[mh:k]")
    assert result.counts == {"credential": 3, "private_key": 1}


@pytest.mark.parametrize(
    "name",
    [
        "api_key",
        "api-key",
        "access_token",
        "refresh_token",
        "client_secret",
        "password",
        "passwd",
        "secret",
        "token",
    ],
)
@pytest.mark.parametrize(
    "value",
    [
        "private-canary'/api/x",
        "private-canary'/api/x'/y",
        'private-canary"/home/operator/x',
        'private-canary"/home/operator/x"/y',
    ],
)
def test_credential_assignments_preempt_path_delimiter_parsing(name: str, value: str) -> None:
    redactor = make_redactor()

    first = redactor.redact(f"{name}={value}")
    second = redactor.redact(first.value)

    assert first.value == f"{name}=[mh:c]"
    assert "private-canary" not in first.value
    assert first.counts == {"credential": 1}
    assert second.value == first.value
    assert second.counts == {}


@pytest.mark.parametrize(
    "header",
    [
        "Authorization: Bearer value",
        "authorization : Bearer value",
        "Cookie: session=value",
        "Set-Cookie:\tvalue",
        "X-API-Key: value",
    ],
)
def test_credential_headers_are_idempotent(header: str) -> None:
    redactor = make_redactor()

    first = redactor.redact(header)
    second = redactor.redact(first.value)

    assert first.counts == {"credential": 1}
    assert second.value == first.value
    assert second.counts == {}
    assert second.changed is False


def test_url_token_assignment_text_remains_under_url_policy() -> None:
    source = "https://example.test/api/token=status?token=private-canary#fragment"

    result = make_redactor().redact(source)

    assert result.value == "https://example.test/api/token=status"
    assert "private-canary" not in result.value
    assert result.counts == {"url": 1, "url_fragment": 1, "url_query": 1}


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


@pytest.mark.parametrize(
    ("secret", "source"),
    [
        ("mh-ps1-e", "https://192.0.2.1/api"),
        ("mh_ps1_e", "https://example.test/home/operator/private/app.py"),
    ],
)
def test_generated_secret_collisions_leave_a_valid_url_or_whole_url_marker(
    secret: str,
    source: str,
) -> None:
    redactor = make_redactor(secret)

    first = redactor.redact_url(source)
    second = redactor.redact(first.value)

    if first.value != "[mh:u]":
        assert sanitize_url(first.value).value == first.value
    assert secret not in first.value
    assert second.value == first.value
    assert second.counts == {}


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

    assert result.value == "bad [mh:u] and 999.999.999.999"
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
        "read /Users/example/private/config.toml, and C:\\Users\\example\\config.toml"
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


def test_email_with_many_valid_domain_labels_is_pseudonymized() -> None:
    address = "operator@a.a.a.a.a.a.a.a.a.a.a.example"

    result = make_redactor().redact(f"contact {address}.")

    assert address not in result.value
    assert result.value.startswith("contact [email:mh_ps1_e4_email_")
    assert result.value.endswith("].")
    assert result.counts == {"email": 1}


def test_email_candidate_with_one_character_tld_is_not_misclassified() -> None:
    source = "contact operator@example.x now"

    result = make_redactor().redact(source)

    assert result.value == source
    assert result.counts == {}


def test_email_local_part_path_syntax_cannot_bypass_email_pseudonymization() -> None:
    address = "private-canary'/api/x'/y@example.test"
    redactor = make_redactor()

    first = redactor.redact(f"contact {address} now")
    second = redactor.redact(first.value)

    assert "private-canary" not in first.value
    assert "/api/" not in first.value
    assert "local-path:" not in first.value
    assert first.value.startswith("contact [email:mh_ps1_e4_email_")
    assert first.value.endswith("] now")
    assert first.counts == {"email": 1}
    assert second.value == first.value
    assert second.counts == {}


@pytest.mark.parametrize(
    "source",
    [
        f"{PRIVILEGED_HOME}/private/component.json",
        "/workspace/repository/private/component.json",
        "/mnt/data/private/component.json",
        "/run/user/1000/private/component.json",
        "/usr/local/private/component.json",
        "/data/private/component.json",
        "~/private/component.json",
        "~operator/private/component.json",
    ],
)
def test_common_linux_and_tilde_paths_are_pseudonymized(source: str) -> None:
    result = make_redactor().redact(f"read {source}")

    assert source not in result.value
    assert "private/component.json" not in result.value
    assert "local-path:mh_ps1_e4_path_" in result.value
    assert result.counts == {"path": 1}


@pytest.mark.parametrize(
    "source",
    [
        "file:///home/operator/private/component.json",
        f"file://{PRIVILEGED_HOME}/private/component.json?mode=private#fragment",
        "file://private-host/share/private/component.json",
        "file:///C:/Users/operator/private/component.json",
        "FILE:/tmp/private/%C3%A9-component.json",
    ],
)
def test_file_uris_are_pseudonymized_as_one_local_path(source: str) -> None:
    result = make_redactor().redact(f"read {source}, then continue")

    assert source not in result.value
    assert "file:" not in result.value.lower()
    assert "private-host" not in result.value
    assert "mode=private" not in result.value
    assert "fragment" not in result.value
    assert "local-path:mh_ps1_e4_path_" in result.value
    assert result.value.endswith(", then continue")
    assert result.counts == {"path": 1}


@pytest.mark.parametrize(
    ("template", "expected"),
    [
        (
            "request {uri}, then continue",
            "request https://example.test/people/O'Brien/activity, then continue",
        ),
        (
            "request '{uri}', then continue",
            "request 'https://example.test/people/O'Brien/activity', then continue",
        ),
        (
            "[activity]({uri})",
            "[activity](https://example.test/people/O'Brien/activity)",
        ),
        (
            "<a href='{uri}'>activity</a>",
            "<a href='https://example.test/people/O'Brien/activity'>activity</a>",
        ),
    ],
)
def test_url_path_apostrophes_cannot_hide_queries_or_fragments(
    template: str,
    expected: str,
) -> None:
    canary = "boundary-canary-not-output"
    uri = f"https://example.test/people/O'Brien/activity?cursor={canary}#{canary}"

    result = make_redactor().redact(template.format(uri=uri))

    assert result.value == expected
    assert canary not in result.value
    assert result.counts == {"url": 1, "url_fragment": 1, "url_query": 1}


def test_url_local_path_apostrophe_is_pseudonymized_as_one_component() -> None:
    canary = "boundary-canary-not-output"
    source = f"https://example.test{APOSTROPHE_HOME}/private.json?cursor={canary}#{canary}"

    result = make_redactor().redact(source)

    assert result.value.startswith("https://example.test/local-path:mh_ps1_e4_path_")
    assert "O'Brien" not in result.value
    assert canary not in result.value
    assert result.counts == {
        "path": 1,
        "url": 1,
        "url_fragment": 1,
        "url_query": 1,
    }


@pytest.mark.parametrize("typed", [False, True])
@pytest.mark.parametrize(
    "path",
    [
        "/people/O'/api/activity",
        "/people/O'/api/O'Brien/activity",
    ],
)
def test_url_segment_ending_apostrophes_do_not_enter_local_path_scanning(
    typed: bool,
    path: str,
) -> None:
    source = f"https://example.test{path}?cursor=private-canary#fragment"
    redactor = make_redactor()

    result = redactor.redact_url(source) if typed else redactor.redact(source)

    assert result.value == f"https://example.test{path}"
    assert "private-canary" not in result.value
    assert result.counts == {"url": 1, "url_fragment": 1, "url_query": 1}


@pytest.mark.parametrize(
    ("template", "prefix", "suffix"),
    [
        ("read {uri}, then continue", "read ", ", then continue"),
        ("read '{uri}', then continue", "read '", "', then continue"),
        ("[local]({uri})", "[local](", ")"),
        ("<a href='{uri}'>local</a>", "<a href='", "'>local</a>"),
    ],
)
def test_file_uri_apostrophes_cannot_split_the_private_path(
    template: str,
    prefix: str,
    suffix: str,
) -> None:
    canary = "boundary-canary-not-output"
    uri = f"file://{APOSTROPHE_HOME}/private.json?cursor={canary}#{canary}"

    result = make_redactor().redact(template.format(uri=uri))

    assert result.value.startswith(f"{prefix}local-path:mh_ps1_e4_path_")
    assert result.value.endswith(suffix)
    assert canary not in result.value
    assert "O'Brien" not in result.value
    assert "file:" not in result.value.lower()
    assert result.counts == {"path": 1}


@pytest.mark.parametrize(
    ("template", "prefix", "suffix"),
    [
        ("read {uri}, then continue", "read ", ", then continue"),
        ("[local]({uri})", "[local](", ")"),
        ("<a href='{uri}'>local</a>", "<a href='", "'>local</a>"),
    ],
)
def test_file_uri_segment_ending_apostrophes_are_pseudonymized_as_one_path(
    template: str,
    prefix: str,
    suffix: str,
) -> None:
    canary = "private-canary-not-output"
    uri = f"file:///people/O'/api/activity?cursor={canary}#{canary}"
    redactor = make_redactor()

    first = redactor.redact(template.format(uri=uri))
    second = redactor.redact(first.value)

    assert first.value.startswith(f"{prefix}local-path:mh_ps1_e4_path_")
    assert first.value.endswith(suffix)
    assert canary not in first.value
    assert "file:" not in first.value.lower()
    assert first.value.count("local-path:") == 1
    assert first.counts == {"path": 1}
    assert second.value == first.value
    assert second.counts == {}


@pytest.mark.parametrize(
    "source",
    [
        f"file:'/home/operator/private folder/{PRIVATE_PATH_CANARY}'",
        f"file:'///home/operator/private folder/{PRIVATE_PATH_CANARY}'",
        f"file:abc'/home/operator/private folder/{PRIVATE_PATH_CANARY}'",
        f"file:/home/operator'/private folder/{PRIVATE_PATH_CANARY}'",
        f"file:///home/operator'/private folder/{PRIVATE_PATH_CANARY}'",
        f"file://host/share'/private folder/{PRIVATE_PATH_CANARY}'",
        repr(f"""file:'/home/operator/private"folder/{PRIVATE_PATH_CANARY}"""),
        repr(f"file:'/home/operator/private folder/{PRIVATE_PATH_CANARY}'"),
        f"[local](file:/home/operator'/private folder/{PRIVATE_PATH_CANARY}')",
        f"`file:/home/operator'/private folder/{PRIVATE_PATH_CANARY}'`",
        f"```text\nfile:/home/operator'/private folder/{PRIVATE_PATH_CANARY}'\n```",
        f"<code>file:/home/operator'/private folder/{PRIVATE_PATH_CANARY}'</code>",
        f"<span data-path=\"file:/home/operator'/private folder/{PRIVATE_PATH_CANARY}'\">x</span>",
    ],
)
def test_quote_continuation_paths_are_never_partially_pseudonymized(source: str) -> None:
    redactor = make_redactor()

    first = redactor.redact(source)
    second = redactor.redact(first.value)

    assert PRIVATE_PATH_CANARY not in first.value
    assert "private folder" not in first.value
    assert first.value.count("local-path:mh_ps1_e4_path_") == 1
    assert first.counts == {"path": 1}
    assert second.value == first.value
    assert second.counts == {}


@pytest.mark.parametrize("followed_by_tail", [False, True])
@pytest.mark.parametrize("delimiter", PATH_SEGMENT_DELIMITERS)
@pytest.mark.parametrize(("prefix", "separator"), RAW_PATH_GRAMMARS)
def test_shell_quoted_path_segments_are_one_token_for_every_raw_grammar(
    prefix: str,
    separator: str,
    delimiter: str,
    followed_by_tail: bool,
) -> None:
    quoted = f"{delimiter}private folder {PRIVATE_PATH_CANARY}{delimiter}"
    tail = f"{separator}more{separator}private-tail" if followed_by_tail else ""
    source = f"{prefix}{separator}{quoted}{tail}"
    redactor = make_redactor()

    first = redactor.redact(source)
    second = redactor.redact(first.value)

    assert PRIVATE_PATH_CANARY not in first.value
    assert "private folder" not in first.value
    assert "private-tail" not in first.value
    assert first.value.count("local-path:mh_ps1_e4_path_") == 1
    assert first.counts == {"path": 1}
    assert second.value == first.value
    assert second.counts == {}


@pytest.mark.parametrize("delimiter", PATH_SEGMENT_DELIMITERS)
@pytest.mark.parametrize(("prefix", "separator"), RAW_PATH_GRAMMARS)
def test_mid_component_quoted_path_segments_and_direct_tails_are_one_token(
    prefix: str,
    separator: str,
    delimiter: str,
) -> None:
    source = (
        f"{prefix}pre{delimiter}private folder {PRIVATE_PATH_CANARY}{delimiter}post{separator}tail"
    )
    redactor = make_redactor()

    first = redactor.redact(source)
    second = redactor.redact(first.value)

    assert PRIVATE_PATH_CANARY not in first.value
    assert "private folder" not in first.value
    assert "post" not in first.value
    assert first.value.count("local-path:mh_ps1_e4_path_") == 1
    assert first.counts == {"path": 1}
    assert second.value == first.value
    assert second.counts == {}


@pytest.mark.parametrize(("prefix", "separator"), RAW_PATH_GRAMMARS)
def test_adjacent_quoted_path_segments_are_one_token(prefix: str, separator: str) -> None:
    source = (
        f'{prefix}{separator}"private one {PRIVATE_PATH_CANARY}"`private two`post{separator}tail'
    )
    redactor = make_redactor()

    first = redactor.redact(source)
    second = redactor.redact(first.value)

    assert PRIVATE_PATH_CANARY not in first.value
    assert "private one" not in first.value
    assert "private two" not in first.value
    assert "post" not in first.value
    assert first.value.count("local-path:mh_ps1_e4_path_") == 1
    assert first.counts == {"path": 1}
    assert second.value == first.value
    assert second.counts == {}


@pytest.mark.parametrize("delimiter_length", [1, 2])
@pytest.mark.parametrize(("prefix", "separator"), RAW_PATH_GRAMMARS)
def test_same_run_backtick_wrappers_cannot_split_inner_path_segments(
    prefix: str,
    separator: str,
    delimiter_length: int,
) -> None:
    delimiter = "`" * delimiter_length
    source = (
        f"{delimiter}{prefix}{separator}{delimiter}private folder "
        f"{PRIVATE_PATH_CANARY}{delimiter}{separator}tail{delimiter}"
    )
    redactor = make_redactor()

    first = redactor.redact(source)
    second = redactor.redact(first.value)

    assert PRIVATE_PATH_CANARY not in first.value
    assert "private folder" not in first.value
    assert first.value.startswith(delimiter)
    assert first.value.endswith(delimiter)
    assert first.value.count("local-path:mh_ps1_e4_path_") == 1
    assert first.counts == {"path": 1}
    for surface in (
        repr(first),
        render_untrusted_evidence(first.value, format="markdown"),
        render_untrusted_evidence(first.value, format="html"),
    ):
        assert PRIVATE_PATH_CANARY not in surface
    assert second.value == first.value
    assert second.counts == {}


@pytest.mark.parametrize(
    "source",
    [
        f"'`/home/operator/{PRIVATE_PATH_CANARY}`'",
        f'"`/home/operator/{PRIVATE_PATH_CANARY}`"',
        f"'`/home/operator/{PRIVATE_PATH_CANARY}`' now",
        f'"`/home/operator/{PRIVATE_PATH_CANARY}`", now',
        f"'`/home/operator/{PRIVATE_PATH_CANARY}`' ratio 1/2 and pattern a/b",
        f'"`/home/operator/{PRIVATE_PATH_CANARY}`" ratio 1/2 and pattern a/b',
        f"<span>`/home/operator/{PRIVATE_PATH_CANARY}`</span>",
    ],
)
def test_backtick_paths_close_before_outer_quotes_and_html(source: str) -> None:
    redactor = make_redactor()

    first = redactor.redact(source)
    second = redactor.redact(first.value)

    assert PRIVATE_PATH_CANARY not in first.value
    assert first.value.count("local-path:mh_ps1_e4_path_") == 1
    assert first.counts == {"path": 1}
    for surface in (
        repr(first),
        render_untrusted_evidence(first.value, format="markdown"),
        render_untrusted_evidence(first.value, format="html"),
    ):
        assert PRIVATE_PATH_CANARY not in surface
    assert second.value == first.value
    assert second.counts == {}


@pytest.mark.parametrize("outer_quote", ['"', "'"])
@pytest.mark.parametrize("delimiter_length", [1, 2])
def test_separate_outer_quote_wrapped_backtick_paths_are_independent(
    delimiter_length: int,
    outer_quote: str,
) -> None:
    delimiter = "`" * delimiter_length
    second_canary = "second-private-canary-0123456789.txt"
    source = (
        f"{outer_quote}{delimiter}C:\\workspace\\one\\{PRIVATE_PATH_CANARY}"
        f"{delimiter}{outer_quote} "
        f"and ratio 1/2, pattern a/b, then {outer_quote}{delimiter}"
        f"\\\\server\\share\\two\\{second_canary}"
        f"{delimiter}{outer_quote}"
    )
    redactor = make_redactor()

    first = redactor.redact(source)
    second = redactor.redact(first.value)

    for canary in (PRIVATE_PATH_CANARY, second_canary):
        assert canary not in first.value
        assert canary not in repr(first)
        assert canary not in render_untrusted_evidence(first.value, format="markdown")
        assert canary not in render_untrusted_evidence(first.value, format="html")
    assert first.value.count("local-path:mh_ps1_e4_path_") == 2
    assert first.counts == {"path": 2}
    assert second.value == first.value
    assert second.counts == {}


@pytest.mark.parametrize("outer_quote", ['"', "'"])
@pytest.mark.parametrize("delimiter_length", [1, 2])
@pytest.mark.parametrize("prefix", NATIVE_WINDOWS_PATH_PREFIXES)
def test_outer_quote_wrapped_backtick_paths_fail_closed_on_cross_line_suffixes(
    prefix: str,
    delimiter_length: int,
    outer_quote: str,
) -> None:
    delimiter = "`" * delimiter_length
    source = (
        f"{outer_quote}{delimiter}{prefix}\\{delimiter}private{delimiter}{outer_quote}\n"
        f"{PRIVATE_PATH_CANARY}\\tail{delimiter}{outer_quote}"
    )

    assert_value_safe_delimiter_failure(source, PRIVATE_PATH_CANARY)


@pytest.mark.parametrize("suffix_separator", ["/", "\\"])
@pytest.mark.parametrize("joiner", [", ", " and ", "\n"])
@pytest.mark.parametrize("outer_quote", ['"', "'"])
@pytest.mark.parametrize("delimiter_length", [1, 2])
def test_outer_wrapper_suffixes_cannot_hide_behind_independent_marked_paths(
    delimiter_length: int,
    outer_quote: str,
    joiner: str,
    suffix_separator: str,
) -> None:
    delimiter = "`" * delimiter_length
    independent = f'"{delimiter}/safe/path{delimiter}"'
    source = (
        f"{outer_quote}{delimiter}C:\\workspace\\example\\{delimiter}private"
        f"{delimiter}{outer_quote}{joiner}{independent}{joiner}"
        f"{PRIVATE_PATH_CANARY}{suffix_separator}tail{delimiter}{outer_quote}"
    )

    assert_value_safe_delimiter_failure(source, PRIVATE_PATH_CANARY)


@pytest.mark.parametrize(
    "independent",
    [
        "/safe/path",
        "cwd:/safe/path",
        "./safe/path",
        "file:/safe/path",
        "D:\\safe\\path",
    ],
)
def test_outer_wrapper_suffixes_cannot_hide_behind_independent_raw_paths(
    independent: str,
) -> None:
    source = f"'`C:\\workspace\\example\\`private`', {independent}, {PRIVATE_PATH_CANARY}\\tail`'"

    assert_value_safe_delimiter_failure(source, PRIVATE_PATH_CANARY)


@pytest.mark.parametrize("segment_quote", ['"', "'"])
@pytest.mark.parametrize("delimiter_length", [1, 2])
@pytest.mark.parametrize("prefix", NATIVE_WINDOWS_PATH_PREFIXES)
def test_backtick_wrapped_native_paths_fail_closed_on_adjacent_quoted_segments(
    prefix: str,
    delimiter_length: int,
    segment_quote: str,
) -> None:
    delimiter = "`" * delimiter_length
    source = (
        f"{delimiter}{prefix}\\{delimiter}private one{delimiter}"
        f"{segment_quote}private two {PRIVATE_PATH_CANARY}{segment_quote}\\tail{delimiter}"
    )

    assert_value_safe_delimiter_failure(source, PRIVATE_PATH_CANARY)


@pytest.mark.parametrize("delimiter_length", [1, 2])
def test_backtick_wrapped_native_paths_fail_closed_before_opening_html(
    delimiter_length: int,
) -> None:
    delimiter = "`" * delimiter_length
    source = (
        f"{delimiter}C:\\Users\\operator\\{delimiter}private{delimiter}"
        f"<span>{PRIVATE_PATH_CANARY}</span>\\tail{delimiter}"
    )

    assert_value_safe_delimiter_failure(source, PRIVATE_PATH_CANARY)


@pytest.mark.parametrize("delimiter_length", [1, 2])
@pytest.mark.parametrize("outer_quote", ["", "'"])
def test_backtick_wrapped_native_paths_fail_closed_on_unclosed_adjacent_quote_tails(
    delimiter_length: int,
    outer_quote: str,
) -> None:
    delimiter = "`" * delimiter_length
    source = (
        f"{outer_quote}{delimiter}C:\\Users\\operator\\{delimiter}private{delimiter}"
        f"' private two {PRIVATE_PATH_CANARY}\\tail{delimiter}{outer_quote}"
    )

    assert_value_safe_delimiter_failure(source, PRIVATE_PATH_CANARY)


@pytest.mark.parametrize(
    "source",
    [
        f"/home/operator/``private ` marker {PRIVATE_PATH_CANARY}``/tail",
        f'/home/operator/"private \\"quoted\\" folder {PRIVATE_PATH_CANARY}"/tail',
        f"/home/example/pre'one'two'three folder {PRIVATE_PATH_CANARY}'/tail",
        f"/home/operator/'private {PRIVATE_PATH_CANARY}'/more\\ with\\ space/tail, status=ok",
    ],
)
def test_quoted_path_scanner_handles_inner_delimiters_direct_closes_and_escaped_spaces(
    source: str,
) -> None:
    redactor = make_redactor()

    first = redactor.redact(source)
    second = redactor.redact(first.value)

    assert PRIVATE_PATH_CANARY not in first.value
    assert first.value.count("local-path:mh_ps1_e4_path_") == 1
    assert first.counts == {"path": 1}
    assert second.value == first.value
    assert second.counts == {}


def test_unclosed_adjacent_path_segment_fails_with_value_safe_error() -> None:
    source = f"/home/operator/'private'/tail\"unclosed folder/{PRIVATE_PATH_CANARY}"

    assert_value_safe_delimiter_failure(source, PRIVATE_PATH_CANARY)


def test_literal_apostrophe_pairs_and_independent_labeled_lines_remain_supported() -> None:
    source = (
        f"/srv/O'Brien's/{PRIVATE_PATH_CANARY}\n"
        f"/srv/O'/api/{PRIVATE_PATH_CANARY}\n"
        "cwd:/home/operator/other-private-value"
    )
    redactor = make_redactor()

    first = redactor.redact(source)
    second = redactor.redact(first.value)

    assert PRIVATE_PATH_CANARY not in first.value
    assert "other-private-value" not in first.value
    assert first.value.count("local-path:mh_ps1_e4_path_") == 3
    assert first.counts == {"path": 3}
    assert second.value == first.value
    assert second.counts == {}


@pytest.mark.parametrize("delimiter", PATH_SEGMENT_DELIMITERS)
@pytest.mark.parametrize(
    ("prefix", "component", "suffix"),
    [
        ("file:", "/srv/private root", ""),
        ("/", "private root", "/tail"),
        ("//", "private server", "/share/tail"),
        ("./", "private root", "/tail"),
        ("../", "private root", "/tail"),
        ("~operator/", "private root", "/tail"),
        ("C:/", "private root", "/tail"),
        ("C:\\", "private root", "\\tail"),
        ("\\\\", "private server", "\\share\\tail"),
        ("\\\\server\\", "private share", "\\tail"),
        ("\\\\?\\UNC\\", "private server", "\\share\\tail"),
        ("\\\\服务器\\", "私密共享", "\\尾部"),
    ],
)
def test_quoted_root_components_are_anchored_as_complete_paths(
    prefix: str,
    component: str,
    suffix: str,
    delimiter: str,
) -> None:
    source = f"{prefix}{delimiter}{component} {PRIVATE_PATH_CANARY}{delimiter}{suffix}"
    redactor = make_redactor()

    first = redactor.redact(source)
    second = redactor.redact(first.value)

    assert PRIVATE_PATH_CANARY not in first.value
    assert "private" not in first.value
    assert "file:" not in first.value.casefold()
    assert first.value.count("local-path:mh_ps1_e4_path_") == 1
    assert first.counts == {"path": 1}
    assert second.value == first.value
    assert second.counts == {}


@pytest.mark.parametrize("delimiter", PATH_SEGMENT_DELIMITERS)
@pytest.mark.parametrize(("prefix", "separator"), RAW_PATH_GRAMMARS)
def test_unclosed_mid_component_quoted_paths_fail_with_value_safe_errors(
    prefix: str,
    separator: str,
    delimiter: str,
) -> None:
    source = f"{prefix}pre{delimiter}private folder{separator}{PRIVATE_PATH_CANARY}"

    assert_value_safe_delimiter_failure(source, PRIVATE_PATH_CANARY)


@pytest.mark.parametrize("closing", ["", "same"])
@pytest.mark.parametrize("next_component", ["folder", "folder:secret"])
@pytest.mark.parametrize("delimiter", PATH_SEGMENT_DELIMITERS)
@pytest.mark.parametrize(("prefix", "separator"), RAW_PATH_GRAMMARS)
def test_cross_line_path_continuations_fail_with_value_safe_errors(
    prefix: str,
    separator: str,
    delimiter: str,
    next_component: str,
    closing: str,
) -> None:
    suffix = delimiter if closing else ""
    source = (
        f"{prefix}{delimiter}{separator}private\n"
        f"{next_component}{separator}{PRIVATE_PATH_CANARY}{suffix}"
    )

    assert_value_safe_delimiter_failure(source, PRIVATE_PATH_CANARY)


@pytest.mark.parametrize("closed", [False, True])
@pytest.mark.parametrize("whitespace", UNICODE_PATH_WHITESPACE)
@pytest.mark.parametrize("delimiter", PATH_SEGMENT_DELIMITERS)
@pytest.mark.parametrize(("prefix", "separator"), RAW_PATH_GRAMMARS)
def test_unicode_whitespace_path_continuations_never_return_private_suffixes(
    prefix: str,
    separator: str,
    delimiter: str,
    whitespace: str,
    closed: bool,
) -> None:
    closing = delimiter if closed else ""
    source = (
        f"{prefix}{delimiter}{separator}private{whitespace}"
        f"folder{separator}{PRIVATE_PATH_CANARY}{closing}"
    )
    if not closed:
        assert_value_safe_delimiter_failure(source, PRIVATE_PATH_CANARY)
        return

    redactor = make_redactor()
    first = redactor.redact(source)
    second = redactor.redact(first.value)

    assert PRIVATE_PATH_CANARY not in first.value
    assert "folder" not in first.value
    assert first.value.count("local-path:mh_ps1_e4_path_") == 1
    assert first.counts == {"path": 1}
    assert second.value == first.value
    assert second.counts == {}


@pytest.mark.parametrize(
    "source",
    [
        f"/home/operator/O'/api/{PRIVATE_PATH_CANARY}",
        f"C:/Users/operator/O'/api/{PRIVATE_PATH_CANARY}",
    ],
)
def test_apostrophes_inside_raw_supported_paths_are_path_data(source: str) -> None:
    redactor = make_redactor()

    first = redactor.redact(source)
    second = redactor.redact(first.value)

    assert PRIVATE_PATH_CANARY not in first.value
    assert first.value.count("local-path:mh_ps1_e4_path_") == 1
    assert first.counts == {"path": 1}
    assert second.value == first.value
    assert second.counts == {}


@pytest.mark.parametrize("terminator", ['"', "`", "<", ">"])
@pytest.mark.parametrize(
    "prefix",
    [
        "file:/home/operator",
        "/home/operator",
        "C:/Users/operator",
        "./operator",
        "../operator",
        "~operator/private",
        r"\\server\share\operator",
        r"\\?\UNC\server\share\operator",
    ],
)
def test_unclosed_path_continuations_fail_safe_for_every_raw_grammar(
    prefix: str,
    terminator: str,
) -> None:
    source = f"{prefix}'/private{terminator}folder/{PRIVATE_PATH_CANARY}"

    assert_value_safe_delimiter_failure(source, PRIVATE_PATH_CANARY)


@pytest.mark.parametrize("whitespace", (" ", *UNICODE_PATH_WHITESPACE))
@pytest.mark.parametrize(("prefix", "separator"), RAW_PATH_GRAMMARS)
def test_unquoted_space_continuations_are_pseudonymized_as_complete_paths(
    prefix: str,
    separator: str,
    whitespace: str,
) -> None:
    source = (
        f"{prefix}{separator}Private{whitespace}Folder{separator}{PRIVATE_PATH_CANARY}, "
        "status=healthy"
    )
    redactor = make_redactor()

    first = redactor.redact(source)
    second = redactor.redact(first.value)

    assert PRIVATE_PATH_CANARY not in first.value
    assert "Folder" not in first.value
    assert first.value.count("local-path:mh_ps1_e4_path_") == 1
    assert first.value.endswith(", status=healthy")
    assert first.counts == {"path": 1}
    assert second.value == first.value
    assert second.counts == {}


@pytest.mark.parametrize("whitespace", (" ", *UNICODE_PATH_WHITESPACE))
@pytest.mark.parametrize(("prefix", "separator"), RAW_PATH_GRAMMARS)
def test_multi_space_and_multi_component_unquoted_paths_are_one_token(
    prefix: str,
    separator: str,
    whitespace: str,
) -> None:
    source = (
        f"{prefix}{separator}Private{whitespace}Folder{separator}"
        f"More{whitespace}Space{whitespace}Name{separator}{PRIVATE_PATH_CANARY}, "
        "status=healthy"
    )
    redactor = make_redactor()

    first = redactor.redact(source)
    second = redactor.redact(first.value)

    assert PRIVATE_PATH_CANARY not in first.value
    assert "Folder" not in first.value
    assert "Space" not in first.value
    assert first.value.count("local-path:mh_ps1_e4_path_") == 1
    assert first.value.endswith(", status=healthy")
    assert first.counts == {"path": 1}
    for surface in (
        repr(first),
        render_untrusted_evidence(first.value, format="markdown"),
        render_untrusted_evidence(first.value, format="html"),
    ):
        assert PRIVATE_PATH_CANARY not in surface
    assert second.value == first.value
    assert second.counts == {}


@pytest.mark.parametrize(
    "wrapped",
    [
        "{path}",
        "cwd={path}",
        "({path})",
        "<code>{path}</code>",
        "```text\n{path}\n```",
    ],
)
def test_multi_space_continuations_are_safe_across_markup_wrappers(wrapped: str) -> None:
    path = f"/home/operator/Private Folder/More Space Name/{PRIVATE_PATH_CANARY}"
    source = wrapped.format(path=path)
    redactor = make_redactor()

    first = redactor.redact(source)
    second = redactor.redact(first.value)

    assert PRIVATE_PATH_CANARY not in first.value
    assert "Private Folder" not in first.value
    assert first.value.count("local-path:mh_ps1_e4_path_") == 1
    assert first.counts == {"path": 1}
    for surface in (
        repr(first),
        render_untrusted_evidence(first.value, format="markdown"),
        render_untrusted_evidence(first.value, format="html"),
    ):
        assert PRIVATE_PATH_CANARY not in surface
    assert second.value == first.value
    assert second.counts == {}


@pytest.mark.parametrize("whitespace", (" ", *UNICODE_PATH_WHITESPACE))
@pytest.mark.parametrize(("prefix", "separator"), RAW_PATH_GRAMMARS)
def test_ambiguous_multi_space_components_fail_closed_without_values(
    prefix: str,
    separator: str,
    whitespace: str,
) -> None:
    source = (
        f"{prefix}{separator}Private{whitespace}Folder{whitespace}With{whitespace}"
        f"Spaces{separator}{PRIVATE_PATH_CANARY}"
    )

    assert_value_safe_continuation_failure(source, PRIVATE_PATH_CANARY)


@pytest.mark.parametrize("whitespace", (" ", *UNICODE_PATH_WHITESPACE))
@pytest.mark.parametrize(("prefix", "separator"), RAW_PATH_GRAMMARS)
def test_ambiguous_plain_text_cannot_hide_before_an_independent_raw_path(
    prefix: str,
    separator: str,
    whitespace: str,
) -> None:
    source = (
        f"{prefix}{separator}Private{whitespace}Folder{whitespace}"
        f"{PRIVATE_PATH_CANARY}{whitespace}/safe/tail"
    )

    assert_value_safe_continuation_failure(source, PRIVATE_PATH_CANARY)


@pytest.mark.parametrize(("prefix", "separator"), RAW_PATH_GRAMMARS)
def test_ambiguous_plain_text_cannot_cross_a_raw_path_line_boundary(
    prefix: str,
    separator: str,
) -> None:
    source = f"{prefix}{separator}Private Folder\n{PRIVATE_PATH_CANARY}{separator}tail"

    assert_value_safe_continuation_failure(source, PRIVATE_PATH_CANARY)


@pytest.mark.parametrize(("prefix", "separator"), RAW_PATH_GRAMMARS)
def test_ambiguous_plain_text_cannot_hide_behind_a_url_placeholder(
    prefix: str,
    separator: str,
) -> None:
    source = f"{prefix}{separator}Private {PRIVATE_PATH_CANARY}https://example.test/api/tail"

    assert_value_safe_continuation_failure(source, PRIVATE_PATH_CANARY)


@pytest.mark.parametrize("encoded_secret", ["secret/value", "secret%2Fvalue"])
@pytest.mark.parametrize(("prefix", "separator"), RAW_PATH_GRAMMARS)
def test_ambiguous_plain_text_cannot_hide_behind_a_secret_placeholder(
    prefix: str,
    separator: str,
    encoded_secret: str,
) -> None:
    source = f"{prefix}{separator}Private {PRIVATE_PATH_CANARY}{encoded_secret}"

    assert_value_safe_continuation_failure(
        source,
        PRIVATE_PATH_CANARY,
        known_secrets=("secret/value",),
    )


@pytest.mark.parametrize(("prefix", "separator"), RAW_PATH_GRAMMARS)
def test_independent_urls_remain_supported_after_complete_raw_paths(
    prefix: str,
    separator: str,
) -> None:
    safe_url = "https://example.test/api/tail"
    source = f"{prefix}{separator}{PRIVATE_PATH_CANARY} {safe_url}"
    redactor = make_redactor()

    first = redactor.redact(source)
    second = redactor.redact(first.value)

    assert PRIVATE_PATH_CANARY not in first.value
    assert safe_url in first.value
    assert first.value.count("local-path:mh_ps1_e4_path_") == 1
    assert first.counts == {"path": 1}
    assert second.value == first.value
    assert second.counts == {}


@pytest.mark.parametrize("whitespace", (" ", *UNICODE_PATH_WHITESPACE))
@pytest.mark.parametrize(("prefix", "separator"), RAW_PATH_GRAMMARS)
def test_adjacent_independent_raw_paths_remain_supported_without_plain_text(
    prefix: str,
    separator: str,
    whitespace: str,
) -> None:
    source = f"{prefix}{separator}{PRIVATE_PATH_CANARY}{whitespace}/safe/tail"
    redactor = make_redactor()

    first = redactor.redact(source)
    second = redactor.redact(first.value)

    assert PRIVATE_PATH_CANARY not in first.value
    assert first.value.count("local-path:mh_ps1_e4_path_") == 2
    assert first.counts == {"path": 2}
    assert second.value == first.value
    assert second.counts == {}


@pytest.mark.parametrize("whitespace", (" ", *UNICODE_PATH_WHITESPACE))
@pytest.mark.parametrize(("prefix", "separator"), RAW_PATH_GRAMMARS)
def test_separator_free_tail_after_space_continuation_fails_closed(
    prefix: str,
    separator: str,
    whitespace: str,
) -> None:
    source = (
        f"{prefix}{separator}Private{whitespace}Folder{separator}More{whitespace}"
        f"{PRIVATE_PATH_CANARY}"
    )

    assert_value_safe_continuation_failure(source, PRIVATE_PATH_CANARY)


def test_path_followed_by_terminated_prose_and_slash_text_keeps_the_prose() -> None:
    source = (
        "read /home/operator/private.json, status then/ratio and "
        "C:\\Users\\operator\\private.json status=healthy then\\ratio"
    )

    result = make_redactor().redact(source)

    assert result.value.count("local-path:mh_ps1_e4_path_") == 2
    assert ", status " in result.value
    assert " status=healthy " in result.value
    assert "then/ratio" in result.value
    assert "then\\ratio" in result.value
    assert result.counts == {"path": 2}


def test_unterminated_prose_with_later_slash_is_rejected_as_ambiguous() -> None:
    source = f"read /home/operator/{PRIVATE_PATH_CANARY} status then/private-tail"

    assert_value_safe_continuation_failure(source, PRIVATE_PATH_CANARY)


@pytest.mark.parametrize(
    "source",
    [
        "/custom-mount/private/component.json",
        "//private-server/share/private/component.json",
        "./private/component.json",
        "../../private/component.json",
        f"{PRIVILEGED_HOME}/private/component\\ with\\ spaces.json",
        "C:\\Users\\operator\\private\\component\\ with\\ spaces.json",
        "\\\\private-server\\share\\private\\component\\ with\\ spaces.json",
        "\\\\?\\UNC\\private-server\\share\\private\\component.json",
        "\\\\服务器\\共享\\私密\\组件.json",
        f'"{PRIVILEGED_HOME}/private/component with spaces.json"',
        f"'{PRIVILEGED_HOME}/private/组件.json'",
        "'\\\\服务器\\共享 目录\\私密 组件.json'",
    ],
)
def test_marked_local_path_grammars_are_pseudonymized_without_root_allowlists(
    source: str,
) -> None:
    result = make_redactor().redact(f"read {source}; then continue")

    assert source not in result.value
    assert "private/component" not in result.value
    assert "local-path:mh_ps1_e4_path_" in result.value
    assert result.value.endswith("; then continue")
    assert result.counts == {"path": 1}


@pytest.mark.parametrize("label", ["cwd", "home"])
def test_colon_delimited_posix_paths_are_pseudonymized(label: str) -> None:
    source = f"{label}:/home/operator/private/component.json"

    result = make_redactor().redact(source)

    assert result.value.startswith(f"{label}:local-path:mh_ps1_e4_path_")
    assert "/home/operator" not in result.value
    assert result.counts == {"path": 1}


def test_ordinary_apostrophes_and_separate_quoted_paths_keep_their_prose() -> None:
    source = (
        f"don't change O'Brien's prose; read '{APOSTROPHE_HOME}/first file.json' "
        "and '/data/second file.json'."
    )

    result = make_redactor().redact(source)

    assert result.value.startswith("don't change O'Brien's prose; read 'local-path:")
    assert "' and 'local-path:" in result.value
    assert result.value.endswith("'.")
    assert "first file" not in result.value
    assert "second file" not in result.value
    assert result.counts == {"path": 2}


@pytest.mark.parametrize(
    "source",
    [
        r'read "/home/operator/A\\\"B/private-canary.txt"',
        r"read \"/home/operator/private folder/private-canary.txt\"",
        "read `/home/operator/private folder/private-canary.txt`",
        r"read `/home/operator/A\`B/private-canary.txt`",
        "read ``/home/operator/A`B/private folder/private-canary.txt`` now",
        "<code>/home/operator/A<B`C/private-canary.txt</code>",
        '<code class="language-text">  /home/operator/private-canary.txt</code>',
        "<code>\n/home/operator/private folder/private-canary.txt\n</code>",
        '<code data-value="'
        + ("x" * 257)
        + '">/home/operator/private folder/private-canary.txt</code>',
        "```text\n/home/operator/private folder/private-canary.txt\n```",
        "```" + ("x" * 257) + "\n/home/operator/private folder/private-canary.txt\n```",
        "~~~\n/home/operator/private folder/private-canary.txt\n~~~",
        r'''read "/home/operator/A<B`C/private-canary.txt"''',
        "read '/home/operator/private \"folder\"/private-canary.txt'",
        "read 'file:///home/operator/private folder/private-canary.txt'",
        "read '../private folder/private-canary.txt'",
        "read 'C:\\Users\\operator\\private folder\\private-canary.txt'",
        "read '~operator/private folder/private-canary.txt'",
        json.dumps(r"\\private-server\share\private-canary.txt"),
    ],
)
def test_delimited_and_serialized_paths_are_pseudonymized_as_one_value(source: str) -> None:
    redactor = make_redactor()

    first = redactor.redact(source)
    second = redactor.redact(first.value)

    assert "private-canary" not in first.value
    assert "private-server" not in first.value
    assert first.value.count("local-path:mh_ps1_e4_path_") == 1
    assert first.counts == {"path": 1}
    assert second.value == first.value
    assert second.counts == {}


def test_non_path_code_spans_are_preserved_and_unclosed_marked_paths_fail_closed() -> None:
    redactor = make_redactor()
    source = "<code>status: healthy</code>"

    result = redactor.redact(source)

    assert result.value == source
    assert result.counts == {}
    for unclosed_non_path in ("<code>status: healthy", "```text\nstatus: healthy"):
        preserved = redactor.redact(unclosed_non_path)
        assert preserved.value == unclosed_non_path
        assert preserved.counts == {}
    for unclosed in (
        'read "/home/operator/private folder/private-canary.txt',
        "<code>/home/operator/private folder/private-canary.txt",
        "```text\n/home/operator/private folder/private-canary.txt",
        "read ``/home/operator/A`B/private folder/private-canary.txt",
    ):
        with pytest.raises(PrivacyError, match="MH_PRIVACY_REDACT_DELIMITER"):
            redactor.redact(unclosed)


@pytest.mark.parametrize("root", FILESYSTEM_URL_ROOTS)
def test_filesystem_root_shaped_http_paths_are_intentionally_pseudonymized(root: str) -> None:
    source = f"https://example.test/{root}/operator/private-canary.txt"

    result = make_redactor().redact(source)

    assert f"/{root}/operator" not in result.value
    assert result.value.startswith("https://example.test/local-path:mh_ps1_e4_path_")
    assert result.counts == {"path": 1, "url": 1}


@pytest.mark.parametrize("root", ["api", "app", "data"])
def test_non_filesystem_http_control_paths_are_preserved(root: str) -> None:
    source = f"https://example.test/{root}/v1"

    result = make_redactor().redact(source)

    assert result.value == source
    assert result.counts == {}


@pytest.mark.parametrize("label", ["file", "cwd", "workspace-root"])
@pytest.mark.parametrize("encoded", [False, True])
def test_labeled_filesystem_paths_inside_http_paths_are_removed_whole(
    label: str,
    encoded: bool,
) -> None:
    labeled_path = f"{label}:/home/operator/{PRIVATE_PATH_CANARY}"
    embedded = quote(labeled_path, safe="") if encoded else labeled_path
    source = f"https://example.test/api/{embedded}"
    redactor = make_redactor()

    first = redactor.redact(source)
    second = redactor.redact(first.value)

    assert label not in first.value
    assert "home/operator" not in first.value
    assert PRIVATE_PATH_CANARY not in first.value
    assert first.value.startswith("https://example.test/local-path:mh_ps1_e4_path_")
    assert first.counts == {"path": 1, "url": 1}
    assert second.value == first.value
    assert second.counts == {}


@pytest.mark.parametrize(
    "embedded",
    [
        "key=file:/home/operator/private-canary.txt",
        "x:file:/home/operator/private-canary.txt",
        ";file:/home/operator/private-canary.txt",
        "key%3Dfile%3A/home/operator/private-canary.txt",
    ],
)
def test_labeled_url_paths_are_detected_after_non_alphanumeric_boundaries(
    embedded: str,
) -> None:
    source = f"https://example.test/api/{embedded}"

    result = make_redactor().redact(source)

    assert "home/operator" not in result.value
    assert "private-canary" not in result.value
    assert result.value.startswith("https://example.test/local-path:mh_ps1_e4_path_")
    assert result.counts == {"path": 1, "url": 1}


@pytest.mark.parametrize("prefix", ["", "api/", "download/", "proxy/v1/"])
@pytest.mark.parametrize("root", FILESYSTEM_URL_ROOTS)
def test_filesystem_url_roots_are_detected_at_every_segment_position(
    prefix: str,
    root: str,
) -> None:
    source = f"https://example.test/{prefix}{root}/operator/{PRIVATE_PATH_CANARY}"

    result = make_redactor().redact(source)

    assert root + "/operator" not in result.value
    assert PRIVATE_PATH_CANARY not in result.value
    assert result.value.startswith("https://example.test/local-path:mh_ps1_e4_path_")
    assert result.counts == {"path": 1, "url": 1}


@pytest.mark.parametrize("segment", ["homebrew", "homepage", "procedure", "systems"])
def test_filesystem_url_root_lookalike_segments_are_preserved(segment: str) -> None:
    source = f"https://example.test/api/{segment}/resource"

    result = make_redactor().redact(source)

    assert result.value == source
    assert result.counts == {}


@pytest.mark.parametrize("label", ["file", "cwd"])
@pytest.mark.parametrize("root", ["api", "app", "data"])
def test_labeled_non_filesystem_http_control_paths_are_preserved(label: str, root: str) -> None:
    source = f"https://example.test/v1/{label}:/{root}/resource"

    result = make_redactor().redact(source)

    assert result.value == source
    assert result.counts == {}


@pytest.mark.parametrize("typed", [False, True])
@pytest.mark.parametrize(
    ("path", "private_value", "category"),
    [
        (
            f"/home%2Foperator%2F{PRIVATE_PATH_CANARY}",
            PRIVATE_PATH_CANARY,
            "path",
        ),
        (
            f"/%68ome/operator/{PRIVATE_PATH_CANARY}",
            PRIVATE_PATH_CANARY,
            "path",
        ),
        (
            f"/%2Fhome%2Foperator%2F{PRIVATE_PATH_CANARY}",
            PRIVATE_PATH_CANARY,
            "path",
        ),
        (
            f"/C:%5CUsers%5Coperator%5C{PRIVATE_PATH_CANARY}",
            PRIVATE_PATH_CANARY,
            "path",
        ),
        (
            f"/%5C%5Cserver%5Cshare%5C{PRIVATE_PATH_CANARY}",
            PRIVATE_PATH_CANARY,
            "path",
        ),
        (
            f"/C:\\Users\\operator\\{PRIVATE_PATH_CANARY}",
            PRIVATE_PATH_CANARY,
            "path",
        ),
        (
            f"/\\\\server\\share\\{PRIVATE_PATH_CANARY}",
            PRIVATE_PATH_CANARY,
            "path",
        ),
        (
            f"/%252fhome%252foperator%252f{PRIVATE_PATH_CANARY}",
            PRIVATE_PATH_CANARY,
            "path",
        ),
        (
            f"/trace/person%40example.test/{PRIVATE_PATH_CANARY}",
            "person@example.test",
            "email",
        ),
        (
            f"/trace/312%2D555%2D0199/{PRIVATE_PATH_CANARY}",
            "312-555-0199",
            "phone",
        ),
        (
            f"/trace/192%2E0%2E2%2E42/{PRIVATE_PATH_CANARY}",
            "192.0.2.42",
            "ip",
        ),
        (
            f"/trace/%5B2001%3Adb8%3A%3A42%5D/{PRIVATE_PATH_CANARY}",
            "2001:db8::42",
            "ip",
        ),
        (
            f"/trace/[2001:db8::42]/{PRIVATE_PATH_CANARY}",
            "2001:db8::42",
            "ip",
        ),
    ],
)
def test_url_components_are_classified_on_a_single_decoded_view_and_removed_whole(
    path: str,
    private_value: str,
    category: str,
    typed: bool,
) -> None:
    source = f"https://example.test{path}"
    redactor = make_redactor()

    first = redactor.redact_url(source) if typed else redactor.redact(source)
    second = redactor.redact(first.value)

    assert PRIVATE_PATH_CANARY not in first.value
    assert private_value not in first.value
    assert first.value.startswith("https://example.test/local-path:mh_ps1_e4_path_")
    assert first.counts["path"] == 1
    assert first.counts["url"] == 1
    if category != "path":
        assert first.counts[category] == 1
    for surface in (
        repr(first),
        render_untrusted_evidence(first.value, format="markdown"),
        render_untrusted_evidence(first.value, format="html"),
    ):
        assert PRIVATE_PATH_CANARY not in surface
        assert private_value not in surface
    assert second.value == first.value
    assert second.counts == {}


def test_ambiguous_slashes_are_not_treated_as_local_paths() -> None:
    source = "ratio 1/2 and root /"

    result = make_redactor().redact(source)

    assert result.value == source
    assert result.counts == {}


def test_local_path_redaction_is_idempotent() -> None:
    redactor = make_redactor()
    first = redactor.redact(
        "read cwd:/custom-mount/private/component.json, "
        "file://host/share/O'Brien/private.json?cursor=private#private, "
        "and \\\\?\\UNC\\host\\share\\private.json"
    )
    second = redactor.redact(first.value)

    assert second.value == first.value
    assert second.counts == {}


def test_unicode_line_endings_and_unsafe_controls_are_normalized() -> None:
    result = make_redactor().redact("café\r\nline\u202e\x1b[31m")

    assert result.value == "café\nline[31m"
    assert result.counts == {"control": 2}


def test_redactor_metadata_and_results_do_not_expose_registered_values() -> None:
    private_value = "fixture-value-not-for-output"
    redactor = make_redactor(private_value)
    result = redactor.redact(private_value)

    assert redactor.version == "r2-e4"
    assert redactor.known_secret_count == 1
    assert private_value not in repr(redactor)
    assert private_value not in repr(result)
    with pytest.raises(TypeError):
        result.counts["secret"] = 0


def test_internal_placeholder_prefix_collision_is_avoided_without_changing_text() -> None:
    source = "MHREDACTIONPLACEHOLDER is ordinary retained text"

    result = make_redactor().redact(source)

    assert result.value == source
    assert result.counts == {}


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


def test_email_no_match_runtime_scales_near_linearly_at_the_input_ceiling() -> None:
    redactor = make_redactor()
    small = ("'a" * 2_048)[:4_096]
    large = ("'a" * 32_760)[:65_520]

    small_started = perf_counter()
    small_result = redactor.redact(small)
    small_elapsed = perf_counter() - small_started

    large_started = perf_counter()
    with pytest.raises(PrivacyError, match="MH_PRIVACY_REDACT_OUTPUT_LARGE"):
        redactor.redact(large)
    large_elapsed = perf_counter() - large_started

    assert small_result.value == small
    assert small_result.counts == {}
    assert large_elapsed < 2.0
    assert large_elapsed <= max(0.5, small_elapsed * 40)


def test_terminal_quote_path_scanning_scales_near_linearly_to_the_input_ceiling() -> None:
    redactor = make_redactor()
    sizes = (8_192, 16_384, 32_768, 60_000)
    elapsed: list[float] = []

    redactor.redact("/a' x " * 32)
    for size in sizes:
        source = ("/a' x " * ((size // 6) + 1))[:size]
        started = perf_counter()
        with pytest.raises(PrivacyError, match="MH_PRIVACY_REDACT_OUTPUT_LARGE"):
            redactor.redact(source)
        elapsed.append(perf_counter() - started)

    assert elapsed[-1] < 2.0
    assert elapsed[-1] <= max(0.75, elapsed[0] * 16)


def test_ambiguous_adjacent_delimiter_failure_scales_to_the_input_ceiling() -> None:
    redactor = make_redactor()
    sizes = (8_192, 16_384, 32_768, 60_000)
    elapsed: list[float] = []

    for size in sizes:
        body = ('`x`"a' * ((size // 5) + 1))[: max(0, size - 20)]
        source = f"`C:\\Users\\operator\\{body}`"
        started = perf_counter()
        with pytest.raises(PrivacyError, match="MH_PRIVACY_REDACT_DELIMITER"):
            redactor.redact(source)
        elapsed.append(perf_counter() - started)

    assert elapsed[-1] < 2.0
    assert elapsed[-1] <= max(0.75, elapsed[0] * 16)


def test_outer_wrapper_suffix_index_scales_to_the_input_ceiling(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import milhouse.privacy.redact as redact_module

    repetitions = 9_000
    source = '"`/a`" ' * repetitions
    original = redact_module._is_escaped
    calls = 0

    def bounded_is_escaped(value: str, index: int) -> bool:
        nonlocal calls
        calls += 1
        if calls > repetitions * 8:
            pytest.fail("backtick wrapper parsing exceeded its linear operation budget")
        return original(value, index)

    monkeypatch.setattr(redact_module, "_is_escaped", bounded_is_escaped)
    started = perf_counter()
    with pytest.raises(PrivacyError, match="MH_PRIVACY_REDACT_OUTPUT_LARGE"):
        make_redactor().redact(source)
    elapsed = perf_counter() - started

    assert calls <= repetitions * 8
    assert elapsed < 2.0


def test_redactor_constructor_is_strict_and_bounded() -> None:
    with pytest.raises(PrivacyError, match="MH_PRIVACY_REDACTOR_PSEUDONYMIZER"):
        LayeredRedactor(object())  # type: ignore[arg-type]
    with pytest.raises(PrivacyError, match="MH_PRIVACY_SECRET_SET"):
        LayeredRedactor(Pseudonymizer(KEY), known_secrets=["private-value"])  # type: ignore[arg-type]
    with pytest.raises(PrivacyError, match="MH_PRIVACY_SECRET_SET"):
        LayeredRedactor(Pseudonymizer(KEY), known_secrets=("private-value",) * 129)
