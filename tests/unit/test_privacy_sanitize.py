import pytest

from milhouse.privacy import (
    PrivacyError,
    Pseudonymizer,
    sanitize_local_path,
    sanitize_url,
)

KEY = bytes(range(32))


def test_url_sanitization_removes_authority_secrets_fragment_and_unlisted_query() -> None:
    source = "https://operator:secret@example.test:443/a%2fb?q=ok&token=secret-value#fragment"
    result = sanitize_url(source, allowed_query_keys=frozenset({"q"}))

    assert result.value == "https://example.test/a%2Fb?q=ok"
    assert result.removed == frozenset({"userinfo", "query", "fragment"})
    for prohibited in ("operator", "secret", "token", "fragment"):
        assert prohibited not in result.value


def test_url_sanitization_normalizes_hosts_ports_paths_and_safe_query_order() -> None:
    result = sanitize_url(
        "HTTPS://Exämple.test:8443/é?q=z&empty=&q=a",
        allowed_query_keys=frozenset({"q", "empty"}),
    )

    assert result.value == "https://xn--exmple-cua.test:8443/%C3%A9?empty=&q=a&q=z"
    assert result.removed == frozenset()
    assert sanitize_url("http://[::1]:80/health").value == "http://[::1]/health"


def test_url_query_allowlist_still_rejects_unsafe_values() -> None:
    result = sanitize_url(
        "https://example.test/health?safe=alpha&safe=user%40example.test",
        allowed_query_keys=frozenset({"safe"}),
    )

    assert result.value == "https://example.test/health?safe=alpha"
    assert result.removed == frozenset({"query"})


@pytest.mark.parametrize(
    ("value", "code"),
    [
        ("ftp://example.test/file", "MH_PRIVACY_URL_SCHEME"),
        ("https:///missing-host", "MH_PRIVACY_URL_HOST"),
        ("https://example.test:0/", "MH_PRIVACY_URL_PORT"),
        ("https://example.test:99999/", "MH_PRIVACY_URL"),
        ("https://example.test/bad%zz", "MH_PRIVACY_URL_PATH"),
        ("https://example.test/has space", "MH_PRIVACY_URL"),
        ("https://example.test/\nheader", "MH_PRIVACY_URL"),
        ("https://" + ("a" * 8_192), "MH_PRIVACY_URL"),
        ("https://\u200d.test/", "MH_PRIVACY_URL_HOST"),
        ("https://" + ".".join(["a" * 63] * 4) + "/", "MH_PRIVACY_URL_HOST"),
        ("", "MH_PRIVACY_URL"),
        (b"https://example.test/", "MH_PRIVACY_URL"),
    ],
)
def test_invalid_urls_fail_with_stable_value_safe_errors(value: object, code: str) -> None:
    with pytest.raises(PrivacyError) as captured:
        sanitize_url(value)  # type: ignore[arg-type]

    assert captured.value.code == code
    if isinstance(value, str) and value:
        assert value not in str(captured.value)


@pytest.mark.parametrize(
    "allowlist",
    [
        {"safe"},
        frozenset({"bad key"}),
        frozenset(f"key{index}" for index in range(101)),
    ],
)
def test_url_query_allowlist_is_strict_and_bounded(allowlist: object) -> None:
    with pytest.raises(PrivacyError, match="MH_PRIVACY_URL_ALLOWLIST"):
        sanitize_url(
            "https://example.test/?safe=value",
            allowed_query_keys=allowlist,  # type: ignore[arg-type]
        )


def test_url_query_field_count_is_bounded() -> None:
    query = "&".join(f"field{index}=value" for index in range(101))

    with pytest.raises(PrivacyError, match="MH_PRIVACY_URL_QUERY"):
        sanitize_url(f"https://example.test/?{query}")


def test_local_paths_are_normalized_and_replaced_by_keyed_tokens() -> None:
    pseudonymizer = Pseudonymizer(KEY)
    posix = sanitize_local_path(
        "/Users/example/private/project/config.toml",
        pseudonymizer=pseudonymizer,
    )
    windows = sanitize_local_path(
        "C:\\Users\\example\\private\\project\\config.toml",
        pseudonymizer=pseudonymizer,
    )

    assert posix.startswith("local-path:mh_ps1_e1_path_")
    assert windows.startswith("local-path:mh_ps1_e1_path_")
    for output in (posix, windows):
        assert "example" not in output
        assert "config.toml" not in output


@pytest.mark.parametrize(
    "value",
    ["", "bad\npath", "bad\ud800path", "x" * 4_097, b"/private/path"],
)
def test_invalid_local_paths_are_value_safe(value: object) -> None:
    with pytest.raises(PrivacyError) as captured:
        sanitize_local_path(  # type: ignore[arg-type]
            value,
            pseudonymizer=Pseudonymizer(KEY),
        )

    if isinstance(value, str) and value:
        assert value not in str(captured.value)
