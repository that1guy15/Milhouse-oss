import socket
from pathlib import Path

import pytest

from scripts import check_links
from scripts.check_links import LinkError, anchors, slug, validate


def test_github_style_slugs_and_duplicate_heading_suffixes(tmp_path: Path) -> None:
    page = tmp_path / "README.md"
    page.write_text(
        "\n".join(
            (
                "# Release 1.0: `Milhouse`_OSS",
                "## Repeated heading",
                "## Repeated heading",
                "[release](#release-10-milhouse_oss)",
                "[repeat](#repeated-heading-1)",
                "",
            )
        ),
        encoding="utf-8",
    )

    assert slug("Release 1.0: `Milhouse`_OSS") == "release-10-milhouse_oss"
    assert "repeated-heading-1" in anchors(page)
    assert validate((page,), tmp_path.resolve(), False, 1, 1.0, 0) == (2, 0)


def test_local_link_cannot_escape_repo_through_encoded_traversal(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    source = repo / "README.md"
    source.write_text("[outside](%2e%2e/outside.md)\n", encoding="utf-8")
    (tmp_path / "outside.md").write_text("# Outside\n", encoding="utf-8")

    with pytest.raises(LinkError, match="escapes the repository"):
        validate((source,), repo.resolve(), False, 1, 1.0, 0)


def test_missing_local_anchor_fails_closed(tmp_path: Path) -> None:
    page = tmp_path / "README.md"
    page.write_text("# Present\n\n[missing](#absent)\n", encoding="utf-8")

    with pytest.raises(LinkError, match="missing anchor"):
        validate((page,), tmp_path.resolve(), False, 1, 1.0, 0)


def test_markdown_discovery_is_recursive_but_skips_generated_trees(tmp_path: Path) -> None:
    root_page = tmp_path / "README.md"
    root_page.write_text("# Root\n", encoding="utf-8")
    docs = tmp_path / "docs"
    docs.mkdir()
    nested = docs / "guide.md"
    nested.write_text("# Guide\n", encoding="utf-8")
    generated = tmp_path / "build"
    generated.mkdir()
    (generated / "ignored.md").write_text("# Ignored\n", encoding="utf-8")

    assert check_links.markdown_files((tmp_path,)) == (root_page, nested)
    assert check_links.markdown_files((root_page,)) == (root_page,)


def test_markdown_discovery_rejects_missing_non_markdown_and_symlink_inputs(
    tmp_path: Path,
) -> None:
    text = tmp_path / "README.txt"
    text.write_text("not Markdown\n", encoding="utf-8")
    with pytest.raises(LinkError, match="expected a Markdown file"):
        check_links.markdown_files((text,))
    with pytest.raises(LinkError, match="input does not exist"):
        check_links.markdown_files((tmp_path / "missing.md",))

    target = tmp_path / "target.md"
    target.write_text("# Target\n", encoding="utf-8")
    link = tmp_path / "link.md"
    link.symlink_to(target)
    with pytest.raises(LinkError, match="symlink inputs"):
        check_links.markdown_files((link,))

    directory = tmp_path / "docs"
    directory.mkdir()
    (directory / "nested.md").symlink_to(target)
    with pytest.raises(LinkError, match="symlink Markdown"):
        check_links.markdown_files((directory,))


def test_markdown_discovery_rejects_a_directory_without_markdown(tmp_path: Path) -> None:
    (tmp_path / "file.txt").write_text("text\n", encoding="utf-8")
    with pytest.raises(LinkError, match="no Markdown files"):
        check_links.markdown_files((tmp_path,))


def test_visible_line_and_link_extraction_ignore_fenced_examples(tmp_path: Path) -> None:
    page = tmp_path / "README.md"
    page.write_text(
        "\n".join(
            (
                "[visible](guide.md)",
                "```md",
                "[ignored](missing.md)",
                "```",
                "<a href='other.md'>other</a>",
                "<https://visible.test/path>",
                "~~~",
                "<https://ignored.test/path>",
                "![ignored](image.png)",
                "~~~",
                "",
            )
        ),
        encoding="utf-8",
    )

    assert check_links.extract(page) == (
        (1, "guide.md"),
        (5, "other.md"),
        (6, "https://visible.test/path"),
    )


def test_uri_autolinks_do_not_duplicate_angle_bracket_markdown_links(tmp_path: Path) -> None:
    page = tmp_path / "README.md"
    page.write_text(
        "[wrapped](<https://example.test/wrapped>) "
        "<https://example.test/standalone?first=1&amp;second=2>\n",
        encoding="utf-8",
    )

    assert check_links.extract(page) == (
        (1, "https://example.test/wrapped"),
        (1, "https://example.test/standalone?first=1&second=2"),
    )


def test_failing_uri_autolink_is_probed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    page = tmp_path / "README.md"
    page.write_text("<https://example.test/failing>\n", encoding="utf-8")

    def fail_probe(_url: str, _timeout: float, _redirects: int) -> None:
        raise LinkError("autolink failed")

    monkeypatch.setattr(check_links, "check_external", fail_probe)

    with pytest.raises(LinkError, match="autolink failed"):
        validate((page,), tmp_path.resolve(), True, 1, 1.0, 0)


def test_destination_supports_titles_and_angle_brackets() -> None:
    assert check_links.destination("guide.md 'title'") == "guide.md"
    assert check_links.destination("<guide with spaces.md> 'title'") == "guide with spaces.md"
    assert check_links.destination("  ") == ""
    with pytest.raises(LinkError, match="unterminated angle-bracket"):
        check_links.destination("<guide.md")


def test_explicit_anchors_and_unicode_headings_are_collected(tmp_path: Path) -> None:
    page = tmp_path / "README.md"
    page.write_text(
        "# Café & Tea\n<a id='explicit-anchor'></a>\n# Café & Tea\n",
        encoding="utf-8",
    )

    assert anchors(page) == {"café--tea", "café--tea-1", "explicit-anchor"}


def test_markdown_readers_reject_non_utf8_evidence(tmp_path: Path) -> None:
    page = tmp_path / "README.md"
    page.write_bytes(b"# invalid\n\xff")

    with pytest.raises(LinkError, match="cannot read UTF-8 Markdown"):
        anchors(page)
    with pytest.raises(LinkError, match="cannot read UTF-8 Markdown"):
        check_links.extract(page)


def _public_endpoint(address: str = "8.8.8.8", port: int = 443) -> check_links.PublicEndpoint:
    return check_links.PublicEndpoint(
        family=socket.AF_INET,
        socket_type=socket.SOCK_STREAM,
        protocol=6,
        address=(address, port),
    )


def test_public_endpoints_reject_local_unresolved_and_non_global_addresses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(LinkError, match="prohibited local hostname"):
        check_links._public_endpoints("localhost", 443)
    with pytest.raises(LinkError, match="prohibited local hostname"):
        check_links._public_endpoints("HOST.LOCAL.", 443)

    def unresolved(*_args: object, **_kwargs: object) -> list[object]:
        raise socket.gaierror("unresolved")

    monkeypatch.setattr(check_links.socket, "getaddrinfo", unresolved)
    with pytest.raises(LinkError, match="cannot resolve"):
        check_links._public_endpoints("example.invalid", 443)

    monkeypatch.setattr(check_links.socket, "getaddrinfo", lambda *_args, **_kwargs: [])
    with pytest.raises(LinkError, match="resolved no addresses"):
        check_links._public_endpoints("example.invalid", 443)

    monkeypatch.setattr(
        check_links.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))],
    )
    with pytest.raises(LinkError, match="outside public address space"):
        check_links._public_endpoints("example.invalid", 443)

    monkeypatch.setattr(
        check_links.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))],
    )
    assert check_links._public_endpoints("example.test", 443) == (_public_endpoint(),)


def test_public_endpoints_filter_unsupported_shapes_and_deduplicate_ipv6(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ipv6 = ("2001:4860:4860::8888", 443, 0, 0)
    monkeypatch.setattr(
        check_links.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [
            (socket.AF_UNIX, socket.SOCK_STREAM, 0, "", "/tmp/socket"),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443, 0)),
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:4860:4860::8888", 443)),
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ipv6),
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ipv6),
        ],
    )

    assert check_links._public_endpoints("example.test", 443) == (
        check_links.PublicEndpoint(socket.AF_INET6, socket.SOCK_STREAM, 6, ipv6),
    )

    monkeypatch.setattr(
        check_links.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [
            (socket.AF_UNIX, socket.SOCK_STREAM, 0, "", "/tmp/socket"),
        ],
    )
    with pytest.raises(LinkError, match="no supported public addresses"):
        check_links._public_endpoints("example.test", 443)


def test_connected_client_uses_only_approved_address_and_original_tls_hostname(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connected: list[tuple[str, int]] = []
    server_names: list[str] = []

    class FakeSocket:
        def settimeout(self, timeout: float) -> None:
            assert timeout == 1.0

        def connect(self, address: tuple[str, int]) -> None:
            connected.append(address)

        def close(self) -> None:
            return None

    raw = FakeSocket()
    monkeypatch.setattr(check_links.socket, "socket", lambda *_args: raw)

    class FakeContext:
        def wrap_socket(self, stream: FakeSocket, *, server_hostname: str) -> FakeSocket:
            assert stream is raw
            server_names.append(server_hostname)
            return stream

    monkeypatch.setattr(check_links.ssl, "create_default_context", FakeContext)
    monkeypatch.setattr(
        check_links.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: pytest.fail("the connector must not resolve the hostname again"),
    )

    client = check_links._connected_client(
        "example.test", 443, "https", _public_endpoint("8.8.4.4"), 1.0
    )
    try:
        assert client.sock is raw
        assert connected == [("8.8.4.4", 443)]
        assert server_names == ["example.test"]
    finally:
        client.close()


def test_connected_client_supports_http_and_closes_both_tls_sockets_on_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    closed: list[str] = []

    class FakeSocket:
        def __init__(self, label: str) -> None:
            self.label = label

        def settimeout(self, _timeout: float) -> None:
            return None

        def connect(self, _address: tuple[str, int]) -> None:
            return None

        def close(self) -> None:
            closed.append(self.label)

    raw = FakeSocket("raw")
    monkeypatch.setattr(check_links.socket, "socket", lambda *_args: raw)
    client = check_links._connected_client(
        "example.test", 80, "http", _public_endpoint(port=80), 1.0
    )
    assert client.sock is raw
    client.close()
    assert closed == ["raw"]

    closed.clear()
    raw = FakeSocket("raw")
    wrapped = FakeSocket("wrapped")
    monkeypatch.setattr(check_links.socket, "socket", lambda *_args: raw)

    class FakeContext:
        def wrap_socket(self, _stream: FakeSocket, *, server_hostname: str) -> FakeSocket:
            assert server_hostname == "example.test"
            return wrapped

    monkeypatch.setattr(check_links.ssl, "create_default_context", FakeContext)
    monkeypatch.setattr(
        check_links.http.client,
        "HTTPConnection",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            ValueError("synthetic constructor failure")
        ),
    )
    with pytest.raises(ValueError, match="constructor failure"):
        check_links._connected_client("example.test", 443, "https", _public_endpoint(), 1.0)
    assert closed == ["wrapped", "raw"]


def test_request_once_retries_only_approved_endpoints_and_bounds_get(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attempted: list[check_links.PublicEndpoint] = []
    requests: list[tuple[str, str, dict[str, str]]] = []
    closed: list[bool] = []

    class FakeResponse:
        status = 206

        def read(self, amount: int) -> bytes:
            assert amount == 1
            return b"x"

        def getheader(self, name: str) -> str | None:
            assert name == "Location"
            return None

    class FakeClient:
        def request(self, method: str, target: str, *, headers: dict[str, str]) -> None:
            requests.append((method, target, headers))

        def getresponse(self) -> FakeResponse:
            return FakeResponse()

        def close(self) -> None:
            closed.append(True)

    first = _public_endpoint("8.8.8.8")
    second = _public_endpoint("8.8.4.4")

    def connect(
        _host: str,
        _port: int,
        _scheme: str,
        endpoint: check_links.PublicEndpoint,
        _timeout: float,
    ) -> FakeClient:
        attempted.append(endpoint)
        if endpoint == first:
            raise OSError("synthetic unavailable endpoint")
        return FakeClient()

    monkeypatch.setattr(check_links, "_connected_client", connect)

    assert check_links._request_once(
        "example.test",
        443,
        "https",
        "/page?value=1",
        (first, second),
        "GET",
        1.0,
    ) == (206, None)
    assert attempted == [first, second]
    assert requests == [
        (
            "GET",
            "/page?value=1",
            {
                "User-Agent": "Milhouse-Link-Checker/1.0",
                "Accept": "*/*",
                "Range": "bytes=0-0",
            },
        )
    ]
    assert closed == [True]

    monkeypatch.setattr(
        check_links,
        "_connected_client",
        lambda *_args: (_ for _ in ()).throw(OSError("synthetic unavailable endpoint")),
    )
    with pytest.raises(LinkError, match="connection failed"):
        check_links._request_once("example.test", 443, "https", "/", (first, second), "HEAD", 1.0)


def test_external_check_accepts_success_and_head_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    resolutions: list[tuple[str, int]] = []

    def resolve(host: str, port: int) -> tuple[check_links.PublicEndpoint, ...]:
        resolutions.append((host, port))
        return (_public_endpoint(port=port),)

    monkeypatch.setattr(check_links, "_public_endpoints", resolve)
    methods: list[str] = []

    def success_request(*args: object) -> tuple[int, str | None]:
        methods.append(str(args[-2]))
        return 204, None

    monkeypatch.setattr(check_links, "_request_once", success_request)
    check_links.check_external("https://example.test/page", 1.0, 0)
    assert methods == ["HEAD"]
    assert resolutions == [("example.test", 443)]

    methods.clear()
    outcomes = iter(((405, None), (206, None)))

    def fallback_request(*args: object) -> tuple[int, str | None]:
        methods.append(str(args[-2]))
        return next(outcomes)

    monkeypatch.setattr(check_links, "_request_once", fallback_request)
    check_links.check_external("https://example.test/page", 1.0, 0)
    assert methods == ["HEAD", "GET"]

    outcomes = iter(((405, None), (500, None)))
    monkeypatch.setattr(check_links, "_request_once", lambda *_args: next(outcomes))
    with pytest.raises(LinkError, match="HTTP 500"):
        check_links.check_external("https://example.test/page", 1.0, 0)


def test_external_check_follows_bounded_redirects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    resolutions: list[str] = []

    def resolve(host: str, port: int) -> tuple[check_links.PublicEndpoint, ...]:
        resolutions.append(host)
        return (_public_endpoint(port=port),)

    monkeypatch.setattr(check_links, "_public_endpoints", resolve)
    outcomes = iter(((302, "/new"), (200, None)))
    monkeypatch.setattr(check_links, "_request_once", lambda *_args: next(outcomes))
    check_links.check_external("https://example.test/old", 1.0, 1)
    assert resolutions == ["example.test", "example.test"]

    monkeypatch.setattr(check_links, "_request_once", lambda *_args: (302, None))
    with pytest.raises(LinkError, match="has no Location"):
        check_links.check_external("https://example.test/old", 1.0, 1)

    monkeypatch.setattr(check_links, "_request_once", lambda *_args: (302, "/new"))
    with pytest.raises(LinkError, match="exceeded 0 redirect"):
        check_links.check_external("https://example.test/old", 1.0, 0)


def test_external_check_rejects_unsafe_or_failed_urls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(LinkError, match="unsupported external URL"):
        check_links.check_external("ftp://example.test/file", 1.0, 0)
    with pytest.raises(LinkError, match="credentials"):
        check_links.check_external("https://user@example.test/file", 1.0, 0)
    with pytest.raises(LinkError, match="invalid port"):
        check_links.check_external("https://example.test:99999/file", 1.0, 0)

    monkeypatch.setattr(
        check_links,
        "_public_endpoints",
        lambda _host, port: (_public_endpoint(port=port),),
    )
    monkeypatch.setattr(check_links, "_request_once", lambda *_args: (404, None))
    with pytest.raises(LinkError, match="HTTP 404"):
        check_links.check_external("https://example.test/missing", 1.0, 0)

    def unavailable(*_args: object) -> tuple[int, str | None]:
        raise LinkError("external URL connection failed")

    monkeypatch.setattr(check_links, "_request_once", unavailable)
    with pytest.raises(LinkError, match="connection failed"):
        check_links.check_external("https://example.test/page", 1.0, 0)


def test_validate_handles_directory_anchors_mailto_and_bounded_external_links(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guide = tmp_path / "guide"
    guide.mkdir()
    (guide / "README.md").write_text("# Introduction\n", encoding="utf-8")
    page = tmp_path / "README.md"
    page.write_text(
        "[guide](guide/#introduction)\n"
        "[mail](mailto:maintainer@example.invalid)\n"
        "[web](https://example.test/page#fragment)\n",
        encoding="utf-8",
    )
    probes: list[str] = []
    monkeypatch.setattr(
        check_links,
        "check_external",
        lambda url, _timeout, _redirects: probes.append(url),
    )

    assert validate((page,), tmp_path.resolve(), True, 1, 1.0, 0) == (3, 1)
    assert probes == ["https://example.test/page"]

    page.write_text("[one](https://one.test)\n[two](https://two.test)\n", encoding="utf-8")
    with pytest.raises(LinkError, match="external link count 2 exceeds"):
        validate((page,), tmp_path.resolve(), True, 1, 1.0, 0)


def test_validate_rejects_empty_and_non_markdown_anchor_targets(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    page = tmp_path / "README.md"
    page.write_text("# Page\n", encoding="utf-8")
    with monkeypatch.context() as patch:
        patch.setattr(check_links, "extract", lambda _source: ((1, ""),))
        with pytest.raises(LinkError, match="empty link destination"):
            validate((page,), tmp_path.resolve(), False, 1, 1.0, 0)

    asset = tmp_path / "asset.txt"
    asset.write_text("synthetic\n", encoding="utf-8")
    page.write_text("[asset](asset.txt#fragment)\n", encoding="utf-8")
    with pytest.raises(LinkError, match="anchor target is not Markdown"):
        validate((page,), tmp_path.resolve(), False, 1, 1.0, 0)


def test_validate_accepts_a_local_file_without_an_anchor(tmp_path: Path) -> None:
    guide = tmp_path / "guide.md"
    guide.write_text("# Guide\n", encoding="utf-8")
    page = tmp_path / "README.md"
    page.write_text("[guide](guide.md)\n", encoding="utf-8")

    assert validate((page,), tmp_path.resolve(), False, 1, 1.0, 0) == (1, 0)


@pytest.mark.parametrize(
    ("target", "message"),
    [
        ("mailto:invalid", "malformed mailto"),
        ("custom:value", "unsupported link scheme"),
        ("/absolute.md", "unsafe local link path"),
        ("folder\\file.md", "unsafe local link path"),
        ("%00file.md", "unsafe local link path"),
    ],
)
def test_validate_rejects_malformed_or_unsafe_link_targets(
    tmp_path: Path,
    target: str,
    message: str,
) -> None:
    page = tmp_path / "README.md"
    page.write_text(f"[target]({target})\n", encoding="utf-8")
    with pytest.raises(LinkError, match=message):
        validate((page,), tmp_path.resolve(), False, 1, 1.0, 0)


def test_link_main_validates_bounds_and_reports_errors(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    page = tmp_path / "README.md"
    page.write_text("# Page\n", encoding="utf-8")
    assert check_links.main(["--repo-root", str(tmp_path), str(page)]) == 0

    with pytest.raises(SystemExit) as caught:
        check_links.main(["--max-external", "0", str(page)])
    assert caught.value.code == 1

    missing = tmp_path / "missing.md"
    with pytest.raises(SystemExit) as caught:
        check_links.main([str(missing)])
    assert caught.value.code == 1
    assert "links:" in capsys.readouterr().err
