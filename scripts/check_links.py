#!/usr/bin/env python3
"""Check Markdown local links/anchors and optionally bounded public web links."""

from __future__ import annotations

import argparse
import html
import http.client
import ipaddress
import re
import socket
import ssl
import sys
import urllib.parse
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import NoReturn

LINK = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")
HTML_LINK = re.compile(r"\b(?:href|src)=[\"']([^\"']+)[\"']", re.IGNORECASE)
URI_AUTOLINK = re.compile(r"<(https?://[^\s<>]+)>", re.IGNORECASE)
HEADING = re.compile(r"^\s{0,3}(#{1,6})\s+(.+?)\s*#*\s*$")
EXPLICIT_ANCHOR = re.compile(r"<(?:a|[A-Za-z][^>]*)\s+(?:id|name)=[\"']([^\"']+)[\"']")
SKIP_PARTS = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "build",
    "dist",
    "site",
}


class LinkError(ValueError):
    """Raised for broken, unsafe, or unbounded links."""


def fail(message: str) -> NoReturn:
    print(f"links: {message}", file=sys.stderr)
    raise SystemExit(1)


def markdown_files(paths: Iterable[Path]) -> tuple[Path, ...]:
    files: set[Path] = set()
    for path in paths:
        if path.is_symlink():
            raise LinkError(f"{path}: symlink inputs are prohibited")
        if path.is_file():
            if path.suffix.lower() != ".md":
                raise LinkError(f"{path}: expected a Markdown file")
            files.add(path)
        elif path.is_dir():
            for candidate in path.rglob("*.md"):
                if any(part in SKIP_PARTS for part in candidate.parts):
                    continue
                if candidate.is_symlink():
                    raise LinkError(f"{candidate}: symlink Markdown is prohibited")
                files.add(candidate)
        else:
            raise LinkError(f"{path}: input does not exist")
    if not files:
        raise LinkError("no Markdown files selected")
    return tuple(sorted(files))


def visible_lines(text: str) -> Iterable[tuple[int, str]]:
    fence: str | None = None
    for number, line in enumerate(text.splitlines(), 1):
        marker = line.lstrip()[:3]
        if marker in {"```", "~~~"}:
            fence = None if fence == marker else marker if fence is None else fence
            continue
        if fence is None:
            yield number, line


def destination(raw: str) -> str:
    value = html.unescape(raw.strip())
    if value.startswith("<"):
        end = value.find(">")
        if end < 0:
            raise LinkError("unterminated angle-bracket link")
        return value[1:end]
    return value.split(maxsplit=1)[0] if value else ""


def slug(text: str) -> str:
    value = re.sub(r"<[^>]+>", "", re.sub(r"`([^`]*)`", r"\1", html.unescape(text)))
    value = value.strip().lower()
    value = "".join(character for character in value if character.isalnum() or character in " _-")
    return "".join("-" if character.isspace() else character for character in value)


def anchors(path: Path) -> set[str]:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise LinkError(f"{path}: cannot read UTF-8 Markdown: {exc}") from exc
    result: set[str] = set()
    counts: dict[str, int] = {}
    for _number, line in visible_lines(text):
        for explicit in EXPLICIT_ANCHOR.findall(line):
            result.add(html.unescape(explicit))
        match = HEADING.match(line)
        if match:
            base = slug(match.group(2))
            count = counts.get(base, 0)
            counts[base] = count + 1
            result.add(base if count == 0 else f"{base}-{count}")
    return result


def _append_extracted_link(
    links: list[tuple[int, str]],
    claimed: list[tuple[int, int]],
    number: int,
    match: re.Match[str],
    target: str,
) -> None:
    span = match.span()
    if any(span[0] < end and span[1] > start for start, end in claimed):
        return
    links.append((number, target))
    claimed.append(span)


def extract(path: Path) -> tuple[tuple[int, str], ...]:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise LinkError(f"{path}: cannot read UTF-8 Markdown: {exc}") from exc
    links: list[tuple[int, str]] = []
    for number, line in visible_lines(text):
        claimed: list[tuple[int, int]] = []
        for match in LINK.finditer(line):
            _append_extracted_link(links, claimed, number, match, destination(match.group(1)))
        for match in HTML_LINK.finditer(line):
            _append_extracted_link(
                links, claimed, number, match, html.unescape(match.group(1).strip())
            )
        for match in URI_AUTOLINK.finditer(line):
            _append_extracted_link(links, claimed, number, match, html.unescape(match.group(1)))
    return tuple(links)


SocketAddress = tuple[str, int] | tuple[str, int, int, int]


@dataclass(frozen=True, slots=True)
class PublicEndpoint:
    """One policy-approved numeric address for an external HTTP connection."""

    family: int
    socket_type: int
    protocol: int
    address: SocketAddress


def _public_endpoints(host: str, port: int) -> tuple[PublicEndpoint, ...]:
    normalized_host = host.casefold().rstrip(".")
    if normalized_host == "localhost" or normalized_host.endswith(".local"):
        raise LinkError("external URL resolves to a prohibited local hostname")
    try:
        addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise LinkError(f"cannot resolve external host {host!r}: {exc}") from exc
    if not addresses:
        raise LinkError(f"external host {host!r} resolved no addresses")

    approved: list[PublicEndpoint] = []
    for family, socket_type, protocol, _canonical_name, raw_address in addresses:
        if family not in {socket.AF_INET, socket.AF_INET6}:
            continue
        parsed = ipaddress.ip_address(raw_address[0])
        if not parsed.is_global:
            raise LinkError(f"external host {host!r} resolves outside public address space")
        if family == socket.AF_INET:
            if len(raw_address) != 2:
                continue
            address: SocketAddress = (str(parsed), int(raw_address[1]))
        else:
            if len(raw_address) != 4:
                continue
            address = (
                str(parsed),
                int(raw_address[1]),
                int(raw_address[2]),
                int(raw_address[3]),
            )
        endpoint = PublicEndpoint(
            family=int(family),
            socket_type=int(socket_type),
            protocol=protocol,
            address=address,
        )
        if endpoint not in approved:
            approved.append(endpoint)
    if not approved:
        raise LinkError(f"external host {host!r} resolved no supported public addresses")
    return tuple(approved)


def _connected_client(
    host: str,
    port: int,
    scheme: str,
    endpoint: PublicEndpoint,
    timeout: float,
) -> http.client.HTTPConnection:
    """Connect to an approved numeric endpoint while retaining HTTP/TLS hostname identity."""

    raw = socket.socket(endpoint.family, endpoint.socket_type, endpoint.protocol)
    connected: socket.socket | ssl.SSLSocket = raw
    try:
        raw.settimeout(timeout)
        raw.connect(endpoint.address)
        if scheme == "https":
            connected = ssl.create_default_context().wrap_socket(raw, server_hostname=host)
        client = http.client.HTTPConnection(host, port, timeout=timeout)
        client.sock = connected
        return client
    except (OSError, ValueError):
        connected.close()
        if connected is not raw:
            raw.close()
        raise


def _request_once(
    host: str,
    port: int,
    scheme: str,
    target: str,
    endpoints: Sequence[PublicEndpoint],
    method: str,
    timeout: float,
) -> tuple[int, str | None]:
    headers = {"User-Agent": "Milhouse-Link-Checker/1.0", "Accept": "*/*"}
    if method == "GET":
        headers["Range"] = "bytes=0-0"
    last_error: BaseException | None = None
    for endpoint in endpoints:
        client: http.client.HTTPConnection | None = None
        try:
            client = _connected_client(host, port, scheme, endpoint, timeout)
            client.request(method, target, headers=headers)
            response = client.getresponse()
            response.read(1)
            return response.status, response.getheader("Location")
        except (OSError, ValueError, http.client.HTTPException) as exc:
            last_error = exc
        finally:
            if client is not None:
                client.close()
    raise LinkError("external URL connection failed") from last_error


def check_external(url: str, timeout: float, redirects: int) -> None:
    current = url
    for _attempt in range(redirects + 1):
        parsed = urllib.parse.urlsplit(current)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise LinkError(f"unsupported external URL {url!r}")
        if parsed.username or parsed.password:
            raise LinkError("credentials in external URLs are prohibited")
        try:
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
        except ValueError as exc:
            raise LinkError(f"external URL has an invalid port: {url!r}") from exc
        endpoints = _public_endpoints(parsed.hostname, port)
        target = urllib.parse.urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
        status, location = _request_once(
            parsed.hostname,
            port,
            parsed.scheme,
            target,
            endpoints,
            "HEAD",
            timeout,
        )
        if status in {301, 302, 303, 307, 308}:
            if not location:
                raise LinkError(f"redirect for {url!r} has no Location")
            current = urllib.parse.urljoin(current, location)
            continue
        if 200 <= status < 300:
            return
        if status in {403, 405, 501}:
            fallback_status, _fallback_location = _request_once(
                parsed.hostname,
                port,
                parsed.scheme,
                target,
                endpoints,
                "GET",
                timeout,
            )
            if 200 <= fallback_status < 300:
                return
            raise LinkError(f"external URL returned HTTP {fallback_status}: {url!r}")
        raise LinkError(f"external URL returned HTTP {status}: {url!r}")
    raise LinkError(f"external URL exceeded {redirects} redirect(s): {url!r}")


def validate(
    paths: Sequence[Path],
    repo_root: Path,
    external: bool,
    limit: int,
    timeout: float,
    redirects: int,
) -> tuple[int, int]:
    cache: dict[Path, set[str]] = {}
    external_urls: set[str] = set()
    checked = 0
    for source in paths:
        for line, target in extract(source):
            checked += 1
            if not target:
                raise LinkError(f"{source}:{line}: empty link destination")
            parsed = urllib.parse.urlsplit(target)
            if parsed.scheme in {"http", "https"}:
                external_urls.add(urllib.parse.urlunsplit(parsed._replace(fragment="")))
                continue
            if parsed.scheme == "mailto":
                if "@" not in parsed.path:
                    raise LinkError(f"{source}:{line}: malformed mailto link")
                continue
            if parsed.scheme or parsed.netloc:
                raise LinkError(f"{source}:{line}: unsupported link scheme")
            raw_path = urllib.parse.unquote(parsed.path)
            if "\\" in raw_path or "\x00" in raw_path or raw_path.startswith("/"):
                raise LinkError(f"{source}:{line}: unsafe local link path")
            target_path = source if not raw_path else source.parent / raw_path
            try:
                resolved = target_path.resolve(strict=True)
                resolved.relative_to(repo_root)
            except (OSError, ValueError) as exc:
                raise LinkError(
                    f"{source}:{line}: local target is missing or escapes the repository"
                ) from exc
            if parsed.fragment:
                if resolved.is_dir():
                    candidates = [resolved / "README.md", resolved / "index.md"]
                    resolved = next((item for item in candidates if item.is_file()), resolved)
                if resolved.suffix.lower() != ".md" or not resolved.is_file():
                    raise LinkError(f"{source}:{line}: anchor target is not Markdown")
                available = cache.setdefault(resolved, anchors(resolved))
                fragment = urllib.parse.unquote(parsed.fragment)
                if fragment not in available:
                    raise LinkError(f"{source}:{line}: missing anchor #{fragment}")
    if external:
        if len(external_urls) > limit:
            raise LinkError(f"external link count {len(external_urls)} exceeds bound {limit}")
        for url in sorted(external_urls):
            check_external(url, timeout, redirects)
    return checked, len(external_urls) if external else 0


def parse_args(arguments: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*", type=Path, default=[Path(".")])
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--external", action="store_true")
    parser.add_argument("--max-external", type=int, default=50)
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--max-redirects", type=int, default=3)
    return parser.parse_args(arguments)


def main(arguments: Sequence[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if arguments is None else arguments)
    if args.max_external < 1 or not 0.1 <= args.timeout <= 30 or not 0 <= args.max_redirects <= 5:
        fail("invalid external-link safety bounds")
    try:
        root = args.repo_root.resolve(strict=True)
        files = markdown_files(args.paths)
        links, external = validate(
            files, root, args.external, args.max_external, args.timeout, args.max_redirects
        )
    except (LinkError, OSError) as exc:
        fail(str(exc))
    print(f"links: {len(files)} file(s), {links} link(s), {external} external probe(s) passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
