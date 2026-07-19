#!/usr/bin/env python3
"""Install and run the checksum-pinned gitleaks binary used by Milhouse."""

from __future__ import annotations

import argparse
import hashlib
import http.client
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.parse
import urllib.request
from collections.abc import Sequence
from pathlib import Path, PurePosixPath
from typing import IO, NoReturn

GITLEAKS_VERSION = "8.30.1"
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
ASSETS = {
    ("darwin", "arm64"): (
        "gitleaks_8.30.1_darwin_arm64.tar.gz",
        "b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5",
    ),
    ("darwin", "x64"): (
        "gitleaks_8.30.1_darwin_x64.tar.gz",
        "dfe101a4db2255fc85120ac7f3d25e4342c3c20cf749f2c20a18081af1952709",
    ),
    ("linux", "arm64"): (
        "gitleaks_8.30.1_linux_arm64.tar.gz",
        "e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080",
    ),
    ("linux", "x64"): (
        "gitleaks_8.30.1_linux_x64.tar.gz",
        "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb",
    ),
}
ALLOWED_DOWNLOAD_HOSTS = {
    "github.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
}


class GitleaksError(RuntimeError):
    """Raised when the scanner cannot be acquired or verified safely."""


def fail(message: str) -> NoReturn:
    print(f"gitleaks-bootstrap: {message}", file=sys.stderr)
    raise SystemExit(1)


def _platform_key() -> tuple[str, str]:
    system = platform.system().casefold()
    machine = platform.machine().casefold()
    architectures = {
        "aarch64": "arm64",
        "arm64": "arm64",
        "amd64": "x64",
        "x86_64": "x64",
    }
    architecture = architectures.get(machine)
    key = (system, architecture or "")
    if key not in ASSETS:
        raise GitleaksError(f"unsupported platform {system}/{machine}")
    return key


def _default_cache() -> Path:
    configured = os.environ.get("MILHOUSE_TOOL_CACHE")
    if configured:
        return Path(configured).expanduser()
    base = os.environ.get("XDG_CACHE_HOME")
    return (Path(base).expanduser() if base else Path.home() / ".cache") / "milhouse"


def _digest(stream: IO[bytes]) -> str:
    result = hashlib.sha256()
    while chunk := stream.read(1024 * 1024):
        result.update(chunk)
    return result.hexdigest()


def _file_digest(path: Path) -> str:
    with path.open("rb") as stream:
        return _digest(stream)


class SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        request: urllib.request.Request,
        file_pointer: IO[bytes],
        code: int,
        message: str,
        headers: http.client.HTTPMessage,
        new_url: str,
    ) -> urllib.request.Request | None:
        parsed = urllib.parse.urlsplit(new_url)
        if parsed.scheme != "https" or parsed.hostname not in ALLOWED_DOWNLOAD_HOSTS:
            raise GitleaksError("gitleaks download redirected outside the GitHub asset hosts")
        return super().redirect_request(request, file_pointer, code, message, headers, new_url)


def _download(url: str, destination: Path, expected: str) -> None:
    opener = urllib.request.build_opener(SafeRedirect)
    request = urllib.request.Request(url, headers={"User-Agent": "Milhouse-Tool-Bootstrap/1.0"})
    written = 0
    digest = hashlib.sha256()
    try:
        with opener.open(request, timeout=30) as response, destination.open("xb") as output:
            os.chmod(destination, 0o600)
            while chunk := response.read(1024 * 1024):
                written += len(chunk)
                if written > MAX_ARCHIVE_BYTES:
                    raise GitleaksError("gitleaks archive exceeds the 64 MiB safety bound")
                digest.update(chunk)
                output.write(chunk)
    except Exception:
        destination.unlink(missing_ok=True)
        raise
    if digest.hexdigest() != expected:
        destination.unlink(missing_ok=True)
        raise GitleaksError("downloaded gitleaks archive failed SHA-256 verification")


def _binary_member(archive: Path) -> tuple[tarfile.TarInfo, str]:
    try:
        with tarfile.open(archive, "r:gz") as bundle:
            members = bundle.getmembers()
            if len(members) > 32:
                raise GitleaksError("gitleaks archive contains too many members")
            binary: tarfile.TarInfo | None = None
            for member in members:
                name = PurePosixPath(member.name)
                if name.is_absolute() or ".." in name.parts or "\\" in member.name:
                    raise GitleaksError("gitleaks archive contains an unsafe path")
                if not (member.isfile() or member.isdir()):
                    raise GitleaksError("gitleaks archive contains a link or special file")
                if member.size > MAX_ARCHIVE_BYTES:
                    raise GitleaksError("gitleaks archive member exceeds the safety bound")
                if member.isfile() and name.name == "gitleaks":
                    if binary is not None:
                        raise GitleaksError("gitleaks archive contains multiple binaries")
                    binary = member
            if binary is None:
                raise GitleaksError("gitleaks archive does not contain its executable")
            stream = bundle.extractfile(binary)
            if stream is None:
                raise GitleaksError("cannot read the gitleaks executable from its archive")
            with stream:
                binary_digest = _digest(stream)
            return binary, binary_digest
    except (OSError, tarfile.TarError) as exc:
        raise GitleaksError(f"cannot inspect gitleaks archive: {exc}") from exc


def _extract_binary(archive: Path, member: tarfile.TarInfo, destination: Path) -> None:
    temporary = destination.with_name(f".{destination.name}.{os.getpid()}.tmp")
    temporary.unlink(missing_ok=True)
    try:
        with tarfile.open(archive, "r:gz") as bundle:
            source = bundle.extractfile(member)
            if source is None:
                raise GitleaksError("cannot extract the gitleaks executable")
            with source, temporary.open("xb") as output:
                shutil.copyfileobj(source, output, length=1024 * 1024)
        os.chmod(temporary, 0o700)
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def _verify_version(binary: Path) -> None:
    try:
        completed = subprocess.run(
            [str(binary), "version"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise GitleaksError(f"cannot run gitleaks: {exc}") from exc
    output = (completed.stdout or completed.stderr).strip()
    if completed.returncode != 0 or not re.fullmatch(
        rf"(?:gitleaks\s+)?v?{re.escape(GITLEAKS_VERSION)}", output, re.IGNORECASE
    ):
        raise GitleaksError("installed gitleaks executable has an unexpected version")


def ensure_gitleaks(cache_root: Path | None = None) -> Path:
    """Return a verified executable, downloading only its pinned official archive."""

    key = _platform_key()
    asset, expected_archive_digest = ASSETS[key]
    root = (
        (cache_root or _default_cache()).resolve() / "gitleaks" / GITLEAKS_VERSION / "-".join(key)
    )
    if root.exists() and (root.is_symlink() or not root.is_dir()):
        raise GitleaksError("gitleaks cache path is not a safe directory")
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(root, 0o700)
    archive = root / asset
    if archive.exists() and (
        archive.is_symlink() or _file_digest(archive) != expected_archive_digest
    ):
        archive.unlink()
    if not archive.exists():
        descriptor, temporary_name = tempfile.mkstemp(prefix=".download-", dir=root)
        os.close(descriptor)
        temporary = Path(temporary_name)
        temporary.unlink()
        url = f"https://github.com/gitleaks/gitleaks/releases/download/v{GITLEAKS_VERSION}/{asset}"
        _download(url, temporary, expected_archive_digest)
        os.replace(temporary, archive)
    member, expected_binary_digest = _binary_member(archive)
    binary = root / "gitleaks"
    if binary.exists() and (
        binary.is_symlink()
        or not binary.is_file()
        or _file_digest(binary) != expected_binary_digest
    ):
        binary.unlink()
    if not binary.exists():
        _extract_binary(archive, member, binary)
    _verify_version(binary)
    return binary


def parse_args(arguments: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache-dir", type=Path)
    parser.add_argument("--print-path", action="store_true")
    parser.add_argument("gitleaks_arguments", nargs=argparse.REMAINDER)
    return parser.parse_args(arguments)


def main(arguments: Sequence[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if arguments is None else arguments)
    try:
        binary = ensure_gitleaks(args.cache_dir)
    except (GitleaksError, OSError) as exc:
        fail(str(exc))
    if args.print_path:
        print(binary)
        return 0
    command: list[str] = args.gitleaks_arguments
    if command[:1] == ["--"]:
        command = command[1:]
    if not command:
        print(f"gitleaks-bootstrap: {GITLEAKS_VERSION} ready")
        return 0
    try:
        return subprocess.run([str(binary), *command], check=False).returncode
    except OSError as exc:
        fail(f"cannot run gitleaks: {exc}")


if __name__ == "__main__":
    raise SystemExit(main())
