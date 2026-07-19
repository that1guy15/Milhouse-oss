import hashlib
import io
import subprocess
import tarfile
from pathlib import Path

import pytest

from scripts import gitleaks
from scripts.gitleaks import GitleaksError


class _Response(io.BytesIO):
    def __enter__(self) -> "_Response":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


class _Opener:
    def __init__(self, payload: bytes | Exception) -> None:
        self.payload = payload

    def open(self, _request: object, timeout: int) -> _Response:
        assert timeout == 30
        if isinstance(self.payload, Exception):
            raise self.payload
        return _Response(self.payload)


def _archive(path: Path, members: list[tuple[str, bytes, bytes | None]]) -> Path:
    with tarfile.open(path, "w:gz") as bundle:
        for name, content, kind in members:
            info = tarfile.TarInfo(name)
            if kind is None:
                info.size = len(content)
                bundle.addfile(info, io.BytesIO(content))
            else:
                info.type = kind
                if kind == tarfile.SYMTYPE:
                    info.linkname = "target"
                bundle.addfile(info)
    return path


def _valid_archive(path: Path, payload: bytes = b"synthetic executable\n") -> Path:
    return _archive(
        path,
        [
            ("README.md", b"fixture\n", None),
            ("gitleaks", payload, None),
        ],
    )


@pytest.mark.parametrize(
    ("system", "machine", "expected"),
    [
        ("Darwin", "arm64", ("darwin", "arm64")),
        ("Linux", "aarch64", ("linux", "arm64")),
        ("Linux", "AMD64", ("linux", "x64")),
        ("Darwin", "x86_64", ("darwin", "x64")),
    ],
)
def test_platform_key_normalizes_supported_architectures(
    monkeypatch: pytest.MonkeyPatch,
    system: str,
    machine: str,
    expected: tuple[str, str],
) -> None:
    monkeypatch.setattr(gitleaks.platform, "system", lambda: system)
    monkeypatch.setattr(gitleaks.platform, "machine", lambda: machine)
    assert gitleaks._platform_key() == expected


def test_platform_key_rejects_unsupported_host(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(gitleaks.platform, "system", lambda: "Other")
    monkeypatch.setattr(gitleaks.platform, "machine", lambda: "mystery")
    with pytest.raises(GitleaksError, match="unsupported platform"):
        gitleaks._platform_key()


def test_default_cache_honors_explicit_and_xdg_locations(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    explicit = tmp_path / "explicit"
    monkeypatch.setenv("MILHOUSE_TOOL_CACHE", str(explicit))
    assert gitleaks._default_cache() == explicit

    monkeypatch.delenv("MILHOUSE_TOOL_CACHE")
    xdg = tmp_path / "xdg"
    monkeypatch.setenv("XDG_CACHE_HOME", str(xdg))
    assert gitleaks._default_cache() == xdg / "milhouse"

    monkeypatch.delenv("XDG_CACHE_HOME")
    monkeypatch.setattr(gitleaks.Path, "home", lambda: tmp_path / "home")
    assert gitleaks._default_cache() == tmp_path / "home" / ".cache" / "milhouse"


def test_digest_helpers_are_streaming_and_deterministic(tmp_path: Path) -> None:
    payload = b"deterministic fixture"
    path = tmp_path / "payload"
    path.write_bytes(payload)
    expected = hashlib.sha256(payload).hexdigest()

    assert gitleaks._digest(io.BytesIO(payload)) == expected
    assert gitleaks._file_digest(path) == expected


def test_safe_redirect_rejects_non_https_or_non_github_asset_hosts() -> None:
    handler = gitleaks.SafeRedirect()
    request = gitleaks.urllib.request.Request("https://github.com/example")

    with pytest.raises(GitleaksError, match="outside the GitHub asset hosts"):
        handler.redirect_request(request, io.BytesIO(), 302, "redirect", {}, "http://github.com/x")
    with pytest.raises(GitleaksError, match="outside the GitHub asset hosts"):
        handler.redirect_request(
            request,
            io.BytesIO(),
            302,
            "redirect",
            {},
            "https://example.invalid/x",
        )

    redirected = handler.redirect_request(
        request,
        io.BytesIO(),
        302,
        "redirect",
        gitleaks.http.client.HTTPMessage(),
        "https://release-assets.githubusercontent.com/asset",
    )
    assert redirected is not None
    assert redirected.full_url == "https://release-assets.githubusercontent.com/asset"


def test_download_writes_only_checksum_matching_bounded_payload(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = b"archive fixture"
    monkeypatch.setattr(
        gitleaks.urllib.request,
        "build_opener",
        lambda *_handlers: _Opener(payload),
    )
    destination = tmp_path / "archive"

    gitleaks._download("https://github.com/asset", destination, hashlib.sha256(payload).hexdigest())

    assert destination.read_bytes() == payload
    assert destination.stat().st_mode & 0o777 == 0o600


def test_download_removes_partial_or_checksum_mismatched_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = b"too large"
    monkeypatch.setattr(
        gitleaks.urllib.request,
        "build_opener",
        lambda *_handlers: _Opener(payload),
    )
    monkeypatch.setattr(gitleaks, "MAX_ARCHIVE_BYTES", 2)
    destination = tmp_path / "oversized"
    with pytest.raises(GitleaksError, match="exceeds"):
        gitleaks._download("https://github.com/asset", destination, "0" * 64)
    assert not destination.exists()

    monkeypatch.setattr(gitleaks, "MAX_ARCHIVE_BYTES", 1024)
    destination = tmp_path / "mismatch"
    with pytest.raises(GitleaksError, match="SHA-256"):
        gitleaks._download("https://github.com/asset", destination, "0" * 64)
    assert not destination.exists()


def test_download_removes_destination_after_reader_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        gitleaks.urllib.request,
        "build_opener",
        lambda *_handlers: _Opener(OSError("offline")),
    )
    destination = tmp_path / "partial"
    with pytest.raises(OSError, match="offline"):
        gitleaks._download("https://github.com/asset", destination, "0" * 64)
    assert not destination.exists()


def test_archive_inspection_and_extraction_accept_one_safe_binary(tmp_path: Path) -> None:
    payload = b"synthetic executable\n"
    archive = _valid_archive(tmp_path / "valid.tar.gz", payload)

    member, digest = gitleaks._binary_member(archive)
    assert member.name == "gitleaks"
    assert digest == hashlib.sha256(payload).hexdigest()

    destination = tmp_path / "gitleaks"
    gitleaks._extract_binary(archive, member, destination)
    assert destination.read_bytes() == payload
    assert destination.stat().st_mode & 0o777 == 0o700


@pytest.mark.parametrize(
    ("members", "message"),
    [
        ([("../gitleaks", b"x", None)], "unsafe path"),
        ([("gitleaks", b"", tarfile.SYMTYPE)], "link or special"),
        ([("README", b"x", None)], "does not contain"),
        (
            [("one/gitleaks", b"x", None), ("two/gitleaks", b"x", None)],
            "multiple binaries",
        ),
    ],
)
def test_archive_inspection_rejects_unsafe_inventory(
    tmp_path: Path,
    members: list[tuple[str, bytes, bytes | None]],
    message: str,
) -> None:
    archive = _archive(tmp_path / "invalid.tar.gz", members)
    with pytest.raises(GitleaksError, match=message):
        gitleaks._binary_member(archive)


def test_archive_inspection_rejects_member_count_and_size_bounds(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    many = [(f"file-{index}", b"", None) for index in range(33)]
    with pytest.raises(GitleaksError, match="too many members"):
        gitleaks._binary_member(_archive(tmp_path / "many.tar.gz", many))

    archive = _valid_archive(tmp_path / "large.tar.gz", b"large")
    monkeypatch.setattr(gitleaks, "MAX_ARCHIVE_BYTES", 2)
    with pytest.raises(GitleaksError, match="member exceeds"):
        gitleaks._binary_member(archive)


def test_invalid_archive_is_normalized(tmp_path: Path) -> None:
    archive = tmp_path / "invalid.tar.gz"
    archive.write_bytes(b"not a tar archive")
    with pytest.raises(GitleaksError, match="cannot inspect"):
        gitleaks._binary_member(archive)


def test_archive_operations_fail_closed_when_tarfile_cannot_supply_member_streams(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    member = tarfile.TarInfo("gitleaks")
    member.size = 1

    class MissingStreamArchive:
        def __enter__(self) -> "MissingStreamArchive":
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def getmembers(self) -> list[tarfile.TarInfo]:
            return [member]

        def extractfile(self, _member: tarfile.TarInfo) -> None:
            return None

    monkeypatch.setattr(
        gitleaks.tarfile,
        "open",
        lambda *_args, **_kwargs: MissingStreamArchive(),
    )
    with pytest.raises(GitleaksError, match="cannot read the gitleaks executable"):
        gitleaks._binary_member(tmp_path / "archive.tar.gz")
    with pytest.raises(GitleaksError, match="cannot extract the gitleaks executable"):
        gitleaks._extract_binary(tmp_path / "archive.tar.gz", member, tmp_path / "gitleaks")


@pytest.mark.parametrize(
    ("completed", "raises"),
    [
        (subprocess.CompletedProcess([], 0, stdout="gitleaks 8.30.1\n", stderr=""), False),
        (subprocess.CompletedProcess([], 0, stdout="v8.30.1\n", stderr=""), False),
        (subprocess.CompletedProcess([], 0, stdout="8.0.0\n", stderr=""), True),
        (subprocess.CompletedProcess([], 2, stdout="8.30.1\n", stderr=""), True),
    ],
)
def test_version_verification_requires_the_exact_release(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    completed: subprocess.CompletedProcess[str],
    raises: bool,
) -> None:
    monkeypatch.setattr(gitleaks.subprocess, "run", lambda *_args, **_kwargs: completed)
    if raises:
        with pytest.raises(GitleaksError, match="unexpected version"):
            gitleaks._verify_version(tmp_path / "gitleaks")
    else:
        gitleaks._verify_version(tmp_path / "gitleaks")


def test_version_verification_normalizes_execution_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def timeout(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired("gitleaks", 1)

    monkeypatch.setattr(gitleaks.subprocess, "run", timeout)
    with pytest.raises(GitleaksError, match="cannot run"):
        gitleaks._verify_version(tmp_path / "gitleaks")


def test_ensure_gitleaks_uses_a_preverified_cached_archive_without_network(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key = ("test", "x64")
    asset = "gitleaks-test.tar.gz"
    archive_source = _valid_archive(tmp_path / "source.tar.gz")
    archive_digest = gitleaks._file_digest(archive_source)
    root = tmp_path / "cache" / "gitleaks" / gitleaks.GITLEAKS_VERSION / "test-x64"
    root.mkdir(parents=True)
    (root / asset).write_bytes(archive_source.read_bytes())
    monkeypatch.setattr(gitleaks, "ASSETS", {key: (asset, archive_digest)})
    monkeypatch.setattr(gitleaks, "_platform_key", lambda: key)
    monkeypatch.setattr(gitleaks, "_verify_version", lambda _binary: None)
    monkeypatch.setattr(
        gitleaks,
        "_download",
        lambda *_args: pytest.fail("network bootstrap must not run for a valid cache"),
    )

    binary = gitleaks.ensure_gitleaks(tmp_path / "cache")

    assert binary.read_bytes() == b"synthetic executable\n"


def test_ensure_gitleaks_reuses_a_matching_cached_binary_without_reextracting(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key = ("test", "x64")
    asset = "gitleaks-test.tar.gz"
    payload = b"synthetic executable\n"
    archive_source = _valid_archive(tmp_path / "source.tar.gz", payload)
    root = tmp_path / "cache" / "gitleaks" / gitleaks.GITLEAKS_VERSION / "test-x64"
    root.mkdir(parents=True)
    (root / asset).write_bytes(archive_source.read_bytes())
    binary = root / "gitleaks"
    binary.write_bytes(payload)
    monkeypatch.setattr(
        gitleaks,
        "ASSETS",
        {key: (asset, gitleaks._file_digest(archive_source))},
    )
    monkeypatch.setattr(gitleaks, "_platform_key", lambda: key)
    monkeypatch.setattr(gitleaks, "_verify_version", lambda _binary: None)
    monkeypatch.setattr(
        gitleaks,
        "_download",
        lambda *_args: pytest.fail("a matching cached archive must not be downloaded"),
    )
    monkeypatch.setattr(
        gitleaks,
        "_extract_binary",
        lambda *_args: pytest.fail("a matching cached binary must not be replaced"),
    )

    assert gitleaks.ensure_gitleaks(tmp_path / "cache") == binary


def test_ensure_gitleaks_replaces_invalid_cached_files_offline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key = ("test", "x64")
    asset = "gitleaks-test.tar.gz"
    archive_source = _valid_archive(tmp_path / "source.tar.gz")
    archive_bytes = archive_source.read_bytes()
    archive_digest = hashlib.sha256(archive_bytes).hexdigest()
    root = tmp_path / "cache" / "gitleaks" / gitleaks.GITLEAKS_VERSION / "test-x64"
    root.mkdir(parents=True)
    (root / asset).write_bytes(b"invalid cache")
    stale_binary = root / "gitleaks"
    stale_binary.write_bytes(b"stale")
    monkeypatch.setattr(gitleaks, "ASSETS", {key: (asset, archive_digest)})
    monkeypatch.setattr(gitleaks, "_platform_key", lambda: key)
    monkeypatch.setattr(gitleaks, "_verify_version", lambda _binary: None)

    def offline_download(_url: str, destination: Path, expected: str) -> None:
        assert expected == archive_digest
        destination.write_bytes(archive_bytes)

    monkeypatch.setattr(gitleaks, "_download", offline_download)

    binary = gitleaks.ensure_gitleaks(tmp_path / "cache")

    assert binary.read_bytes() == b"synthetic executable\n"


def test_ensure_gitleaks_rejects_unsafe_cache_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key = ("test", "x64")
    monkeypatch.setattr(gitleaks, "ASSETS", {key: ("asset.tar.gz", "0" * 64)})
    monkeypatch.setattr(gitleaks, "_platform_key", lambda: key)
    root = tmp_path / "cache" / "gitleaks" / gitleaks.GITLEAKS_VERSION / "test-x64"
    root.parent.mkdir(parents=True)
    root.write_text("unsafe\n", encoding="utf-8")

    with pytest.raises(GitleaksError, match="not a safe directory"):
        gitleaks.ensure_gitleaks(tmp_path / "cache")


def test_gitleaks_main_prints_path_ready_and_forwards_arguments(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    binary = tmp_path / "gitleaks"
    monkeypatch.setattr(gitleaks, "ensure_gitleaks", lambda _cache: binary)
    assert gitleaks.main(["--print-path"]) == 0
    assert str(binary) in capsys.readouterr().out

    assert gitleaks.main([]) == 0
    assert "ready" in capsys.readouterr().out

    monkeypatch.setattr(
        gitleaks.subprocess,
        "run",
        lambda command, check: subprocess.CompletedProcess(command, 17),
    )
    assert gitleaks.main(["--", "dir", "."]) == 17


def test_gitleaks_main_fails_closed_on_bootstrap_or_execution_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unavailable(_cache: Path | None) -> Path:
        raise GitleaksError("offline")

    monkeypatch.setattr(gitleaks, "ensure_gitleaks", unavailable)
    with pytest.raises(SystemExit) as caught:
        gitleaks.main([])
    assert caught.value.code == 1

    monkeypatch.setattr(gitleaks, "ensure_gitleaks", lambda _cache: tmp_path / "gitleaks")

    def broken(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        raise OSError("cannot execute")

    monkeypatch.setattr(gitleaks.subprocess, "run", broken)
    with pytest.raises(SystemExit) as caught:
        gitleaks.main(["dir", "."])
    assert caught.value.code == 1
