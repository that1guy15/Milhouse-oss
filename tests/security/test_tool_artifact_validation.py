import base64
import hashlib
import io
import json
import os
import runpy
import stat
import subprocess
import sys
import tarfile
import tomllib
import zipfile
from dataclasses import replace
from pathlib import Path
from typing import Self, cast

import pytest

from scripts import check_artifacts
from scripts.check_artifacts import (
    ArtifactError,
    Inventory,
    SourceInventory,
    inspect_sdist,
    inspect_source,
    inspect_wheel,
    install_smoke,
)

VERSION = "0.1.0a0"
SUMMARY = "Synthetic artifact validator fixture"
README = b"# Synthetic Milhouse fixture\n"
PROJECT_URL = "https://example.invalid/milhouse"
MANIFEST = json.dumps(
    {
        "distribution": "milhouse-observability",
        "import_package": "milhouse",
        "manifest_version": 1,
        "resources": ["py.typed", "resources/manifest.json"],
    },
    sort_keys=True,
).encode()


def _metadata_bytes(
    version: str = VERSION,
    *,
    project_url: str = PROJECT_URL,
) -> bytes:
    return (
        "Metadata-Version: 2.4\n"
        "Name: milhouse-observability\n"
        f"Version: {version}\n"
        f"Summary: {SUMMARY}\n"
        "Author: Milhouse contributors\n"
        "License-Expression: Apache-2.0\n"
        f"Project-URL: Repository, {project_url}\n"
        "Classifier: Typing :: Typed\n"
        "Requires-Python: <3.15,>=3.11\n"
        "Description-Content-Type: text/markdown\n"
        "License-File: LICENSE\n"
        "Requires-Dist: click<9,>=8.1\n"
        "Provides-Extra: receiver\n"
        'Requires-Dist: starlette<2,>=1; extra == "receiver"\n'
        "Dynamic: license-file\n\n"
    ).encode() + README


def _pyproject_bytes(
    *,
    console_target: str = "milhouse.cli:main",
    project_url: str = PROJECT_URL,
) -> bytes:
    return (
        "[project]\n"
        'name = "milhouse-observability"\n'
        'dynamic = ["version"]\n'
        f'description = "{SUMMARY}"\n'
        'readme = "README.md"\n'
        'requires-python = ">=3.11,<3.15"\n'
        'license = "Apache-2.0"\n'
        'license-files = ["LICENSE"]\n'
        'authors = [{ name = "Milhouse contributors" }]\n'
        'classifiers = ["Typing :: Typed"]\n'
        'dependencies = ["click>=8.1,<9"]\n'
        "[project.optional-dependencies]\n"
        'receiver = ["starlette>=1,<2"]\n'
        "[project.scripts]\n"
        f'milhouse = "{console_target}"\n'
        "[project.urls]\n"
        f'Repository = "{project_url}"\n'
    ).encode()


def _package_files(version: str = VERSION) -> dict[str, bytes]:
    return {
        "milhouse/__init__.py": f'__version__: str = "{version}"\n'.encode(),
        "milhouse/__main__.py": b"",
        "milhouse/cli/__init__.py": b"",
        "milhouse/cli/__main__.py": b"",
        "milhouse/cli/root.py": b"",
        "milhouse/py.typed": b"",
        "milhouse/resources/__init__.py": b"",
        "milhouse/resources/manifest.json": MANIFEST,
    }


def _minimal_wheel(
    tmp_path: Path,
    extra_member: str | None = None,
    *,
    license_bytes: bytes = b"Synthetic Apache-2.0 fixture\n",
    console_target: str = "milhouse.cli:main",
    project_url: str = PROJECT_URL,
) -> Path:
    version = VERSION
    dist_info = f"milhouse_observability-{version}.dist-info"
    members = _package_files()
    members.update(
        {
            f"{dist_info}/METADATA": _metadata_bytes(project_url=project_url),
            f"{dist_info}/WHEEL": b"Wheel-Version: 1.0\nTag: py3-none-any\n",
            f"{dist_info}/entry_points.txt": (
                f"[console_scripts]\nmilhouse = {console_target}\n"
            ).encode(),
            f"{dist_info}/licenses/LICENSE": license_bytes,
            f"{dist_info}/top_level.txt": b"milhouse\n",
        }
    )
    if extra_member is not None:
        members[extra_member] = b"undeclared\n"
    record_name = f"{dist_info}/RECORD"
    records = []
    for name, content in sorted(members.items()):
        digest = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=").decode()
        records.append(f"{name},sha256={digest},{len(content)}")
    records.append(f"{record_name},,")
    members[record_name] = ("\n".join(records) + "\n").encode()
    wheel = tmp_path / f"milhouse_observability-{version}-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in members.items():
            archive.writestr(name, content)
    return wheel


def _minimal_sdist(
    tmp_path: Path,
    extra_member: str | None = None,
    *,
    license_bytes: bytes = b"Synthetic Apache-2.0 fixture\n",
    console_target: str = "milhouse.cli:main",
    project_url: str = PROJECT_URL,
) -> Path:
    root = f"milhouse_observability-{VERSION}"
    egg_info = "src/milhouse_observability.egg-info"
    pyproject = _pyproject_bytes(console_target=console_target, project_url=project_url)
    members = {
        "CHANGELOG.md": b"changelog\n",
        "LICENSE": license_bytes,
        "MANIFEST.in": b"manifest\n",
        "PKG-INFO": _metadata_bytes(project_url=project_url),
        "README.md": README,
        "pyproject.toml": pyproject,
        "setup.cfg": b"[metadata]\n",
        f"{egg_info}/PKG-INFO": _metadata_bytes(project_url=project_url),
        f"{egg_info}/SOURCES.txt": b"sources\n",
        f"{egg_info}/dependency_links.txt": b"\n",
        f"{egg_info}/entry_points.txt": (
            f"[console_scripts]\nmilhouse = {console_target}\n"
        ).encode(),
        f"{egg_info}/requires.txt": b"click\n",
        f"{egg_info}/top_level.txt": b"milhouse\n",
    }
    members.update({f"src/{name}": content for name, content in _package_files().items()})
    if extra_member is not None:
        members[extra_member] = b"extra\n"
    path = tmp_path / f"milhouse_observability-{VERSION}.tar.gz"
    with tarfile.open(path, "w:gz") as archive:
        for relative, content in members.items():
            info = tarfile.TarInfo(f"{root}/{relative}")
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))
    return path


def _wheel_member_bytes(path: Path) -> dict[str, bytes]:
    with zipfile.ZipFile(path) as archive:
        return {name: archive.read(name) for name in archive.namelist() if not name.endswith("/")}


def _write_record_valid_wheel(path: Path, members: dict[str, bytes]) -> None:
    """Rewrite a synthetic wheel and regenerate RECORD for an inventory mutation."""

    dist_info = f"milhouse_observability-{VERSION}.dist-info"
    record_name = f"{dist_info}/RECORD"
    members = {name: content for name, content in members.items() if name != record_name}
    records = []
    for name, content in sorted(members.items()):
        digest = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=").decode()
        records.append(f"{name},sha256={digest},{len(content)}")
    records.append(f"{record_name},,")
    members[record_name] = ("\n".join(records) + "\n").encode()
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in members.items():
            archive.writestr(name, content)


def _sdist_member_bytes(path: Path) -> dict[str, bytes]:
    with tarfile.open(path, "r:gz") as archive:
        result: dict[str, bytes] = {}
        for item in archive.getmembers():
            if not item.isfile():
                continue
            stream = archive.extractfile(item)
            assert stream is not None
            with stream:
                result[item.name] = stream.read()
        return result


def _write_sdist_members(
    path: Path,
    members: dict[str, bytes],
    *,
    directories: tuple[str, ...] = (),
    duplicate: str | None = None,
) -> None:
    with tarfile.open(path, "w:gz") as archive:
        for name in directories:
            info = tarfile.TarInfo(name)
            info.type = tarfile.DIRTYPE
            archive.addfile(info)
        for name, content in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))
        if duplicate is not None:
            content = members[duplicate]
            info = tarfile.TarInfo(duplicate)
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))


def _source_tree(tmp_path: Path) -> Path:
    root = tmp_path / "source"
    for name, content in _package_files().items():
        path = root / "src" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    project_files = {
        "CHANGELOG.md": b"changelog\n",
        "LICENSE": b"Synthetic Apache-2.0 fixture\n",
        "MANIFEST.in": b"manifest\n",
        "README.md": README,
        "pyproject.toml": _pyproject_bytes(),
    }
    for name, content in project_files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    return root


def _inventory(path: Path, kind: str) -> Inventory:
    if not path.exists():
        path.write_bytes(f"synthetic {kind} artifact".encode())
    package_files = {"milhouse/__init__.py": b"same package"}
    resources = {"resources/manifest.json": b"same resource"}
    project_files = {"pyproject.toml": b"same project"} if kind == "sdist" else {}
    return Inventory(
        path=path,
        kind=kind,
        names=frozenset(),
        name="milhouse-observability",
        version="0.1.0a0",
        metadata=(),
        description_bytes=b"same description",
        license_bytes=b"same license",
        console_scripts=(("milhouse", "milhouse.cli:main"),),
        package_files=package_files,
        resources=resources,
        sdist_files=project_files,
    )


def _assert_wheel_record_is_valid(path: Path) -> None:
    with zipfile.ZipFile(path) as archive:
        record_name = next(
            name for name in archive.namelist() if name.endswith(".dist-info/RECORD")
        )
        rows = [line.split(",") for line in archive.read(record_name).decode().splitlines()]
        assert {row[0] for row in rows} == set(archive.namelist())
        for name, digest, size in rows:
            if name == record_name:
                assert (digest, size) == ("", "")
                continue
            content = archive.read(name)
            expected = (
                base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=").decode()
            )
            assert digest == f"sha256={expected}"
            assert size == str(len(content))


def _project_table() -> dict[str, object]:
    project = tomllib.loads(_pyproject_bytes().decode())["project"]
    assert isinstance(project, dict)
    return project


def _mutate_wheel_record(path: Path, *, column: int, value: str) -> None:
    with zipfile.ZipFile(path) as archive:
        members = {name: archive.read(name) for name in archive.namelist()}
    record_name = next(name for name in members if name.endswith(".dist-info/RECORD"))
    rows = [line.split(",") for line in members[record_name].decode().splitlines()]
    target = next(row for row in rows if row[0].endswith(".dist-info/METADATA"))
    target[column] = value
    members[record_name] = ("\n".join(",".join(row) for row in rows) + "\n").encode()
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in members.items():
            archive.writestr(name, content)


def _mutate_wheel_record_shape(path: Path, case: str) -> None:
    with zipfile.ZipFile(path) as archive:
        members = {name: archive.read(name) for name in archive.namelist()}
    record_name = next(name for name in members if name.endswith(".dist-info/RECORD"))
    rows = [line.split(",") for line in members[record_name].decode().splitlines()]
    if case == "malformed row":
        rows[0] = rows[0][:2]
    elif case == "duplicate row":
        rows.append(rows[0])
    elif case == "missing row":
        rows.pop(0)
    elif case == "self hash":
        self_row = next(row for row in rows if row[0] == record_name)
        self_row[1] = "sha256=invalid"
    else:  # pragma: no cover - test helper programming error
        raise AssertionError(case)
    members[record_name] = ("\n".join(",".join(row) for row in rows) + "\n").encode()
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in members.items():
            archive.writestr(name, content)


def test_descriptor_helpers_fail_closed_when_required_operations_are_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delattr(os, "O_CLOEXEC")
    with pytest.raises(ArtifactError, match="descriptor-safe artifact operations are unavailable"):
        check_artifacts._artifact_source_flags()

    monkeypatch.setattr(os, "write", lambda _descriptor, _content: 0)
    with pytest.raises(ArtifactError, match="snapshot write made no progress"):
        check_artifacts._write_all(1, b"content")


def test_private_snapshot_rejects_unsafe_directories_and_oversized_sources(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "candidate-py3-none-any.whl"
    source.write_bytes(b"candidate")

    unsafe = tmp_path / "unsafe-snapshots"
    unsafe.mkdir(mode=0o700)
    unsafe.chmod(0o770)
    with pytest.raises(ArtifactError, match="snapshot directory is unsafe"):
        check_artifacts._pin_artifact(source, unsafe)

    safe_existing = tmp_path / "safe-snapshots"
    safe_existing.mkdir(mode=0o700)
    pinned = check_artifacts._pin_artifact(source, safe_existing)
    assert pinned.path.read_bytes() == b"candidate"

    monkeypatch.setattr(check_artifacts, "MAX_EXPANDED_BYTES", 1)
    with pytest.raises(ArtifactError, match="stable bounded regular file"):
        check_artifacts._pin_artifact(source, tmp_path / "bounded-snapshots")


def test_private_snapshot_rejects_directory_name_descriptor_identity_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "candidate-py3-none-any.whl"
    source.write_bytes(b"candidate")
    monkeypatch.setattr(check_artifacts, "_same_file_snapshot", lambda _left, _right: False)

    with pytest.raises(ArtifactError, match="snapshot directory is unsafe"):
        check_artifacts._pin_artifact(source, tmp_path / "snapshots")


def test_private_snapshot_and_public_reverification_normalize_os_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    missing = tmp_path / "missing-py3-none-any.whl"
    with pytest.raises(ArtifactError, match="artifact could not be pinned safely"):
        check_artifacts._pin_artifact(missing, tmp_path / "snapshots")

    source = tmp_path / "candidate-py3-none-any.whl"
    source.write_bytes(b"candidate")
    source_info = source.stat()
    source.unlink()
    pinned = check_artifacts.PinnedArtifact(
        source,
        tmp_path / "private-copy.whl",
        hashlib.sha256(b"candidate").hexdigest(),
        source_info,
    )
    with pytest.raises(ArtifactError, match="public artifact could not be reverified"):
        check_artifacts._verify_pinned_source(pinned)

    source.write_bytes(b"candidate")
    original_copy = check_artifacts._copy_descriptor

    def corrupt_snapshot(source_fd: int, destination_fd: int) -> tuple[str, int]:
        result = original_copy(source_fd, destination_fd)
        os.lseek(destination_fd, 0, os.SEEK_SET)
        os.write(destination_fd, b"X")
        return result

    monkeypatch.setattr(check_artifacts, "_copy_descriptor", corrupt_snapshot)
    monkeypatch.setattr(
        os,
        "unlink",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("cleanup refused")),
    )
    with pytest.raises(ArtifactError, match="private artifact snapshot could not be verified"):
        check_artifacts._pin_artifact(source, tmp_path / "cleanup-failure")


def test_private_inventory_parity_rejects_any_snapshot_drift(tmp_path: Path) -> None:
    public = _inventory(tmp_path / "public.whl", "wheel")
    pinned = replace(public, path=tmp_path / "pinned.whl", resources={"other": b"drift"})

    with pytest.raises(ArtifactError, match="private snapshot does not match public inventory"):
        check_artifacts._require_inventory_parity(public, pinned)


def test_wheel_rejects_an_undeclared_extra_package_resource(tmp_path: Path) -> None:
    wheel = _minimal_wheel(tmp_path, "milhouse/resources/undeclared.json")

    with pytest.raises(ArtifactError, match="undeclared package files"):
        inspect_wheel(wheel)


def test_record_valid_wheel_license_mutation_fails_source_parity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    wheel_path = _minimal_wheel(tmp_path, license_bytes=b"mutated license\n")
    _assert_wheel_record_is_valid(wheel_path)
    wheel = inspect_wheel(wheel_path)
    canonical_license = b"canonical license\n"
    sdist = replace(
        _inventory(tmp_path / "candidate.tar.gz", "sdist"),
        metadata=wheel.metadata,
        description_bytes=wheel.description_bytes,
        license_bytes=canonical_license,
        console_scripts=wheel.console_scripts,
        package_files=wheel.package_files,
        resources=wheel.resources,
    )
    source = SourceInventory(
        name="milhouse-observability",
        version=wheel.version,
        metadata=wheel.metadata,
        description_bytes=wheel.description_bytes,
        license_bytes=canonical_license,
        console_scripts=wheel.console_scripts,
        package_files=wheel.package_files,
        resources=wheel.resources,
        sdist_files=sdist.sdist_files,
    )
    monkeypatch.setattr(check_artifacts, "inspect_source", lambda _root: source)
    monkeypatch.setattr(
        check_artifacts, "find_artifacts", lambda _directory: (wheel.path, sdist.path)
    )
    monkeypatch.setattr(check_artifacts, "inspect_wheel", lambda _path: wheel)
    monkeypatch.setattr(check_artifacts, "inspect_sdist", lambda _path: sdist)

    with pytest.raises(SystemExit) as caught:
        check_artifacts.main(["--repo-root", str(tmp_path), "--skip-install"])

    assert caught.value.code == 1
    assert "wheel and sdist LICENSE contents differ" in capsys.readouterr().err


def test_record_valid_wheel_console_target_mutation_is_rejected(tmp_path: Path) -> None:
    wheel = _minimal_wheel(tmp_path, console_target="milhouse.cli.root:main")
    _assert_wheel_record_is_valid(wheel)

    with pytest.raises(ArtifactError, match="console scripts must be exactly"):
        inspect_wheel(wheel)


@pytest.mark.parametrize(
    ("column", "value", "message"),
    [
        (1, "sha256=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "sha256 mismatch"),
        (2, "1", "size mismatch"),
    ],
)
def test_wheel_record_rejects_independent_hash_and_size_mutations(
    tmp_path: Path,
    column: int,
    value: str,
    message: str,
) -> None:
    wheel = _minimal_wheel(tmp_path)
    _mutate_wheel_record(wheel, column=column, value=value)

    with pytest.raises(ArtifactError, match=message):
        inspect_wheel(wheel)


@pytest.mark.parametrize(
    ("case", "message"),
    [
        ("malformed row", "exactly three fields"),
        ("duplicate row", "RECORD duplicates"),
        ("missing row", "inventory does not exactly match"),
        ("self hash", "self-row must have blank"),
    ],
)
def test_wheel_record_rejects_malformed_inventory_and_self_row(
    tmp_path: Path,
    case: str,
    message: str,
) -> None:
    wheel = _minimal_wheel(tmp_path)
    _mutate_wheel_record_shape(wheel, case)

    with pytest.raises(ArtifactError, match=message):
        inspect_wheel(wheel)


def test_wheel_record_rejects_non_utf8_csv_metadata(tmp_path: Path) -> None:
    wheel = _minimal_wheel(tmp_path)
    members = _wheel_member_bytes(wheel)
    record_name = next(name for name in members if name.endswith(".dist-info/RECORD"))
    members[record_name] = b"\xff"
    with zipfile.ZipFile(wheel, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in members.items():
            archive.writestr(name, content)

    with pytest.raises(ArtifactError, match="RECORD is missing or malformed"):
        inspect_wheel(wheel)


def test_record_valid_project_url_mutation_fails_complete_source_metadata_parity(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    mutated_url = "https://example.invalid/mutated"
    wheel = _minimal_wheel(tmp_path, project_url=mutated_url)
    _minimal_sdist(tmp_path, project_url=mutated_url)
    source = _source_tree(tmp_path)
    _assert_wheel_record_is_valid(wheel)

    with pytest.raises(SystemExit) as caught:
        check_artifacts.main(
            [
                "--repo-root",
                str(source),
                "--dist-dir",
                str(tmp_path),
                "--skip-install",
            ]
        )

    assert caught.value.code == 1
    assert "core metadata does not match the current source" in capsys.readouterr().err


@pytest.mark.parametrize(
    "name",
    ["", "../file", "/absolute", "folder\\file", "folder/../file", "cache/__pycache__/x"],
)
def test_archive_member_names_fail_closed(name: str) -> None:
    with pytest.raises(ArtifactError):
        check_artifacts._safe_name(name)


def test_artifact_metadata_and_manifest_parsers_require_exact_identity() -> None:
    name, version, metadata, description = check_artifacts._metadata(_metadata_bytes(), "fixture")
    assert (name, version) == ("milhouse-observability", VERSION)
    assert dict(metadata)["license-expression"] == ("Apache-2.0",)
    assert description == README
    assert check_artifacts._manifest_resources(MANIFEST, "fixture") == (
        "py.typed",
        "resources/manifest.json",
    )

    with pytest.raises(ArtifactError, match="wrong distribution"):
        check_artifacts._metadata(
            _metadata_bytes().replace(b"milhouse-observability", b"other-project"),
            "fixture",
        )
    with pytest.raises(ArtifactError, match="invalid version"):
        check_artifacts._metadata(_metadata_bytes().replace(VERSION.encode(), b"bad version"), "x")


def test_core_metadata_rejects_parser_defects_empty_headers_and_nonbyte_payloads(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(ArtifactError, match="malformed or multipart"):
        check_artifacts._metadata(b"Malformed header\n\nbody", "fixture")

    multipart = (
        b"Name: milhouse-observability\n"
        b"Version: 0.1.0a0\n"
        b"Content-Type: multipart/mixed; boundary=fixture\n\n"
        b"--fixture\nContent-Type: text/plain\n\nbody\n--fixture--\n"
    )
    with pytest.raises(ArtifactError, match="malformed or multipart"):
        check_artifacts._metadata(multipart, "fixture")

    empty_header = _metadata_bytes().replace(
        f"Summary: {SUMMARY}\n".encode(),
        b"Summary: \n",
    )
    with pytest.raises(ArtifactError, match="empty core metadata header"):
        check_artifacts._metadata(empty_header, "fixture")

    class NonByteMessage:
        defects: tuple[object, ...] = ()

        @staticmethod
        def is_multipart() -> bool:
            return False

        @staticmethod
        def get(name: str) -> str | None:
            return {"Name": "milhouse-observability", "Version": VERSION}.get(name)

        @staticmethod
        def raw_items() -> tuple[tuple[str, str], ...]:
            return (("Name", "milhouse-observability"), ("Version", VERSION))

        @staticmethod
        def get_payload(*, decode: bool) -> str:
            assert decode
            return "not bytes"

    class FakeParser:
        @staticmethod
        def parsebytes(_raw: bytes) -> NonByteMessage:
            return NonByteMessage()

    monkeypatch.setattr(check_artifacts, "BytesParser", lambda **_kwargs: FakeParser())
    with pytest.raises(ArtifactError, match="non-text metadata description"):
        check_artifacts._metadata(b"ignored", "fixture")


def test_source_core_metadata_derives_every_declared_project_field() -> None:
    _name, _version, artifact_metadata, description = check_artifacts._metadata(
        _metadata_bytes(), "fixture"
    )

    assert check_artifacts._source_core_metadata(_project_table(), VERSION, README) == (
        artifact_metadata
    )
    assert description == README
    assert check_artifacts._normalized_requirement(
        'package>=1; python_version >= "3.11"',
        extra="feature",
    ).endswith('python_version >= "3.11" and extra == "feature"')


@pytest.mark.parametrize("value", [None, "", "nul\x00value", "line\nvalue", 3])
def test_source_project_string_rejects_empty_control_and_nonstring_values(value: object) -> None:
    with pytest.raises(ArtifactError, match="must be a nonempty string"):
        check_artifacts._project_string({"field": value}, "field")


@pytest.mark.parametrize(
    "value",
    [None, "value", ["valid", 3], ["valid", ""], ["duplicate", "duplicate"]],
)
def test_source_project_string_list_rejects_ambiguous_values(value: object) -> None:
    with pytest.raises(ArtifactError, match="must be a unique string list"):
        check_artifacts._project_string_list({"field": value}, "field")


def test_source_requirement_rejects_invalid_pep508_input() -> None:
    with pytest.raises(ArtifactError, match="invalid dependency requirement"):
        check_artifacts._normalized_requirement("not a requirement @@@")


@pytest.mark.parametrize(
    ("key", "value", "message"),
    [
        ("name", "other-project", "wrong distribution name"),
        ("readme", "OTHER.md", "readme must be exactly"),
        ("license", "MIT", "license must be exactly"),
        ("license-files", ["LICENSE", "NOTICE"], "license-files must be exactly"),
        ("dynamic", ["version", "readme"], "dynamic metadata must be exactly"),
        ("authors", None, "exactly one named author"),
        ("authors", [], "exactly one named author"),
        ("authors", ["name"], "exactly one named author"),
        ("authors", [{"name": "Author", "email": "author@example.invalid"}], "named author"),
        ("authors", [{"name": 3}], "named author"),
        ("authors", [{"name": ""}], "named author"),
        ("urls", None, "nonempty string mapping"),
        ("urls", {}, "nonempty string mapping"),
        ("urls", {"": PROJECT_URL}, "nonempty string mapping"),
        ("urls", {"Repository": ""}, "nonempty string mapping"),
        ("optional-dependencies", None, "must be a nonempty mapping"),
        ("optional-dependencies", {}, "must be a nonempty mapping"),
        ("optional-dependencies", {"receiver": "not-list"}, "invalid group"),
        ("optional-dependencies", {"": []}, "invalid group"),
        ("optional-dependencies", {"receiver": [3]}, "requires strings"),
        ("requires-python", "not a specifier", "requires-python is invalid"),
    ],
)
def test_source_core_metadata_rejects_project_contract_drift(
    key: str,
    value: object,
    message: str,
) -> None:
    project = _project_table()
    project[key] = value

    with pytest.raises(ArtifactError, match=message):
        check_artifacts._source_core_metadata(project, VERSION, README)


def test_source_core_metadata_requires_nonempty_readme() -> None:
    with pytest.raises(ArtifactError, match=r"README\.md must not be empty"):
        check_artifacts._source_core_metadata(_project_table(), VERSION, b"")


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ({"extra": True}, "wrong schema"),
        ({"manifest_version": 2}, "unsupported version"),
        ({"distribution": "other"}, "identity mismatch"),
        ({"resources": []}, "requires string resources"),
        ({"resources": ["py.typed", "py.typed"]}, "sorted and unique"),
        ({"resources": ["../escape"]}, "unsafe path"),
        ({"resources": ["folder\\file"]}, "unsafe path"),
    ],
)
def test_resource_manifest_parser_rejects_unsafe_shapes(
    mutation: dict[str, object],
    message: str,
) -> None:
    document = json.loads(MANIFEST)
    document.update(mutation)
    with pytest.raises(ArtifactError, match=message):
        check_artifacts._manifest_resources(json.dumps(document).encode(), "fixture")


def test_resource_manifest_and_console_parsers_reject_invalid_encoding_and_schema() -> None:
    with pytest.raises(ArtifactError, match="invalid resource manifest"):
        check_artifacts._manifest_resources(b"{", "fixture")
    with pytest.raises(ArtifactError, match="invalid console entry-point"):
        check_artifacts._console_scripts(b"not ini", "fixture")
    with pytest.raises(ArtifactError, match="only the console_scripts"):
        check_artifacts._console_scripts(b"[other]\nvalue = target\n", "fixture")
    with pytest.raises(ArtifactError, match="console scripts must be exactly"):
        check_artifacts._console_scripts(
            b"[console_scripts]\nother = milhouse.cli:main\n",
            "fixture",
        )


def test_regular_reader_and_source_version_are_strict(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    regular = tmp_path / "regular"
    regular.write_bytes(b"content")
    assert check_artifacts._read_regular(regular, "fixture") == b"content"
    assert check_artifacts._source_version(_package_files()["milhouse/__init__.py"]) == VERSION

    link = tmp_path / "link"
    link.symlink_to(regular)
    with pytest.raises(ArtifactError, match="regular, non-symlink"):
        check_artifacts._read_regular(link, "fixture")

    monkeypatch.setattr(check_artifacts, "MAX_EXPANDED_BYTES", 1)
    with pytest.raises(ArtifactError, match="safety bound"):
        check_artifacts._read_regular(regular, "fixture")

    with pytest.raises(ArtifactError, match="valid UTF-8 Python"):
        check_artifacts._source_version(b"\xff")
    with pytest.raises(ArtifactError, match="one literal valid"):
        check_artifacts._source_version(b'__version__ = "1.0"\n')


def test_regular_reader_normalizes_a_read_race(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    regular = tmp_path / "regular"
    regular.write_bytes(b"content")
    original_read_bytes = Path.read_bytes

    def refuse_selected_path(path: Path) -> bytes:
        if path == regular:
            raise OSError("synthetic read race")
        return original_read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", refuse_selected_path)
    with pytest.raises(ArtifactError, match="cannot read fixture"):
        check_artifacts._read_regular(regular, "fixture")


def test_source_inventory_captures_exact_package_project_license_and_console_contract(
    tmp_path: Path,
) -> None:
    root = _source_tree(tmp_path)

    source = inspect_source(root)

    assert source.version == VERSION
    assert source.license_bytes == b"Synthetic Apache-2.0 fixture\n"
    assert source.console_scripts == (("milhouse", "milhouse.cli:main"),)
    assert set(source.package_files) == set(_package_files())


def test_source_inventory_rejects_undeclared_missing_and_drifted_files(tmp_path: Path) -> None:
    root = _source_tree(tmp_path)
    extra = root / "src" / "milhouse" / "resources" / "extra.bin"
    extra.write_bytes(b"extra")
    with pytest.raises(ArtifactError, match="undeclared file"):
        inspect_source(root)

    root = _source_tree(tmp_path / "missing")
    (root / "src" / "milhouse" / "cli" / "root.py").unlink()
    with pytest.raises(ArtifactError, match="missing required files"):
        inspect_source(root)

    root = _source_tree(tmp_path / "console")
    pyproject = root / "pyproject.toml"
    pyproject.write_text(
        '[project]\nname = "milhouse-observability"\n[project.scripts]\nother = "x:y"\n',
        encoding="utf-8",
    )
    with pytest.raises(ArtifactError, match="console scripts must be exactly"):
        inspect_source(root)


def test_source_inventory_rejects_symlinks_and_bad_project_metadata(tmp_path: Path) -> None:
    root = _source_tree(tmp_path)
    package_file = root / "src" / "milhouse" / "cli" / "root.py"
    target = root / "target.py"
    target.write_text("", encoding="utf-8")
    package_file.unlink()
    package_file.symlink_to(target)
    with pytest.raises(ArtifactError, match="source package contains symlink"):
        inspect_source(root)

    root = _source_tree(tmp_path / "bad-project")
    (root / "pyproject.toml").write_text("not toml", encoding="utf-8")
    with pytest.raises(ArtifactError, match="invalid project metadata"):
        inspect_source(root)


def test_source_inventory_rejects_unsafe_roots_special_files_and_manifest_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    not_a_package = _source_tree(tmp_path / "bad-root")
    package_root = not_a_package / "src" / "milhouse"
    for child in sorted(package_root.rglob("*"), reverse=True):
        if child.is_file():
            child.unlink()
        elif child.is_dir():
            child.rmdir()
    package_root.rmdir()
    package_root.write_bytes(b"not a directory")
    with pytest.raises(ArtifactError, match="import package must be a regular directory"):
        inspect_source(not_a_package)

    cached = _source_tree(tmp_path / "cached")
    cache_file = cached / "src" / "milhouse" / "__pycache__" / "ignored.pyc"
    cache_file.parent.mkdir()
    cache_file.write_bytes(b"ignored cache")
    assert inspect_source(cached).version == VERSION

    special = _source_tree(tmp_path / "special")
    special_file = special / "src" / "milhouse" / "special"
    os.mkfifo(special_file)
    with pytest.raises(ArtifactError, match="contains special file"):
        inspect_source(special)

    missing_declared = _source_tree(tmp_path / "declared")
    manifest_path = missing_declared / "src" / "milhouse" / "resources" / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["resources"] = ["missing.json", "py.typed", "resources/manifest.json"]
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ArtifactError, match="manifest declares missing files"):
        inspect_source(missing_declared)

    nonmapping = _source_tree(tmp_path / "nonmapping")
    monkeypatch.setattr(tomllib, "loads", lambda _raw: {"project": "invalid"})
    with pytest.raises(ArtifactError, match="invalid project metadata"):
        inspect_source(nonmapping)


def test_source_inventory_rejects_a_wrong_project_identity(tmp_path: Path) -> None:
    root = _source_tree(tmp_path)
    pyproject = root / "pyproject.toml"
    pyproject.write_bytes(_pyproject_bytes().replace(b"milhouse-observability", b"other-project"))

    with pytest.raises(ArtifactError, match="wrong distribution name"):
        inspect_source(root)


def test_valid_wheel_and_sdist_inventories_match(tmp_path: Path) -> None:
    wheel = inspect_wheel(_minimal_wheel(tmp_path))
    sdist = inspect_sdist(_minimal_sdist(tmp_path))

    assert wheel.version == sdist.version == VERSION
    assert wheel.package_files == sdist.package_files
    assert wheel.resources == sdist.resources
    assert wheel.license_bytes == sdist.license_bytes
    assert wheel.console_scripts == sdist.console_scripts


def test_wheel_and_sdist_reject_wrong_file_types_and_corrupt_archives(tmp_path: Path) -> None:
    wrong_wheel = tmp_path / "candidate.whl"
    wrong_wheel.write_bytes(b"not a wheel")
    with pytest.raises(ArtifactError, match="universal py3-none-any"):
        inspect_wheel(wrong_wheel)

    corrupt_wheel = tmp_path / "candidate-py3-none-any.whl"
    corrupt_wheel.write_bytes(b"not zip")
    with pytest.raises(ArtifactError, match="cannot inspect wheel"):
        inspect_wheel(corrupt_wheel)

    wrong_sdist = tmp_path / "candidate.tar"
    wrong_sdist.write_bytes(b"not sdist")
    with pytest.raises(ArtifactError, match=r"regular \.tar\.gz"):
        inspect_sdist(wrong_sdist)

    corrupt_sdist = tmp_path / "candidate.tar.gz"
    corrupt_sdist.write_bytes(b"not tar")
    with pytest.raises(ArtifactError, match="cannot inspect sdist"):
        inspect_sdist(corrupt_sdist)


def test_wheel_rejects_empty_oversized_duplicate_link_and_incomplete_archives(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    empty = tmp_path / "empty-py3-none-any.whl"
    with zipfile.ZipFile(empty, "w"):
        pass
    with pytest.raises(ArtifactError, match="member count is outside"):
        inspect_wheel(empty)

    oversized_root = tmp_path / "oversized"
    oversized_root.mkdir()
    oversized = _minimal_wheel(oversized_root)
    monkeypatch.setattr(check_artifacts, "MAX_EXPANDED_BYTES", 1)
    with pytest.raises(ArtifactError, match="expanded size exceeds"):
        inspect_wheel(oversized)
    monkeypatch.undo()

    duplicate = tmp_path / "duplicate-py3-none-any.whl"
    with zipfile.ZipFile(duplicate, "w") as archive:
        archive.writestr("same/", b"")
        archive.writestr("same", b"content")
    with pytest.raises(ArtifactError, match="duplicate member"):
        inspect_wheel(duplicate)

    linked = tmp_path / "linked-py3-none-any.whl"
    link = zipfile.ZipInfo("link")
    link.create_system = 3
    link.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(linked, "w") as archive:
        archive.writestr(link, b"target")
    with pytest.raises(ArtifactError, match="symbolic link"):
        inspect_wheel(linked)

    incomplete = tmp_path / "incomplete-py3-none-any.whl"
    with zipfile.ZipFile(incomplete, "w") as archive:
        archive.writestr("package.py", b"")
    with pytest.raises(ArtifactError, match="metadata, entry point, or LICENSE inventory"):
        inspect_wheel(incomplete)


def test_record_valid_wheel_rejects_missing_and_undeclared_inventory(tmp_path: Path) -> None:
    missing_required_root = tmp_path / "missing-required"
    missing_required_root.mkdir()
    missing_required = _minimal_wheel(missing_required_root)
    members = _wheel_member_bytes(missing_required)
    del members["milhouse/cli/root.py"]
    _write_record_valid_wheel(missing_required, members)
    with pytest.raises(ArtifactError, match="missing package resources"):
        inspect_wheel(missing_required)

    missing_declared_root = tmp_path / "missing-declared"
    missing_declared_root.mkdir()
    missing_declared = _minimal_wheel(missing_declared_root)
    members = _wheel_member_bytes(missing_declared)
    manifest = json.loads(members["milhouse/resources/manifest.json"])
    manifest["resources"] = ["missing.json", "py.typed", "resources/manifest.json"]
    members["milhouse/resources/manifest.json"] = json.dumps(manifest).encode()
    _write_record_valid_wheel(missing_declared, members)
    with pytest.raises(ArtifactError, match="missing declared resource"):
        inspect_wheel(missing_declared)

    unexpected_root = tmp_path / "unexpected"
    unexpected_root.mkdir()
    unexpected = _minimal_wheel(unexpected_root)
    members = _wheel_member_bytes(unexpected)
    dist_info = f"milhouse_observability-{VERSION}.dist-info"
    members[f"{dist_info}/unexpected.txt"] = b"unexpected"
    _write_record_valid_wheel(unexpected, members)
    with pytest.raises(ArtifactError, match="wheel inventory mismatch: unexpected"):
        inspect_wheel(unexpected)

    missing_metadata_root = tmp_path / "missing-metadata"
    missing_metadata_root.mkdir()
    missing_metadata = _minimal_wheel(missing_metadata_root)
    members = _wheel_member_bytes(missing_metadata)
    del members[f"{dist_info}/top_level.txt"]
    _write_record_valid_wheel(missing_metadata, members)
    with pytest.raises(ArtifactError, match="wheel inventory mismatch: missing"):
        inspect_wheel(missing_metadata)


def test_sdist_rejects_undeclared_package_and_root_inventory(tmp_path: Path) -> None:
    package_extra = _minimal_sdist(tmp_path, "src/milhouse/resources/extra.bin")
    with pytest.raises(ArtifactError, match="undeclared package files"):
        inspect_sdist(package_extra)

    package_extra.unlink()
    root_extra = _minimal_sdist(tmp_path, "unexpected.txt")
    with pytest.raises(ArtifactError, match="sdist inventory mismatch"):
        inspect_sdist(root_extra)


def test_sdist_console_target_mutation_is_rejected(tmp_path: Path) -> None:
    path = _minimal_sdist(tmp_path, console_target="milhouse.cli.root:main")
    with pytest.raises(ArtifactError, match="console scripts must be exactly"):
        inspect_sdist(path)


def test_artifact_discovery_requires_exactly_one_pair(tmp_path: Path) -> None:
    with pytest.raises(ArtifactError, match="exactly one wheel and one sdist"):
        check_artifacts.find_artifacts(tmp_path)

    not_directory = tmp_path / "not-directory"
    not_directory.write_bytes(b"file")
    with pytest.raises(ArtifactError, match="must be a regular directory"):
        check_artifacts.find_artifacts(not_directory)
    wheel = _minimal_wheel(tmp_path)
    sdist = _minimal_sdist(tmp_path)
    assert check_artifacts.find_artifacts(tmp_path) == (wheel, sdist)

    duplicate = tmp_path / "duplicate-py3-none-any.whl"
    duplicate.write_bytes(wheel.read_bytes())
    with pytest.raises(ArtifactError, match="exactly one wheel and one sdist"):
        check_artifacts.find_artifacts(tmp_path)


def test_safe_sdist_extraction_recreates_only_regular_files(tmp_path: Path) -> None:
    sdist = _minimal_sdist(tmp_path)
    destination = tmp_path / "extract"
    destination.mkdir()

    source_root = check_artifacts._extract_sdist(sdist, destination)

    assert source_root.is_dir()
    assert (
        source_root / "src" / "milhouse" / "resources" / "manifest.json"
    ).read_bytes() == MANIFEST


def test_sdist_size_bound_is_enforced_before_any_member_payload_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class OversizedMember:
        name = "milhouse_observability-0.1.0a0/PKG-INFO"
        size = check_artifacts.MAX_EXPANDED_BYTES + 1

        @staticmethod
        def isfile() -> bool:
            return True

        @staticmethod
        def isdir() -> bool:
            return False

    class PayloadMustNotBeRead:
        def __enter__(self) -> Self:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def __iter__(self) -> object:
            return iter((OversizedMember(),))

        def extractfile(self, _item: object) -> object:
            raise AssertionError("payload was read before enforcing the declared-size bound")

    path = tmp_path / "candidate.tar.gz"
    path.write_bytes(b"synthetic archive placeholder")
    monkeypatch.setattr(
        check_artifacts.tarfile,
        "open",
        lambda *_args, **_kwargs: PayloadMustNotBeRead(),
    )

    with pytest.raises(ArtifactError, match="expanded size exceeds"):
        inspect_sdist(path)

    destination = tmp_path / "extract-bound"
    destination.mkdir()
    with pytest.raises(ArtifactError, match="expanded-size safety bound"):
        check_artifacts._extract_sdist(path, destination)


@pytest.mark.parametrize("negative_is_directory", [False, True])
def test_sdist_negative_declared_size_cannot_offset_a_later_oversized_member(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    negative_is_directory: bool,
) -> None:
    class NegativeMember:
        name = "milhouse_observability-0.1.0a0/negative"
        size = -1

        @staticmethod
        def isfile() -> bool:
            return not negative_is_directory

        @staticmethod
        def isdir() -> bool:
            return negative_is_directory

    class OversizedMember:
        name = "milhouse_observability-0.1.0a0/oversized"
        size = check_artifacts.MAX_EXPANDED_BYTES + 1

        @staticmethod
        def isfile() -> bool:
            return True

        @staticmethod
        def isdir() -> bool:
            return False

    class PayloadMustNotBeRead:
        def __enter__(self) -> Self:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def __iter__(self) -> object:
            return iter((NegativeMember(), OversizedMember()))

        def extractfile(self, _item: object) -> object:
            raise AssertionError("payload was read before validating the declared member size")

    path = tmp_path / "candidate.tar.gz"
    path.write_bytes(b"synthetic archive placeholder")
    monkeypatch.setattr(
        check_artifacts.tarfile,
        "open",
        lambda *_args, **_kwargs: PayloadMustNotBeRead(),
    )

    with pytest.raises(ArtifactError, match="negative declared size"):
        inspect_sdist(path)

    destination = tmp_path / "negative-extract"
    destination.mkdir()
    with pytest.raises(ArtifactError, match="negative declared size"):
        check_artifacts._extract_sdist(path, destination)


@pytest.mark.parametrize("extraction", [False, True])
def test_bounded_sdist_policy_rejects_count_cumulative_size_empty_and_special_members(
    monkeypatch: pytest.MonkeyPatch,
    extraction: bool,
) -> None:
    regular = tarfile.TarInfo("root/regular")
    regular.size = 1

    monkeypatch.setattr(check_artifacts, "MAX_MEMBERS", 0)
    with pytest.raises(ArtifactError, match="member count is outside"):
        list(
            check_artifacts._bounded_sdist_members(
                cast(tarfile.TarFile, iter((regular,))),
                extraction=extraction,
            )
        )
    monkeypatch.setattr(check_artifacts, "MAX_MEMBERS", 10_000)

    with pytest.raises(ArtifactError, match="member count is outside"):
        list(
            check_artifacts._bounded_sdist_members(
                cast(tarfile.TarFile, iter(())),
                extraction=extraction,
            )
        )

    special = tarfile.TarInfo("root/link")
    special.type = tarfile.SYMTYPE
    special.linkname = "target"
    with pytest.raises(ArtifactError, match=r"links and special|link or special"):
        list(
            check_artifacts._bounded_sdist_members(
                cast(tarfile.TarFile, iter((special,))),
                extraction=extraction,
            )
        )

    first = tarfile.TarInfo("root/first")
    first.size = 2
    second = tarfile.TarInfo("root/second")
    second.size = 2
    monkeypatch.setattr(check_artifacts, "MAX_EXPANDED_BYTES", 3)
    expected = (
        "extraction exceeds the expanded-size safety bound"
        if extraction
        else "sdist expanded size exceeds the safety bound"
    )
    with pytest.raises(ArtifactError, match=expected):
        list(
            check_artifacts._bounded_sdist_members(
                cast(tarfile.TarFile, iter((first, second))),
                extraction=extraction,
            )
        )


def test_sdist_rejects_duplicate_roots_missing_files_and_short_payloads(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    duplicate_root = tmp_path / "duplicate"
    duplicate_root.mkdir()
    duplicate = _minimal_sdist(duplicate_root)
    members = _sdist_member_bytes(duplicate)
    duplicate_name = next(iter(members))
    _write_sdist_members(duplicate, members, duplicate=duplicate_name)
    with pytest.raises(ArtifactError, match="duplicate member"):
        inspect_sdist(duplicate)

    multiple_root = tmp_path / "multiple-root"
    multiple_root.mkdir()
    multiple = _minimal_sdist(multiple_root)
    members = _sdist_member_bytes(multiple)
    members["other-root/unexpected"] = b"unexpected"
    _write_sdist_members(multiple, members)
    with pytest.raises(ArtifactError, match="exactly one top-level directory"):
        inspect_sdist(multiple)
    extraction = tmp_path / "multiple-extraction"
    extraction.mkdir()
    with pytest.raises(ArtifactError, match="exactly one source root"):
        check_artifacts._extract_sdist(multiple, extraction)

    missing_required_root = tmp_path / "missing-required"
    missing_required_root.mkdir()
    missing_required = _minimal_sdist(missing_required_root)
    members = _sdist_member_bytes(missing_required)
    package_root = f"milhouse_observability-{VERSION}"
    del members[f"{package_root}/src/milhouse/cli/root.py"]
    _write_sdist_members(missing_required, members)
    with pytest.raises(ArtifactError, match="missing package resources"):
        inspect_sdist(missing_required)

    missing_inventory_root = tmp_path / "missing-inventory"
    missing_inventory_root.mkdir()
    missing_inventory = _minimal_sdist(missing_inventory_root)
    members = _sdist_member_bytes(missing_inventory)
    del members[f"{package_root}/CHANGELOG.md"]
    _write_sdist_members(missing_inventory, members)
    with pytest.raises(ArtifactError, match="sdist inventory mismatch: missing"):
        inspect_sdist(missing_inventory)

    missing_metadata_root = tmp_path / "missing-metadata"
    missing_metadata_root.mkdir()
    missing_metadata = _minimal_sdist(missing_metadata_root)
    members = _sdist_member_bytes(missing_metadata)
    del members[f"{package_root}/PKG-INFO"]
    _write_sdist_members(missing_metadata, members)
    with pytest.raises(ArtifactError, match="missing required file"):
        inspect_sdist(missing_metadata)

    short_root = tmp_path / "short"
    short_root.mkdir()
    short = _minimal_sdist(short_root)
    original_extractfile = tarfile.TarFile.extractfile

    def short_metadata(
        archive: tarfile.TarFile,
        member: tarfile.TarInfo | str,
    ) -> object:
        if isinstance(member, tarfile.TarInfo) and member.name.endswith("/PKG-INFO"):
            return io.BytesIO(b"")
        return original_extractfile(archive, member)

    monkeypatch.setattr(tarfile.TarFile, "extractfile", short_metadata)
    with pytest.raises(ArtifactError, match="ended before its declared size"):
        inspect_sdist(short)


def test_sdist_directory_and_extraction_failure_paths_are_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    directory_root = tmp_path / "directory"
    directory_root.mkdir()
    with_directory = _minimal_sdist(directory_root)
    members = _sdist_member_bytes(with_directory)
    package_root = f"milhouse_observability-{VERSION}"
    _write_sdist_members(with_directory, members, directories=(f"{package_root}/",))
    assert inspect_sdist(with_directory).version == VERSION
    extracted = tmp_path / "directory-extracted"
    extracted.mkdir()
    assert check_artifacts._extract_sdist(with_directory, extracted).is_dir()

    missing_stream_root = tmp_path / "missing-stream"
    missing_stream_root.mkdir()
    missing_stream = _minimal_sdist(missing_stream_root)
    original_extractfile = tarfile.TarFile.extractfile

    def refuse_metadata(
        archive: tarfile.TarFile,
        member: tarfile.TarInfo | str,
    ) -> object:
        if isinstance(member, tarfile.TarInfo) and member.name.endswith("/PKG-INFO"):
            return None
        return original_extractfile(archive, member)

    monkeypatch.setattr(tarfile.TarFile, "extractfile", refuse_metadata)
    with pytest.raises(ArtifactError, match="cannot read sdist member"):
        inspect_sdist(missing_stream)
    destination = tmp_path / "missing-stream-extracted"
    destination.mkdir()
    with pytest.raises(ArtifactError, match="cannot extract sdist member"):
        check_artifacts._extract_sdist(missing_stream, destination)
    monkeypatch.undo()

    collision_root = tmp_path / "collision"
    collision_root.mkdir()
    collision = _minimal_sdist(collision_root)
    collision_destination = tmp_path / "collision-extracted"
    first_target = collision_destination / package_root / "CHANGELOG.md"
    first_target.parent.mkdir(parents=True)
    first_target.write_bytes(b"planted")
    with pytest.raises(ArtifactError, match="cannot safely extract sdist"):
        check_artifacts._extract_sdist(collision, collision_destination)

    file_root = tmp_path / "file-root.tar.gz"
    with tarfile.open(file_root, "w:gz") as archive:
        info = tarfile.TarInfo("only-root")
        info.size = 4
        archive.addfile(info, io.BytesIO(b"file"))
    file_destination = tmp_path / "file-root-extracted"
    file_destination.mkdir()
    with pytest.raises(ArtifactError, match="did not produce a regular source root"):
        check_artifacts._extract_sdist(file_root, file_destination)


def test_subprocess_wrapper_normalizes_success_failure_and_timeout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    env: dict[str, str] = {}
    monkeypatch.setattr(
        check_artifacts.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            [], 0, stdout=" output \n", stderr=""
        ),
    )
    assert check_artifacts._run(("command",), tmp_path, env, "fixture") == "output"

    monkeypatch.setattr(
        check_artifacts.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 3, stdout="", stderr="detail\n"),
    )
    with pytest.raises(ArtifactError, match="fixture failed: detail"):
        check_artifacts._run(("command",), tmp_path, env, "fixture")

    def timeout(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired("command", 1)

    monkeypatch.setattr(check_artifacts.subprocess, "run", timeout)
    with pytest.raises(ArtifactError, match="could not execute"):
        check_artifacts._run(("command",), tmp_path, env, "fixture")


def test_hash_manifest_is_deterministic_and_rejects_symlink_targets(tmp_path: Path) -> None:
    first = tmp_path / "a.whl"
    second = tmp_path / "b.tar.gz"
    first.write_bytes(b"a")
    second.write_bytes(b"b")
    manifest = tmp_path / "hashes.txt"

    check_artifacts.write_hashes(manifest, (second, first))

    assert manifest.read_text(encoding="utf-8") == (
        f"{check_artifacts.sha256(first)}  {first.name}\n"
        f"{check_artifacts.sha256(second)}  {second.name}\n"
    )

    created_parent_manifest = tmp_path / "created-parent" / "hashes.txt"
    check_artifacts.write_hashes(created_parent_manifest, (first, second))
    assert created_parent_manifest.is_file()
    assert stat.S_IMODE(created_parent_manifest.parent.stat().st_mode) & 0o077 == 0

    target = tmp_path / "target"
    target.write_text("", encoding="utf-8")
    linked = tmp_path / "linked"
    linked.symlink_to(target)
    with pytest.raises(ArtifactError, match="must not be a symlink"):
        check_artifacts.write_hashes(linked, (first,))

    safe_parent = tmp_path / "safe-parent"
    safe_parent.mkdir(mode=0o700)
    planted_manifest = safe_parent / "artifact-sha256.txt"
    planted_temporary = planted_manifest.with_name(f".{planted_manifest.name}.{os.getpid()}.tmp")
    outside = tmp_path / "outside-victim.txt"
    outside.write_text("preserve outside bytes\n", encoding="utf-8")
    outside.chmod(0o600)
    planted_temporary.symlink_to(outside)

    with pytest.raises(ArtifactError, match="temporary path is unsafe"):
        check_artifacts.write_hashes(planted_manifest, (first, second))

    assert planted_temporary.is_symlink()
    assert not planted_manifest.exists()
    assert outside.read_text(encoding="utf-8") == "preserve outside bytes\n"
    assert stat.S_IMODE(outside.stat().st_mode) == 0o600


def test_hash_manifest_rejects_untrusted_hashes_paths_parents_and_hardlinks(
    tmp_path: Path,
) -> None:
    artifact = tmp_path / "candidate.whl"
    artifact.write_bytes(b"candidate")

    with pytest.raises(ArtifactError, match="one trusted sha256 per artifact"):
        check_artifacts.write_hashes(
            tmp_path / "untrusted.txt",
            (artifact,),
            trusted_hashes={},
        )
    with pytest.raises(ArtifactError, match="path must name a regular file"):
        check_artifacts.write_hashes(Path("/"), (artifact,))

    unsafe_parent = tmp_path / "unsafe-parent"
    unsafe_parent.mkdir(mode=0o700)
    unsafe_parent.chmod(0o770)
    with pytest.raises(ArtifactError, match="parent directory is unsafe"):
        check_artifacts.write_hashes(unsafe_parent / "hashes.txt", (artifact,))

    hardlink_parent = tmp_path / "hardlink-parent"
    hardlink_parent.mkdir(mode=0o700)
    target = hardlink_parent / "target"
    target.write_bytes(b"existing")
    linked = hardlink_parent / "hashes.txt"
    os.link(target, linked)
    with pytest.raises(ArtifactError, match="safe owned regular file"):
        check_artifacts.write_hashes(linked, (artifact,))

    safe = tmp_path / "safe" / "hashes.txt"
    check_artifacts.write_hashes(safe, (artifact,))
    check_artifacts.write_hashes(safe, (artifact,))
    assert safe.read_text(encoding="utf-8").endswith(f"  {artifact.name}\n")


def test_hash_manifest_verifies_temporary_and_published_file_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact = tmp_path / "candidate.whl"
    artifact.write_bytes(b"candidate")

    temporary_manifest = tmp_path / "temporary" / "hashes.txt"
    original_fchmod = os.fchmod
    monkeypatch.setattr(os, "fchmod", lambda _fd, _mode: None)
    with pytest.raises(ArtifactError, match="temporary file could not be verified"):
        check_artifacts.write_hashes(temporary_manifest, (artifact,))
    planted_name = f".{temporary_manifest.name}.{os.getpid()}.tmp"
    assert not (temporary_manifest.parent / planted_name).exists()
    monkeypatch.setattr(os, "fchmod", original_fchmod)

    published_manifest = tmp_path / "published" / "hashes.txt"
    original_replace = os.replace

    def replace_then_change_mode(
        source: str,
        destination: str,
        *,
        src_dir_fd: int,
        dst_dir_fd: int,
    ) -> None:
        original_replace(
            source,
            destination,
            src_dir_fd=src_dir_fd,
            dst_dir_fd=dst_dir_fd,
        )
        os.chmod(destination, 0o600, dir_fd=dst_dir_fd)

    monkeypatch.setattr(os, "replace", replace_then_change_mode)
    with pytest.raises(ArtifactError, match="atomic replacement could not be verified"):
        check_artifacts.write_hashes(published_manifest, (artifact,))


@pytest.mark.parametrize("cleanup_fails", [False, True])
def test_hash_manifest_closes_and_attempts_cleanup_after_fdopen_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    cleanup_fails: bool,
) -> None:
    artifact = tmp_path / "candidate.whl"
    artifact.write_bytes(b"candidate")
    manifest = tmp_path / "fdopen" / "hashes.txt"
    original_unlink = os.unlink

    def refuse_fdopen(_descriptor: int, _mode: str) -> object:
        raise OSError("synthetic fdopen failure")

    def maybe_refuse_unlink(path: str, *, dir_fd: int | None = None) -> None:
        if cleanup_fails:
            raise OSError("synthetic cleanup failure")
        original_unlink(path, dir_fd=dir_fd)

    monkeypatch.setattr(os, "fdopen", refuse_fdopen)
    monkeypatch.setattr(os, "unlink", maybe_refuse_unlink)
    with pytest.raises(ArtifactError, match="could not be written safely"):
        check_artifacts.write_hashes(manifest, (artifact,))


def test_hash_manifest_normalizes_parent_creation_failure(tmp_path: Path) -> None:
    artifact = tmp_path / "candidate.whl"
    artifact.write_bytes(b"candidate")
    missing_ancestor = tmp_path / "missing" / "nested" / "hashes.txt"

    with pytest.raises(ArtifactError, match="could not be written safely"):
        check_artifacts.write_hashes(missing_ancestor, (artifact,))


def test_artifact_swap_during_private_pin_fails_before_install_or_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    wheel_path = tmp_path / "candidate-py3-none-any.whl"
    sdist_path = tmp_path / "candidate.tar.gz"
    wheel_path.write_bytes(b"validated original candidate")
    sdist_path.write_bytes(b"sdist candidate")
    replacement = tmp_path / "unvalidated-replacement"
    replacement.write_bytes(b"unvalidated replacement")
    original_copy = check_artifacts._copy_descriptor
    swapped = False
    installs: list[str] = []

    def copy_then_swap(source: int, destination: int) -> tuple[str, int]:
        nonlocal swapped
        result = original_copy(source, destination)
        if not swapped:
            os.replace(replacement, wheel_path)
            swapped = True
        return result

    synthetic = _inventory(tmp_path / "synthetic.whl", "wheel")
    source = SourceInventory(
        synthetic.name,
        synthetic.version,
        synthetic.metadata,
        synthetic.description_bytes,
        synthetic.license_bytes,
        synthetic.console_scripts,
        synthetic.package_files,
        synthetic.resources,
        {},
    )
    monkeypatch.setattr(check_artifacts, "inspect_source", lambda _root: source)
    monkeypatch.setattr(
        check_artifacts,
        "find_artifacts",
        lambda _directory: (wheel_path, sdist_path),
    )
    monkeypatch.setattr(check_artifacts, "_copy_descriptor", copy_then_swap)
    monkeypatch.setattr(
        check_artifacts,
        "install_smoke",
        lambda artifact, _root, _offline: installs.append(artifact.kind),
    )

    with pytest.raises(SystemExit) as caught:
        check_artifacts.main(["--repo-root", str(tmp_path)])

    assert caught.value.code == 1
    assert swapped
    assert wheel_path.read_bytes() == b"unvalidated replacement"
    assert installs == []
    assert "changed while it was being pinned" in capsys.readouterr().err


def test_private_artifact_snapshot_digest_must_match_source_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "candidate-py3-none-any.whl"
    source.write_bytes(b"validated original candidate")
    snapshot_directory = tmp_path / "snapshots"
    original_copy = check_artifacts._copy_descriptor

    def corrupt_private_copy(source_fd: int, destination_fd: int) -> tuple[str, int]:
        result = original_copy(source_fd, destination_fd)
        os.lseek(destination_fd, 0, os.SEEK_SET)
        os.write(destination_fd, b"X")
        return result

    monkeypatch.setattr(check_artifacts, "_copy_descriptor", corrupt_private_copy)

    with pytest.raises(ArtifactError, match="private artifact snapshot could not be verified"):
        check_artifacts._pin_artifact(source, snapshot_directory)

    assert source.read_bytes() == b"validated original candidate"
    assert not (snapshot_directory / source.name).exists()


def test_artifact_swap_after_inventory_uses_only_pinned_bytes_then_fails_reverify(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    wheel_path = tmp_path / "candidate-py3-none-any.whl"
    sdist_path = tmp_path / "candidate.tar.gz"
    wheel_bytes = b"validated wheel snapshot"
    sdist_bytes = b"validated sdist snapshot"
    wheel_path.write_bytes(wheel_bytes)
    sdist_path.write_bytes(sdist_bytes)
    replacement = tmp_path / "unvalidated-replacement"
    replacement.write_bytes(b"unvalidated replacement")

    wheel = _inventory(wheel_path, "wheel")
    sdist = replace(
        _inventory(sdist_path, "sdist"),
        metadata=wheel.metadata,
        description_bytes=wheel.description_bytes,
        license_bytes=wheel.license_bytes,
        console_scripts=wheel.console_scripts,
        package_files=wheel.package_files,
        resources=wheel.resources,
    )
    source = SourceInventory(
        wheel.name,
        wheel.version,
        wheel.metadata,
        wheel.description_bytes,
        wheel.license_bytes,
        wheel.console_scripts,
        wheel.package_files,
        wheel.resources,
        sdist.sdist_files,
    )
    observed: list[tuple[str, Path, bytes]] = []
    swapped = False

    def smoke_from_private_snapshot(
        artifact: Inventory,
        _root: Path,
        _offline: bool,
    ) -> None:
        nonlocal swapped
        if not swapped:
            os.replace(replacement, wheel_path)
            swapped = True
        observed.append((artifact.kind, artifact.path, artifact.path.read_bytes()))

    monkeypatch.setattr(check_artifacts, "inspect_source", lambda _root: source)
    monkeypatch.setattr(
        check_artifacts,
        "find_artifacts",
        lambda _directory: (wheel_path, sdist_path),
    )
    monkeypatch.setattr(check_artifacts, "inspect_wheel", lambda _path: wheel)
    monkeypatch.setattr(check_artifacts, "inspect_sdist", lambda _path: sdist)
    monkeypatch.setattr(check_artifacts, "install_smoke", smoke_from_private_snapshot)

    with pytest.raises(SystemExit) as caught:
        check_artifacts.main(["--repo-root", str(tmp_path)])

    assert caught.value.code == 1
    assert swapped
    assert [(kind, content) for kind, _path, content in observed] == [
        ("wheel", wheel_bytes),
        ("sdist", sdist_bytes),
    ]
    assert all(path not in {wheel_path, sdist_path} for _kind, path, _content in observed)
    assert wheel_path.read_bytes() == b"unvalidated replacement"
    assert "public artifact changed after it was pinned" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("case", "message"),
    [
        ("version", "artifact identity does not match the current source"),
        ("resource", "artifact resources do not match the current source"),
        ("project", "sdist project files do not match the current source"),
    ],
)
def test_artifact_validation_rejects_source_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    case: str,
    message: str,
) -> None:
    wheel = _inventory(tmp_path / "candidate.whl", "wheel")
    sdist = _inventory(tmp_path / "candidate.tar.gz", "sdist")
    source = SourceInventory(
        name="milhouse-observability",
        version="0.1.0a0",
        metadata=wheel.metadata,
        description_bytes=wheel.description_bytes,
        license_bytes=wheel.license_bytes,
        console_scripts=wheel.console_scripts,
        package_files=wheel.package_files,
        resources=wheel.resources,
        sdist_files=sdist.sdist_files,
    )
    if case == "version":
        source = replace(source, version="0.1.0b1")
    elif case == "resource":
        source = replace(source, resources={"resources/manifest.json": b"source drift"})
    elif case == "project":
        source = replace(source, sdist_files={"pyproject.toml": b"source drift"})

    monkeypatch.setattr(check_artifacts, "inspect_source", lambda _root: source)
    monkeypatch.setattr(
        check_artifacts,
        "find_artifacts",
        lambda _directory: (wheel.path, sdist.path),
    )
    monkeypatch.setattr(check_artifacts, "inspect_wheel", lambda _path: wheel)
    monkeypatch.setattr(check_artifacts, "inspect_sdist", lambda _path: sdist)

    with pytest.raises(SystemExit) as caught:
        check_artifacts.main(["--repo-root", os.fspath(tmp_path), "--skip-install"])

    assert caught.value.code == 1
    assert message in capsys.readouterr().err


def test_install_smoke_syncs_runtime_dependencies_without_dev_groups(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact_path = tmp_path / "candidate.whl"
    artifact_path.write_bytes(b"fixture")
    artifact = _inventory(artifact_path, "wheel")
    uv = tmp_path / "uv"
    uv.write_bytes(b"fixture")
    calls: list[tuple[tuple[str, ...], dict[str, str], str]] = []

    def fake_run(
        command: list[str],
        _cwd: Path,
        env: dict[str, str],
        label: str,
    ) -> str:
        calls.append((tuple(command), env, label))
        if label.endswith("CLI version"):
            return "milhouse, version 0.1.0a0"
        if label.endswith("resource smoke"):
            return json.dumps(
                {
                    "version": artifact.version,
                    "resources": sorted(artifact.resources),
                }
            )
        return ""

    monkeypatch.setattr(check_artifacts, "candidate_uv", lambda: uv)
    monkeypatch.setattr(check_artifacts, "verify_uv", lambda _path: None)
    monkeypatch.setattr(check_artifacts, "_run", fake_run)
    monkeypatch.setenv("PYTHONPATH", "ambient-development-environment")
    monkeypatch.setenv("UV_PROJECT", "ambient-project")
    monkeypatch.setenv("UV_CONFIG_FILE", "ambient-config")

    install_smoke(artifact, tmp_path, offline=True)

    sync, sync_env, label = calls[0]
    assert label == "wheel locked dependency sync"
    assert "--frozen" in sync
    assert "--no-install-project" in sync
    assert "--no-dev" in sync
    assert "--exact" in sync
    assert "--offline" in sync
    assert "--all-groups" not in sync
    assert "PYTHONPATH" not in sync_env
    assert "UV_PROJECT" not in sync_env
    assert "UV_CONFIG_FILE" not in sync_env
    uv_commands = [command for command, _env, _label in calls if command[0] == str(uv)]
    assert uv_commands
    assert all(command[1] == "--no-config" for command in uv_commands)


def test_sdist_install_smoke_builds_and_compares_a_locked_derived_wheel(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact_path = tmp_path / "candidate.tar.gz"
    artifact_path.write_bytes(b"fixture")
    artifact = _inventory(artifact_path, "sdist")
    uv = tmp_path / "uv"
    uv.write_bytes(b"fixture")
    calls: list[str] = []

    def fake_run(
        command: list[str],
        _cwd: Path,
        _env: dict[str, str],
        label: str,
    ) -> str:
        calls.append(label)
        if label == "sdist locked wheel build":
            output = Path(command[command.index("--outdir") + 1])
            (output / "derived-py3-none-any.whl").write_bytes(b"derived")
        if label.endswith("CLI version"):
            return f"milhouse, version {artifact.version}"
        if label.endswith("resource smoke"):
            return json.dumps(
                {"version": artifact.version, "resources": sorted(artifact.resources)}
            )
        return ""

    source_root = tmp_path / "extracted"
    source_root.mkdir()
    derived = replace(artifact, path=tmp_path / "derived-py3-none-any.whl", kind="wheel")
    monkeypatch.setattr(check_artifacts, "candidate_uv", lambda: uv)
    monkeypatch.setattr(check_artifacts, "verify_uv", lambda _path: None)
    monkeypatch.setattr(check_artifacts, "_run", fake_run)
    monkeypatch.setattr(
        check_artifacts,
        "_extract_sdist",
        lambda _path, _destination: source_root,
    )
    monkeypatch.setattr(check_artifacts, "inspect_wheel", lambda path: replace(derived, path=path))

    install_smoke(artifact, tmp_path, offline=False)

    assert "sdist locked wheel build" in calls
    assert "sdist install" in calls


@pytest.mark.parametrize(
    ("case", "message"),
    [
        ("missing", "did not produce exactly one wheel"),
        ("drift", "wheel built from sdist does not match sdist contents"),
    ],
)
def test_sdist_install_smoke_rejects_missing_and_drifted_derived_wheels(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    case: str,
    message: str,
) -> None:
    artifact_path = tmp_path / "candidate.tar.gz"
    artifact_path.write_bytes(b"fixture")
    artifact = _inventory(artifact_path, "sdist")
    uv = tmp_path / "uv"
    uv.write_bytes(b"fixture")
    source_root = tmp_path / "extracted"
    source_root.mkdir()

    def fake_run(
        command: list[str],
        _cwd: Path,
        _env: dict[str, str],
        label: str,
    ) -> str:
        if label == "sdist locked wheel build" and case == "drift":
            output = Path(command[command.index("--outdir") + 1])
            (output / "derived-py3-none-any.whl").write_bytes(b"derived")
        return ""

    monkeypatch.setattr(check_artifacts, "candidate_uv", lambda: uv)
    monkeypatch.setattr(check_artifacts, "verify_uv", lambda _path: None)
    monkeypatch.setattr(check_artifacts, "_run", fake_run)
    monkeypatch.setattr(
        check_artifacts,
        "_extract_sdist",
        lambda _path, _destination: source_root,
    )
    monkeypatch.setattr(
        check_artifacts,
        "inspect_wheel",
        lambda path: replace(artifact, path=path, kind="wheel", package_files={"drift": b"x"}),
    )

    with pytest.raises(ArtifactError, match=message):
        install_smoke(artifact, tmp_path, offline=False)


def test_both_artifacts_use_distinct_exact_receiver_extra_environments(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wheel_path = tmp_path / "candidate [local]-py3-none-any.whl"
    wheel_path.write_bytes(b"fixture")
    sdist_path = tmp_path / "candidate.tar.gz"
    sdist_path.write_bytes(b"fixture")
    wheel = _inventory(wheel_path, "wheel")
    sdist = _inventory(sdist_path, "sdist")
    uv = tmp_path / "uv"
    uv.write_bytes(b"fixture")
    calls: list[tuple[tuple[str, ...], dict[str, str], str]] = []

    def fake_run(
        command: list[str],
        _cwd: Path,
        env: dict[str, str],
        label: str,
    ) -> str:
        calls.append((tuple(command), env.copy(), label))
        if label == "sdist locked wheel build":
            output = Path(command[command.index("--outdir") + 1])
            (output / "derived-py3-none-any.whl").write_bytes(b"derived")
        if label.endswith("CLI version"):
            return f"milhouse, version {VERSION}"
        if label.endswith("resource smoke"):
            return json.dumps(
                {
                    "version": VERSION,
                    "resources": sorted(wheel.resources),
                }
            )
        return ""

    source_root = tmp_path / "extracted"
    source_root.mkdir()
    derived = replace(sdist, path=tmp_path / "derived-py3-none-any.whl", kind="wheel")
    monkeypatch.setattr(check_artifacts, "candidate_uv", lambda: uv)
    monkeypatch.setattr(check_artifacts, "verify_uv", lambda _path: None)
    monkeypatch.setattr(check_artifacts, "_run", fake_run)
    monkeypatch.setattr(
        check_artifacts,
        "_extract_sdist",
        lambda _path, _destination: source_root,
    )
    monkeypatch.setattr(check_artifacts, "inspect_wheel", lambda path: replace(derived, path=path))
    monkeypatch.setenv("PIP_INDEX_URL", "https://ambient.invalid/simple")
    monkeypatch.setenv("PYTHONPATH", "ambient-development-environment")
    monkeypatch.setenv("UV_CONFIG_FILE", "ambient-config")
    monkeypatch.setenv("UV_PROJECT", "ambient-project")
    monkeypatch.setenv("VIRTUAL_ENV", "ambient-virtual-environment")

    install_smoke(wheel, tmp_path, offline=True)
    install_smoke(sdist, tmp_path, offline=True)

    by_label = {label: (command, env) for command, env, label in calls}
    expected_receiver_syncs = {
        "wheel receiver locked dependency sync",
        "sdist receiver locked dependency sync",
    }
    assert expected_receiver_syncs <= by_label.keys()
    base_environments: set[str] = set()
    receiver_environments: set[str] = set()
    for kind in ("wheel", "sdist"):
        base_sync, base_sync_env = by_label[f"{kind} locked dependency sync"]
        receiver_sync, receiver_sync_env = by_label[f"{kind} receiver locked dependency sync"]
        base_environment = base_sync_env["UV_PROJECT_ENVIRONMENT"]
        receiver_environment = receiver_sync_env["UV_PROJECT_ENVIRONMENT"]
        base_environments.add(base_environment)
        receiver_environments.add(receiver_environment)
        assert Path(base_environment).name == "environment"
        assert Path(receiver_environment).name == "receiver-environment"
        assert Path(base_environment).parent == Path(receiver_environment).parent
        assert base_environment != receiver_environment

        assert "--extra" not in base_sync
        assert "--frozen" in receiver_sync
        assert "--exact" in receiver_sync
        assert "--no-dev" in receiver_sync
        assert "--no-install-project" in receiver_sync
        assert "--project" not in receiver_sync
        assert "--all-groups" not in receiver_sync
        assert "--offline" in receiver_sync
        assert receiver_sync[receiver_sync.index("--extra") + 1] == "receiver"

        receiver_install, receiver_install_env = by_label[f"{kind} receiver install"]
        requirement = receiver_install[-1]
        assert requirement.startswith("milhouse-observability[receiver] @ file://")
        assert "--no-deps" in receiver_install
        assert "--offline" in receiver_install
        assert receiver_install_env["UV_PROJECT_ENVIRONMENT"] == receiver_environment
        if kind == "wheel":
            assert "%20%5Blocal%5D" in requirement
            assert "candidate [local]" not in requirement
        else:
            assert "sdist-wheel/derived-py3-none-any.whl" in requirement
            assert sdist_path.as_uri() not in requirement

        receiver_check, receiver_check_env = by_label[f"{kind} receiver pip check"]
        assert receiver_check[:4] == (str(uv), "--no-config", "pip", "check")
        checked_python = receiver_check[receiver_check.index("--python") + 1]
        assert Path(checked_python).parent.parent == Path(receiver_environment)
        assert receiver_check_env["UV_PROJECT_ENVIRONMENT"] == receiver_environment

    assert len(base_environments) == 2
    assert len(receiver_environments) == 2
    assert base_environments.isdisjoint(receiver_environments)
    for _command, env, _label in calls:
        assert "PIP_INDEX_URL" not in env
        assert "PYTHONPATH" not in env
        assert "UV_CONFIG_FILE" not in env
        assert "UV_PROJECT" not in env
        assert "VIRTUAL_ENV" not in env


@pytest.mark.parametrize(
    ("version_output", "resource_output", "message"),
    [
        ("milhouse, version other", "{}", "CLI version does not match"),
        (f"milhouse, version {VERSION}", "not json", "invalid evidence"),
        (
            f"milhouse, version {VERSION}",
            json.dumps({"version": "other", "resources": ["resources/manifest.json"]}),
            "installed metadata drifted",
        ),
        (
            f"milhouse, version {VERSION}",
            json.dumps({"version": VERSION, "resources": []}),
            "installed resource inventory drifted",
        ),
    ],
)
def test_install_smoke_rejects_cli_and_resource_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    version_output: str,
    resource_output: str,
    message: str,
) -> None:
    path = tmp_path / "candidate.whl"
    path.write_bytes(b"fixture")
    artifact = replace(_inventory(path, "wheel"), version=VERSION)
    uv = tmp_path / "uv"
    uv.write_bytes(b"fixture")

    def fake_run(
        _command: list[str],
        _cwd: Path,
        _env: dict[str, str],
        label: str,
    ) -> str:
        if label.endswith("CLI version"):
            return version_output
        if label.endswith("resource smoke"):
            return resource_output
        return ""

    monkeypatch.setattr(check_artifacts, "candidate_uv", lambda: uv)
    monkeypatch.setattr(check_artifacts, "verify_uv", lambda _path: None)
    monkeypatch.setattr(check_artifacts, "_run", fake_run)

    with pytest.raises(ArtifactError, match=message):
        install_smoke(artifact, tmp_path, offline=False)


def test_artifact_main_success_writes_hashes_and_runs_both_smokes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wheel_path = tmp_path / "candidate.whl"
    sdist_path = tmp_path / "candidate.tar.gz"
    wheel_path.write_bytes(b"wheel")
    sdist_path.write_bytes(b"sdist")
    wheel = _inventory(wheel_path, "wheel")
    sdist = replace(
        _inventory(sdist_path, "sdist"),
        metadata=wheel.metadata,
        description_bytes=wheel.description_bytes,
        license_bytes=wheel.license_bytes,
        console_scripts=wheel.console_scripts,
        package_files=wheel.package_files,
        resources=wheel.resources,
    )
    source = SourceInventory(
        wheel.name,
        wheel.version,
        wheel.metadata,
        wheel.description_bytes,
        wheel.license_bytes,
        wheel.console_scripts,
        wheel.package_files,
        wheel.resources,
        sdist.sdist_files,
    )
    smoke_calls: list[str] = []
    monkeypatch.setattr(check_artifacts, "inspect_source", lambda _root: source)
    monkeypatch.setattr(
        check_artifacts, "find_artifacts", lambda _directory: (wheel_path, sdist_path)
    )
    monkeypatch.setattr(check_artifacts, "inspect_wheel", lambda _path: wheel)
    monkeypatch.setattr(check_artifacts, "inspect_sdist", lambda _path: sdist)
    monkeypatch.setattr(
        check_artifacts,
        "install_smoke",
        lambda artifact, _root, _offline: smoke_calls.append(artifact.kind),
    )
    hashes = tmp_path / "hashes.txt"

    assert (
        check_artifacts.main(
            [
                "--repo-root",
                str(tmp_path),
                "--dist-dir",
                str(tmp_path),
                "--write-hashes",
                str(hashes),
            ]
        )
        == 0
    )
    assert smoke_calls == ["wheel", "sdist"]
    assert hashes.is_file()
    assert (
        check_artifacts.main(
            [
                "--repo-root",
                str(tmp_path),
                "--dist-dir",
                str(tmp_path),
                "--skip-install",
            ]
        )
        == 0
    )
    assert smoke_calls == ["wheel", "sdist"]


@pytest.mark.parametrize(
    ("case", "message"),
    [
        ("artifact identity", "wheel and sdist metadata do not match"),
        ("metadata", "complete core metadata headers differ"),
        ("sdist description", "wheel and sdist metadata descriptions differ"),
        ("source metadata", "core metadata does not match the current source"),
        ("source description", "metadata description does not match README.md"),
        ("source license", "LICENSE does not match the current source"),
        ("sdist console", "wheel and sdist console entry points differ"),
        ("source console", "console entry points do not match the current source"),
        ("sdist package", "package-file inventories differ"),
        ("source package", "package files do not match the current source"),
        ("sdist resource", "packaged resources differ"),
    ],
)
def test_artifact_main_rejects_cross_surface_parity_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    case: str,
    message: str,
) -> None:
    wheel = _inventory(tmp_path / "candidate.whl", "wheel")
    sdist = replace(
        _inventory(tmp_path / "candidate.tar.gz", "sdist"),
        metadata=wheel.metadata,
        description_bytes=wheel.description_bytes,
        license_bytes=wheel.license_bytes,
        console_scripts=wheel.console_scripts,
        package_files=wheel.package_files,
        resources=wheel.resources,
    )
    source = SourceInventory(
        wheel.name,
        wheel.version,
        wheel.metadata,
        wheel.description_bytes,
        wheel.license_bytes,
        wheel.console_scripts,
        wheel.package_files,
        wheel.resources,
        sdist.sdist_files,
    )
    if case == "artifact identity":
        sdist = replace(sdist, version="0.1.0b1")
    elif case == "metadata":
        sdist = replace(sdist, metadata=(("version", ("other",)),))
    elif case == "sdist description":
        sdist = replace(sdist, description_bytes=b"different")
    elif case == "source metadata":
        source = replace(source, metadata=(("version", ("other",)),))
    elif case == "source description":
        source = replace(source, description_bytes=b"different")
    elif case == "source license":
        source = replace(source, license_bytes=b"different")
    elif case == "sdist console":
        sdist = replace(sdist, console_scripts=(("other", "target"),))
    elif case == "source console":
        source = replace(source, console_scripts=(("other", "target"),))
    elif case == "sdist package":
        sdist = replace(sdist, package_files={"other": b"different"})
    elif case == "source package":
        source = replace(source, package_files={"other": b"different"})
    elif case == "sdist resource":
        sdist = replace(sdist, resources={"other": b"different"})
    monkeypatch.setattr(check_artifacts, "inspect_source", lambda _root: source)
    monkeypatch.setattr(
        check_artifacts,
        "find_artifacts",
        lambda _directory: (wheel.path, sdist.path),
    )
    monkeypatch.setattr(check_artifacts, "inspect_wheel", lambda _path: wheel)
    monkeypatch.setattr(check_artifacts, "inspect_sdist", lambda _path: sdist)

    with pytest.raises(SystemExit) as caught:
        check_artifacts.main(["--repo-root", str(tmp_path), "--skip-install"])

    assert caught.value.code == 1


def test_artifact_main_does_not_rewrite_an_explicit_system_exit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def stop(_root: Path) -> SourceInventory:
        raise SystemExit(7)

    monkeypatch.setattr(check_artifacts, "inspect_source", stop)
    with pytest.raises(SystemExit) as caught:
        check_artifacts.main(["--repo-root", str(tmp_path)])

    assert caught.value.code == 7


def test_artifact_validator_direct_script_entrypoint_fails_closed_for_missing_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    script = Path(check_artifacts.__file__)
    monkeypatch.syspath_prepend(str(script.parent))
    monkeypatch.setattr(sys, "argv", [str(script), "--repo-root", str(tmp_path / "missing")])

    with pytest.raises(SystemExit) as caught:
        runpy.run_path(str(script), run_name="__main__")

    assert caught.value.code == 1
