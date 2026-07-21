import json
from pathlib import Path

import pytest

import milhouse.resources as resource_module
from milhouse.resources import (
    ResourceManifest,
    ResourceManifestError,
    load_manifest,
    read_resource_text,
)


def _manifest(**overrides: object) -> dict[str, object]:
    candidate: dict[str, object] = {
        "manifest_version": 1,
        "distribution": "milhouse-observability",
        "import_package": "milhouse",
        "resources": ["py.typed"],
    }
    candidate.update(overrides)
    return candidate


@pytest.mark.parametrize(
    ("candidate", "message"),
    [
        (None, "must be a JSON object"),
        (_manifest(distribution="another-project"), "distribution does not match"),
        (_manifest(import_package="another_package"), "import package does not match"),
        (_manifest(resources="py.typed"), "resources must be an array"),
        (_manifest(resources=[]), "declare at least one resource"),
        (_manifest(resources=["z.json", "a.json"]), "sorted and unique"),
        (_manifest(resources=["py.typed", "py.typed"]), "sorted and unique"),
        (_manifest(resources=[""]), "non-empty strings"),
        (_manifest(resources=[7]), "non-empty strings"),
    ],
)
def test_manifest_rejects_invalid_shapes(candidate: object, message: str) -> None:
    with pytest.raises(ResourceManifestError, match=message):
        ResourceManifest.from_mapping(candidate)


def test_load_manifest_wraps_invalid_packaged_json(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    (tmp_path / "manifest.json").write_text("{", encoding="utf-8")
    monkeypatch.setattr(resource_module.resources, "files", lambda _package: tmp_path)

    with pytest.raises(ResourceManifestError, match="unable to read") as captured:
        load_manifest()

    assert captured.value.code == "MH_RESOURCE_MANIFEST"
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None


def test_resource_reader_rejects_an_undeclared_normalized_path() -> None:
    with pytest.raises(ResourceManifestError, match="not declared"):
        read_resource_text("resources/not-declared.json")


def test_resource_reader_wraps_a_missing_declared_file(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    manifest = ResourceManifest.from_mapping(_manifest(resources=["resources/missing.json"]))
    monkeypatch.setattr(resource_module, "load_manifest", lambda: manifest)
    monkeypatch.setattr(resource_module.resources, "files", lambda _package: tmp_path)

    with pytest.raises(ResourceManifestError, match="unable to read") as captured:
        read_resource_text("resources/missing.json")

    assert captured.value.code == "MH_RESOURCE_MANIFEST"
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None


def test_manifest_json_is_canonical_json() -> None:
    decoded = json.loads(read_resource_text("resources/manifest.json"))

    assert decoded["manifest_version"] == 1
