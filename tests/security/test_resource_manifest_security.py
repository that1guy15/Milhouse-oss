import secrets

import pytest

from milhouse.resources import ResourceManifest, ResourceManifestError, read_resource_text


def _valid_manifest() -> dict[str, object]:
    return {
        "manifest_version": 1,
        "distribution": "milhouse-observability",
        "import_package": "milhouse",
        "resources": ["py.typed"],
    }


def test_manifest_rejects_runtime_generated_sensitive_fields_without_echoing_values() -> None:
    adversarial_value = "".join(("gh", "p", "_", secrets.token_urlsafe(32)))
    candidate = _valid_manifest()
    candidate["credential"] = adversarial_value

    with pytest.raises(ResourceManifestError) as caught:
        ResourceManifest.from_mapping(candidate)

    assert adversarial_value not in str(caught.value)


@pytest.mark.parametrize(
    "relative_path",
    ("../__init__.py", "/etc/passwd", "resources\\manifest.json", "./py.typed"),
)
def test_resource_reader_rejects_paths_outside_the_declared_namespace(
    relative_path: str,
) -> None:
    with pytest.raises(ResourceManifestError):
        read_resource_text(relative_path)
