import pytest

from milhouse.resources import ResourceManifest, ResourceManifestError


@pytest.mark.parametrize("unsupported_version", [0, 2, "1", True, None])
def test_unsupported_resource_manifest_versions_fail_closed(
    unsupported_version: object,
) -> None:
    candidate = {
        "manifest_version": unsupported_version,
        "distribution": "milhouse-observability",
        "import_package": "milhouse",
        "resources": ["py.typed"],
    }

    with pytest.raises(ResourceManifestError, match="unsupported resource manifest version"):
        ResourceManifest.from_mapping(candidate)
