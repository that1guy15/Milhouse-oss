from hypothesis import given
from hypothesis import strategies as st

from milhouse.resources import ResourceManifest, ResourceManifestError

_SEGMENTS = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyz0123456789_-",
    min_size=1,
    max_size=16,
)
_RESOURCE_PATHS = st.lists(
    st.lists(_SEGMENTS, min_size=1, max_size=4).map("/".join),
    min_size=1,
    max_size=12,
    unique=True,
).map(sorted)


def _manifest(resources: list[str]) -> dict[str, object]:
    return {
        "manifest_version": 1,
        "distribution": "milhouse-observability",
        "import_package": "milhouse",
        "resources": resources,
    }


@given(_RESOURCE_PATHS)
def test_sorted_unique_package_relative_paths_round_trip(paths: list[str]) -> None:
    manifest = ResourceManifest.from_mapping(_manifest(paths))

    assert manifest.resources == tuple(paths)


@given(_SEGMENTS, _SEGMENTS)
def test_parent_traversal_paths_are_always_rejected(prefix: str, suffix: str) -> None:
    path = f"{prefix}/../{suffix}"

    try:
        ResourceManifest.from_mapping(_manifest([path]))
    except ResourceManifestError:
        return
    raise AssertionError("parent traversal was accepted as a package resource")
