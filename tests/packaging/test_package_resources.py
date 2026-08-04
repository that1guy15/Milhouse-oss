from importlib import metadata, resources

from milhouse import __version__
from milhouse.resources import load_manifest


def test_distribution_metadata_and_import_version_agree() -> None:
    assert metadata.version("milhouse-observability") == __version__


def test_typed_resource_inventory_is_installed() -> None:
    package_root = resources.files("milhouse")
    manifest = load_manifest()

    assert package_root.joinpath("py.typed").is_file()
    assert package_root.joinpath("resources", "manifest.json").is_file()
    assert set(manifest.resources) == {
        "py.typed",
        "resources/manifest.json",
        "storage/migrations/0001_core.sql",
        "storage/migrations/0002_records.sql",
        "storage/migrations/0003_feedback.sql",
        "storage/migrations/0004_views.sql",
    }
    for migration in ("0001_core", "0002_records", "0003_feedback", "0004_views"):
        assert package_root.joinpath("storage", "migrations", f"{migration}.sql").is_file()
