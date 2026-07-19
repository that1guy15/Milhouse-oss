import json
from importlib import resources
from pathlib import Path

from milhouse.resources import load_manifest, read_resource_text


def test_packaged_manifest_declares_only_present_resources() -> None:
    manifest = load_manifest()

    assert manifest.manifest_version == 1
    assert manifest.distribution == "milhouse-observability"
    assert manifest.import_package == "milhouse"
    assert manifest.resources == tuple(sorted(set(manifest.resources)))

    package_root = resources.files("milhouse")
    for relative_path in manifest.resources:
        target = package_root
        for part in Path(relative_path).parts:
            target = target.joinpath(part)
        assert target.is_file(), relative_path
        assert read_resource_text(relative_path) == target.read_text(encoding="utf-8")


def test_synthetic_json_and_jsonl_fixtures_are_equivalent() -> None:
    fixture_root = Path(__file__).resolve().parents[1] / "fixtures" / "w01"
    json_document = json.loads(
        (fixture_root / "synthetic-records.json").read_text(encoding="utf-8")
    )
    jsonl_records = [
        json.loads(line)
        for line in (fixture_root / "synthetic-records.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
        if line
    ]

    assert json_document["fixture_schema"] == "milhouse.synthetic-fixture.v1"
    assert json_document["records"] == jsonl_records
    assert all(record["synthetic"] is True for record in jsonl_records)
