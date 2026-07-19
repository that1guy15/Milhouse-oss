from pathlib import Path

import pytest

from scripts.milhouse_tools import strict_data
from scripts.milhouse_tools.strict_data import DataError, load_data, require_mapping


def _document(tmp_path: Path, name: str, content: str) -> Path:
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    return path


@pytest.mark.parametrize(
    ("name", "content", "message"),
    [
        ("duplicate.json", '{"value": 1, "value": 2}\n', "duplicate JSON key"),
        ("duplicate.toml", "value = 1\nvalue = 2\n", "invalid TOML"),
        ("duplicate.yaml", "value: one\nvalue: two\n", "duplicate YAML key"),
    ],
)
def test_strict_data_rejects_duplicate_mapping_keys(
    tmp_path: Path,
    name: str,
    content: str,
    message: str,
) -> None:
    with pytest.raises(DataError, match=message):
        load_data(_document(tmp_path, name, content))


def test_strict_yaml_rejects_anchors_and_aliases(tmp_path: Path) -> None:
    path = _document(
        tmp_path,
        "alias.yaml",
        "defaults: &defaults\n  enabled: true\ncopy: *defaults\n",
    )

    with pytest.raises(DataError, match="aliases and anchors"):
        load_data(path)


@pytest.mark.parametrize(
    "content",
    [
        "value: !custom data\n",
        "!custom key: value\n",
        "value: !<tag:example.invalid,2026:custom> data\n",
    ],
)
def test_strict_yaml_rejects_nonstandard_tags(tmp_path: Path, content: str) -> None:
    with pytest.raises(DataError, match="nonstandard YAML tag"):
        load_data(_document(tmp_path, "tagged.yaml", content))


@pytest.mark.parametrize(
    ("name", "content"),
    [
        ("non-finite.json", '{"value": NaN}\n'),
        ("non-finite.toml", "value = inf\n"),
        ("non-finite.yaml", "value: .nan\n"),
    ],
)
def test_strict_data_rejects_non_finite_numbers(
    tmp_path: Path,
    name: str,
    content: str,
) -> None:
    with pytest.raises(DataError, match="non-finite"):
        load_data(_document(tmp_path, name, content))


def test_strict_data_accepts_plain_finite_documents(tmp_path: Path) -> None:
    assert load_data(_document(tmp_path, "data.json", '{"value": 1.25}\n')) == {"value": 1.25}
    assert load_data(_document(tmp_path, "data.toml", "value = 1.25\n")) == {"value": 1.25}
    assert load_data(_document(tmp_path, "data.yaml", "value: 1.25\n")) == {"value": "1.25"}


def test_strict_data_rejects_empty_symlink_oversized_and_unsupported_documents(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    empty = _document(tmp_path, "empty.json", "")
    with pytest.raises(DataError, match="empty documents"):
        load_data(empty)

    target = _document(tmp_path, "target.json", "{}")
    link = tmp_path / "link.json"
    link.symlink_to(target)
    with pytest.raises(DataError, match="non-symlink"):
        load_data(link)

    monkeypatch.setattr(strict_data, "MAX_DOCUMENT_BYTES", 1)
    with pytest.raises(DataError, match="16 MiB safety bound"):
        load_data(target)

    unsupported = _document(tmp_path, "data.txt", "value")
    monkeypatch.setattr(strict_data, "MAX_DOCUMENT_BYTES", 1024)
    with pytest.raises(DataError, match="unsupported data-file suffix"):
        load_data(unsupported)


@pytest.mark.parametrize(
    ("name", "content"),
    [
        ("invalid.json", "{"),
        ("invalid.toml", "[invalid"),
        ("invalid.yaml", "value: [unterminated"),
    ],
)
def test_strict_data_normalizes_parser_errors(tmp_path: Path, name: str, content: str) -> None:
    with pytest.raises(DataError, match="invalid"):
        load_data(_document(tmp_path, name, content))


def test_strict_yaml_scalar_and_sequence_conversion(tmp_path: Path) -> None:
    value = load_data(
        _document(
            tmp_path,
            "values.yaml",
            "null_value: null\n"
            "true_value: true\n"
            "false_value: false\n"
            "integer: -7\n"
            "items: [one, two]\n",
        )
    )
    assert value == {
        "null_value": None,
        "true_value": True,
        "false_value": False,
        "integer": -7,
        "items": ["one", "two"],
    }


def test_strict_yaml_rejects_complex_mapping_keys(tmp_path: Path) -> None:
    with pytest.raises(DataError, match="mapping keys must be scalar strings"):
        load_data(_document(tmp_path, "complex.yaml", "? [one, two]\n: value\n"))


def test_require_mapping_accepts_string_keys_and_rejects_other_shapes() -> None:
    assert require_mapping({"value": 1}, "fixture") == {"value": 1}
    with pytest.raises(DataError, match="string-keyed mapping"):
        require_mapping([], "fixture")
    with pytest.raises(DataError, match="string-keyed mapping"):
        require_mapping({1: "value"}, "fixture")
