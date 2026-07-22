from __future__ import annotations

import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Literal, cast

import pytest

from milhouse.core.canonical import canonical_json_bytes
from milhouse.domain import (
    RecordDedupeV1,
    RecordDraftV1,
    RecordIdentityV1,
    derive_content_hash,
    derive_dedupe_key,
    derive_record_id,
    finalize_record,
)

FIXTURE_PATH = (
    Path(__file__).resolve().parents[1] / "fixtures" / "w02" / "identity-portability-v1.json"
)
MAX_FIXTURE_BYTES = 256 * 1024
ORDER_MODES = ("natural", "reverse", "rotate")

FixtureObject = dict[str, object]
OrderMode = Literal["natural", "reverse", "rotate"]

_FIXTURE_KEYS = frozenset({"fixture_schema", "vectors"})
_VECTOR_KEYS = frozenset(
    {
        "id",
        "installation_id",
        "identity_variants",
        "content_variants",
        "draft_variants",
        "expected",
    }
)
_EXPECTED_KEYS = frozenset(
    {
        "identity_canonical_hex",
        "record_id",
        "dedupe_wire",
        "content_hash",
        "finalized_envelope",
    }
)
_FINALIZED_EXPECTED_KEYS = frozenset(
    {"record_id", "dedupe_wire", "content_hash", "canonical_sha256"}
)


def _as_object(value: object) -> FixtureObject:
    assert type(value) is dict
    return cast(FixtureObject, value)


def _as_list(value: object) -> list[object]:
    assert type(value) is list
    return cast(list[object], value)


def _as_text(value: object) -> str:
    assert type(value) is str
    return cast(str, value)


def _load_fixture() -> FixtureObject:
    raw = FIXTURE_PATH.read_bytes()
    assert 0 < len(raw) <= MAX_FIXTURE_BYTES
    return _as_object(json.loads(raw))


def _validate_fixture_shape(fixture: FixtureObject) -> list[FixtureObject]:
    assert frozenset(fixture) == _FIXTURE_KEYS
    assert fixture["fixture_schema"] == "milhouse.identity-portability.v1"

    vectors = [_as_object(value) for value in _as_list(fixture["vectors"])]
    assert vectors
    for vector in vectors:
        assert frozenset(vector) == _VECTOR_KEYS
        assert _as_text(vector["installation_id"])
        for variants_key in ("identity_variants", "content_variants", "draft_variants"):
            assert _as_list(vector[variants_key])

        expected = _as_object(vector["expected"])
        assert frozenset(expected) == _EXPECTED_KEYS
        finalized = _as_object(expected["finalized_envelope"])
        assert frozenset(finalized) == _FINALIZED_EXPECTED_KEYS
        for key in _EXPECTED_KEYS - {"finalized_envelope"}:
            assert _as_text(expected[key]) not in {"", "PENDING"}
        for key in _FINALIZED_EXPECTED_KEYS:
            assert _as_text(finalized[key]) not in {"", "PENDING"}

    vector_ids = [_as_text(vector["id"]) for vector in vectors]
    assert len(vector_ids) == len(set(vector_ids))

    return vectors


def _reorder_mappings(value: object, mode: OrderMode) -> object:
    if type(value) is list:
        return [_reorder_mappings(member, mode) for member in cast(list[object], value)]
    if type(value) is not dict:
        return value

    items = list(cast(FixtureObject, value).items())
    if mode == "reverse":
        items.reverse()
    elif mode == "rotate" and len(items) > 1:
        items = items[1:] + items[:1]
    return {key: _reorder_mappings(member, mode) for key, member in items}


def _materialize_datetime_sentinels(value: object) -> object:
    if type(value) is list:
        return [_materialize_datetime_sentinels(member) for member in cast(list[object], value)]
    if type(value) is not dict:
        return value

    mapping = cast(FixtureObject, value)
    if frozenset(mapping) == {"$datetime"}:
        parsed = datetime.fromisoformat(_as_text(mapping["$datetime"]))
        assert parsed.utcoffset() is not None
        return parsed
    return {key: _materialize_datetime_sentinels(member) for key, member in mapping.items()}


def _assert_identifier_edge_vectors(vectors: list[FixtureObject]) -> None:
    by_id = {_as_text(vector["id"]): vector for vector in vectors}
    assert frozenset(by_id) == {
        "target-mixed-scalars",
        "installation-optional-identifiers-absent",
    }

    target_vector = by_id["target-mixed-scalars"]
    for raw_identity in _as_list(target_vector["identity_variants"]):
        identity = _as_object(raw_identity)
        assert identity["scope"] == "target"
        assert _as_text(identity["target_id"])
        assert _as_text(identity["source_event_id"])
        assert _as_text(identity["source_entity_id"])
    for raw_draft in _as_list(target_vector["draft_variants"]):
        draft = _as_object(raw_draft)
        assert draft["scope"] == "target"
        assert _as_object(draft["target"])["id"]
        assert _as_text(draft["source_event_id"])
        assert _as_text(draft["source_entity_id"])

    installation_vector = by_id["installation-optional-identifiers-absent"]
    for raw_identity in _as_list(installation_vector["identity_variants"]):
        identity = _as_object(raw_identity)
        assert identity["scope"] == "installation"
        assert "target_id" not in identity
        assert "source_event_id" not in identity
        assert "source_entity_id" not in identity
    for raw_draft in _as_list(installation_vector["draft_variants"]):
        draft = _as_object(raw_draft)
        assert draft["scope"] == "installation"
        assert "target" not in draft
        assert "source_event_id" not in draft
        assert "source_entity_id" not in draft


@pytest.mark.contract
def test_identity_portability_corpus_matches_locked_golden_wires() -> None:
    vectors = _validate_fixture_shape(_load_fixture())
    _assert_identifier_edge_vectors(vectors)

    for vector in vectors:
        installation_id = _as_text(vector["installation_id"])
        expected = _as_object(vector["expected"])
        finalized_expected = _as_object(expected["finalized_envelope"])

        for raw_identity in _as_list(vector["identity_variants"]):
            for mode in ORDER_MODES:
                reordered = _reorder_mappings(raw_identity, mode)
                identity = RecordIdentityV1.model_validate(reordered)
                identity_bytes = canonical_json_bytes(
                    identity.model_dump(mode="python", exclude_none=True)
                )
                assert identity_bytes.hex() == expected["identity_canonical_hex"]
                assert derive_record_id(identity) == expected["record_id"]
                assert (
                    derive_dedupe_key(RecordDedupeV1.from_identity(identity))
                    == expected["dedupe_wire"]
                )

        for raw_content in _as_list(vector["content_variants"]):
            materialized = _materialize_datetime_sentinels(raw_content)
            for mode in ORDER_MODES:
                content = _as_object(_reorder_mappings(materialized, mode))
                assert derive_content_hash(content) == expected["content_hash"]

        for raw_draft in _as_list(vector["draft_variants"]):
            for mode in ORDER_MODES:
                reordered = _as_object(_reorder_mappings(raw_draft, mode))
                wire = json.dumps(
                    reordered,
                    ensure_ascii=False,
                    allow_nan=False,
                    separators=(",", ":"),
                )
                draft = RecordDraftV1.model_validate_json(wire)
                direct_identity = draft.identity(installation_id)
                direct_record_id = derive_record_id(direct_identity)
                direct_dedupe_key = derive_dedupe_key(RecordDedupeV1.from_identity(direct_identity))

                finalized = finalize_record(draft, installation_id=installation_id)
                finalized_bytes = canonical_json_bytes(
                    finalized.model_dump(mode="python", exclude_none=True)
                )

                assert finalized.record_id == finalized_expected["record_id"]
                assert finalized.dedupe_key == finalized_expected["dedupe_wire"]
                assert finalized.content_hash == finalized_expected["content_hash"]
                assert (
                    hashlib.sha256(finalized_bytes).hexdigest()
                    == finalized_expected["canonical_sha256"]
                )
                assert finalized.record_id == direct_record_id == expected["record_id"]
                assert finalized.dedupe_key == direct_dedupe_key == expected["dedupe_wire"]
