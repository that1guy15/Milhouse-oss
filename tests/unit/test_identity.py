import re

import pytest
from pydantic import ValidationError

from milhouse.domain.identity import (
    DedupeSourceV1,
    IdentityError,
    ObservationCoordinateV1,
    RecordDedupeV1,
    RecordIdentityV1,
    SourceIdentityV1,
    derive_content_hash,
    derive_dedupe_key,
    derive_record_id,
    validate_dedupe_key,
    validate_record_id,
)


def _source(*, generation: str = "0" * 64) -> SourceIdentityV1:
    return SourceIdentityV1(
        id="example-source",
        type="source.event",
        observation_namespace_id="mh_ns1_00000000000040008000000000000000",
        source_generation_digest=generation,
    )


def _identity(**overrides: object) -> RecordIdentityV1:
    values: dict[str, object] = {
        "installation_id": "mh_in1_00000000000040008000000000000000",
        "redaction_version": "r1-e1",
        "source": _source(),
        "scope": "target",
        "target_id": "example-target",
        "record_type": "event",
        "name": "source.event",
        "source_event_id": "event-1",
        "source_entity_id": "entity-1",
        "observation": ObservationCoordinateV1(
            kind="source.revision",
            parts={"revision": 1},
        ),
    }
    values.update(overrides)
    return RecordIdentityV1.model_validate(values)


def test_record_and_dedupe_ids_are_deterministic_canonical_sha256_tokens() -> None:
    identity = _identity()
    dedupe = RecordDedupeV1.from_identity(identity)

    record_id = derive_record_id(identity)
    dedupe_key = derive_dedupe_key(dedupe)
    expected_token = "".join(
        ("mh_d1_yfzuu5qthlz3", "ocli7jeuybxump5", "uxg4a2ibabe6frv", "zohslqhwyq")
    )

    assert record_id == "mh_g3hdcz3y6hf7wf5puc2h77nm554bfl3e45vrdfyyartayjdogdga"
    assert dedupe_key == expected_token
    assert re.fullmatch(r"mh_[a-z2-7]{51}[aq]", record_id)
    assert re.fullmatch(r"mh_d1_[a-z2-7]{51}[aq]", dedupe_key)
    assert validate_record_id(record_id) == record_id
    assert validate_dedupe_key(dedupe_key) == dedupe_key


def test_generation_and_redaction_changes_do_not_change_dedupe_coordinates() -> None:
    original = _identity()
    changed = _identity(
        source=_source(generation="1" * 64),
        redaction_version="r2-e3",
    )

    assert derive_record_id(original) != derive_record_id(changed)
    assert derive_dedupe_key(RecordDedupeV1.from_identity(original)) == derive_dedupe_key(
        RecordDedupeV1.from_identity(changed)
    )


def test_installation_and_observation_changes_change_record_and_dedupe_ids() -> None:
    original = _identity()
    changed_installation = _identity(installation_id="mh_in1_11111111111141118111111111111111")
    changed_observation = _identity(
        observation=ObservationCoordinateV1(
            kind="source.revision",
            parts={"revision": 2},
        )
    )

    for changed in (changed_installation, changed_observation):
        assert derive_record_id(original) != derive_record_id(changed)
        assert derive_dedupe_key(RecordDedupeV1.from_identity(original)) != derive_dedupe_key(
            RecordDedupeV1.from_identity(changed)
        )


def test_content_hash_is_domain_separated_and_order_independent() -> None:
    first = {"content_version": 1, "name": "source.event", "data": {"status": "ok"}}
    reordered = {"data": {"status": "ok"}, "name": "source.event", "content_version": 1}

    assert derive_content_hash(first) == derive_content_hash(reordered)
    assert derive_content_hash(first) == (
        "ae0a88c0cec9980e744d6c50ccb986d1a39664a887c86254cd5cbacdceae760e"
    )


@pytest.mark.parametrize(
    "value",
    [
        "mh_" + "a" * 51 + "b",
        "mh_" + "A" * 52,
        "mh_d1_" + "a" * 51 + "b",
        1,
    ],
)
def test_digest_token_validation_rejects_noncanonical_or_wrong_tokens(value: object) -> None:
    validator = (
        validate_dedupe_key
        if isinstance(value, str) and value.startswith("mh_d1_")
        else validate_record_id
    )
    with pytest.raises(IdentityError):
        validator(value)  # type: ignore[arg-type]


def test_identity_models_reject_unknown_fields_coercion_and_scope_mismatch() -> None:
    with pytest.raises(ValidationError):
        RecordIdentityV1.model_validate(
            {
                **_identity().model_dump(mode="python"),
                "unknown": "field",
            }
        )

    with pytest.raises(ValidationError):
        ObservationCoordinateV1.model_validate(
            {"kind": "source.revision", "parts": {"revision": b"1"}}
        )

    with pytest.raises(ValidationError):
        _identity(scope="installation")

    installation_identity = _identity(scope="installation", target_id=None)
    dedupe = RecordDedupeV1.from_identity(installation_identity)
    assert dedupe.source == DedupeSourceV1(
        type="source.event",
        id="example-source",
        observation_namespace_id="mh_ns1_00000000000040008000000000000000",
    )
    assert dedupe.target_id is None
