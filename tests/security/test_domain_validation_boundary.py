import json
import pickle
import secrets
import traceback
import warnings
from collections.abc import Callable, Iterator, Mapping
from datetime import UTC, datetime, timedelta, tzinfo
from types import ModuleType
from typing import Literal

import pytest
from pydantic import BaseModel, ConfigDict, TypeAdapter, ValidationError

import milhouse.domain.identity as identity_module
import milhouse.domain.records as record_module
from milhouse.core.canonical import CanonicalizationError, canonical_json_bytes
from milhouse.domain import (
    ActorReferenceV1,
    EventDataV1,
    RecordDraftV1,
    RecordIdentityV1,
    RunDataV1,
    SourceDescriptorV1,
    finalize_record,
)
from milhouse.domain._validation import (
    IDENTITY_VALIDATION_ERROR_MESSAGE,
    IDENTITY_VALIDATION_ERROR_TYPE,
    RECORD_VALIDATION_ERROR_MESSAGE,
    RECORD_VALIDATION_ERROR_TYPE,
    ValueSafeIdentityModel,
    ValueSafeRecordModel,
)
from milhouse.domain.identity import ObservationCoordinateV1
from milhouse.privacy import LayeredRedactor, Pseudonymizer


def _assert_value_safe(
    error: ValidationError,
    *,
    private_values: tuple[str, ...],
    error_type: str,
    message: str,
) -> None:
    surfaces = (
        str(error),
        repr(error),
        repr(error.args),
        repr(error.errors()),
        error.json(),
        "".join(traceback.format_exception(error)),
    )
    for private_value in private_values:
        assert all(private_value not in surface for surface in surfaces)
    assert error.__cause__ is None
    assert error.__context__ is None
    details = error.errors()
    assert len(details) == 1
    assert details[0]["type"] == error_type
    assert details[0]["loc"] in ((), (0,))
    assert details[0]["msg"] == message
    assert details[0]["input"] is None
    assert "ctx" not in details[0]


def _record_document() -> dict[str, object]:
    now = datetime.fromisoformat("2026-07-21T15:00:00+00:00")
    return {
        "record_type": "event",
        "name": "canary.result",
        "occurred_at": now,
        "observed_at": now,
        "ingested_at": now,
        "expires_at": datetime.fromisoformat("2026-08-20T15:00:00+00:00"),
        "operation_id": "operation-1",
        "collector_run_id": "collector-run-1",
        "scope": "target",
        "source": {
            "id": "example-source",
            "type": "site.canary",
            "producer": "collector",
            "observation_namespace_id": "mh_ns1_00000000000040008000000000000000",
            "source_generation_digest": "0" * 64,
            "observation": {"kind": "scheduled.route", "parts": {"route": "home"}},
        },
        "collector": {
            "id": "example-canary",
            "type": "site.canary",
            "implementation_version": "1.0.0",
        },
        "target": {
            "id": "example-target",
            "name": "Example target",
            "kind": "web.service",
            "environment": "test",
        },
        "severity": "info",
        "trust_level": "authenticated",
        "privacy_class": "internal",
        "redaction_version": "r1-e1",
        "data": {
            "type": "event",
            "category": "availability",
            "status": "healthy",
        },
    }


def _deprecated_validate(document: dict[str, object]) -> ActorReferenceV1:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return ActorReferenceV1.validate(document)


def _deprecated_parse_raw(document: str | bytes) -> ActorReferenceV1:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return ActorReferenceV1.parse_raw(document)


def _deprecated_construct(private_value: str) -> ActorReferenceV1:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return ActorReferenceV1.construct(
            type="operator",
            id=f"{private_value}\nspoofed",
        )


def test_record_validation_entry_points_detach_rejected_values() -> None:
    private_value = secrets.token_urlsafe(32)
    document = {"type": "operator", "id": f"{private_value}\nspoofed"}
    operations = (
        lambda: ActorReferenceV1(**document),
        lambda: ActorReferenceV1.model_validate(document),
        lambda: ActorReferenceV1.model_validate_json(json.dumps(document)),
        lambda: ActorReferenceV1.model_validate_strings(document),
        lambda: _deprecated_validate(document),
        lambda: TypeAdapter(ActorReferenceV1).validate_python(document),
        lambda: TypeAdapter(ActorReferenceV1).validate_json(json.dumps(document)),
        lambda: ActorReferenceV1.__pydantic_validator__.validate_python(document),
    )

    for operation in operations:
        with pytest.raises(ValidationError) as captured:
            operation()
        _assert_value_safe(
            captured.value,
            private_values=(private_value,),
            error_type=RECORD_VALIDATION_ERROR_TYPE,
            message=RECORD_VALIDATION_ERROR_MESSAGE,
        )


def test_non_mapping_domain_inputs_are_rejected_value_safely() -> None:
    private_value = secrets.token_urlsafe(32)
    operations = (
        lambda: ActorReferenceV1.model_validate(private_value),
        lambda: TypeAdapter(ActorReferenceV1).validate_python(private_value),
        lambda: ActorReferenceV1.__pydantic_validator__.validate_python(private_value),
    )

    for operation in operations:
        with pytest.raises(ValidationError) as captured:
            operation()
        _assert_value_safe(
            captured.value,
            private_values=(private_value,),
            error_type=RECORD_VALIDATION_ERROR_TYPE,
            message=RECORD_VALIDATION_ERROR_MESSAGE,
        )


def test_invalid_json_unknown_fields_and_discriminators_are_value_safe() -> None:
    private_value = secrets.token_urlsafe(32)
    unknown_field = f"private_{secrets.token_hex(16)}"
    malformed = f'{{"type":"operator","id":"{private_value}"'
    invalid_extra = {"type": "operator", "id": "operator-1", unknown_field: private_value}
    invalid_record = _record_document()
    invalid_record["data"] = {"type": private_value}
    operations = (
        lambda: ActorReferenceV1.model_validate_json(malformed),
        lambda: TypeAdapter(ActorReferenceV1).validate_json(malformed),
        lambda: ActorReferenceV1.__pydantic_validator__.validate_json(malformed),
        lambda: _deprecated_parse_raw(malformed),
        lambda: ActorReferenceV1.model_validate(invalid_extra),
        lambda: RecordDraftV1.model_validate(invalid_record),
    )

    for operation in operations:
        with pytest.raises(ValidationError) as captured:
            operation()
        _assert_value_safe(
            captured.value,
            private_values=(private_value, unknown_field),
            error_type=RECORD_VALIDATION_ERROR_TYPE,
            message=RECORD_VALIDATION_ERROR_MESSAGE,
        )


def test_callers_cannot_weaken_strict_or_extra_field_validation() -> None:
    private_value = secrets.token_urlsafe(32)
    extra_document = {
        "type": "operator",
        "id": "operator-1",
        "private": private_value,
    }
    relaxed_extra_operations = (
        lambda: ActorReferenceV1.model_validate(extra_document, extra="allow"),
        lambda: ActorReferenceV1.model_validate(extra_document, extra="ignore"),
        lambda: TypeAdapter(ActorReferenceV1).validate_python(
            extra_document,
            extra="allow",
        ),
        lambda: ActorReferenceV1.__pydantic_validator__.validate_python(
            extra_document,
            extra="ignore",
        ),
        lambda: TypeAdapter(list[ActorReferenceV1]).validate_python(
            [extra_document],
            extra="allow",
        ),
    )

    for operation in relaxed_extra_operations:
        with pytest.raises(ValidationError) as captured:
            operation()
        _assert_value_safe(
            captured.value,
            private_values=(private_value,),
            error_type=RECORD_VALIDATION_ERROR_TYPE,
            message=RECORD_VALIDATION_ERROR_MESSAGE,
        )

    relaxed_metric = {
        "value": "424242",
        "unit": "requests",
        "metric_semantics": "gauge",
    }
    relaxed_strict_operations = (
        lambda: record_module.MetricDataV1.model_validate(relaxed_metric, strict=False),
        lambda: TypeAdapter(record_module.MetricDataV1).validate_python(
            relaxed_metric,
            strict=False,
        ),
        lambda: TypeAdapter(list[record_module.MetricDataV1]).validate_python(
            [relaxed_metric],
            strict=False,
        ),
    )

    for operation in relaxed_strict_operations:
        with pytest.raises(ValidationError) as captured:
            operation()
        _assert_value_safe(
            captured.value,
            private_values=("424242",),
            error_type=RECORD_VALIDATION_ERROR_TYPE,
            message=RECORD_VALIDATION_ERROR_MESSAGE,
        )


class _HostileRepresentation:
    def __init__(self, private_value: str) -> None:
        self.private_value = private_value

    def __repr__(self) -> str:
        return f"<hostile {self.private_value}>"


class _HostileMapping(Mapping[str, object]):
    def __init__(self, private_value: str) -> None:
        self.private_value = private_value

    def __getitem__(self, key: str) -> object:
        raise RuntimeError(self.private_value)

    def __iter__(self) -> Iterator[str]:
        raise RuntimeError(self.private_value)

    def __len__(self) -> int:
        raise RuntimeError(self.private_value)


class _ForeignActor(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        frozen=True,
        revalidate_instances="always",
    )

    type: Literal["operator"]
    id: str


class _ForeignEvent(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        frozen=True,
        revalidate_instances="always",
    )

    type: Literal["event"] = "event"
    category: str
    status: str


class _WrongDomainEvent(ValueSafeRecordModel):
    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        frozen=True,
        revalidate_instances="always",
    )

    type: Literal["event"] = "event"
    category: str
    status: str


class _ActorReferenceSubtype(ActorReferenceV1):
    pass


class _SourceDescriptorSubtype(SourceDescriptorV1):
    pass


class _EventDataSubtype(EventDataV1):
    pass


class _RecordDraftSubtype(RecordDraftV1):
    pass


class _RecordIdentitySubtype(RecordIdentityV1):
    pass


class _ObservationCoordinateSubtype(ObservationCoordinateV1):
    pass


def test_concrete_model_subtypes_are_rejected_at_top_level_boundaries() -> None:
    private_value = f"private-{secrets.token_hex(16)}"
    subtype = _ActorReferenceSubtype(type="operator", id=private_value)
    operations = (
        lambda: ActorReferenceV1.model_validate(subtype),
        lambda: TypeAdapter(ActorReferenceV1).validate_python(subtype),
        lambda: TypeAdapter(list[ActorReferenceV1]).validate_python([subtype]),
        lambda: ActorReferenceV1.__pydantic_validator__.validate_python(subtype),
    )

    for operation in operations:
        with pytest.raises(ValidationError) as captured:
            operation()
        _assert_value_safe(
            captured.value,
            private_values=(private_value,),
            error_type=RECORD_VALIDATION_ERROR_TYPE,
            message=RECORD_VALIDATION_ERROR_MESSAGE,
        )


@pytest.mark.parametrize("field_name", ["source", "data"])
def test_concrete_model_subtypes_are_rejected_at_nested_annotated_positions(
    field_name: str,
) -> None:
    private_value = secrets.token_hex(16)
    document = _record_document()
    if field_name == "source":
        source_document = dict(document["source"])
        source_document["id"] = f"private-{private_value}"
        document[field_name] = _SourceDescriptorSubtype.model_validate(source_document)
    else:
        document[field_name] = _EventDataSubtype(
            category=f"private.{private_value}",
            status="healthy",
        )

    operations = (
        lambda: RecordDraftV1(**document),
        lambda: RecordDraftV1.model_validate(document),
        lambda: TypeAdapter(RecordDraftV1).validate_python(document),
        lambda: RecordDraftV1.__pydantic_validator__.validate_python(document),
    )

    for operation in operations:
        with pytest.raises(ValidationError) as captured:
            operation()
        _assert_value_safe(
            captured.value,
            private_values=(private_value,),
            error_type=RECORD_VALIDATION_ERROR_TYPE,
            message=RECORD_VALIDATION_ERROR_MESSAGE,
        )


def test_nested_subtypes_cannot_hide_inside_an_exact_model_instance() -> None:
    private_value = secrets.token_hex(16)
    document = _record_document()
    source = SourceDescriptorV1.model_validate(document["source"])
    observation_values = source.observation.model_dump(mode="python")
    observation_values["parts"] = {"route": f"private-{private_value}"}
    observation_subtype = _ObservationCoordinateSubtype.model_validate(observation_values)
    source_values = source.model_dump(mode="python")
    source_values["observation"] = observation_subtype
    forged_source = BaseModel.model_construct.__func__(
        SourceDescriptorV1,
        **source_values,
    )
    document["source"] = forged_source

    operations = (
        lambda: SourceDescriptorV1.model_validate(forged_source),
        lambda: TypeAdapter(SourceDescriptorV1).validate_python(forged_source),
        lambda: RecordDraftV1(**document),
        lambda: RecordDraftV1.model_validate(document),
        lambda: RecordDraftV1.__pydantic_validator__.validate_python(document),
    )

    for operation in operations:
        with pytest.raises(ValidationError) as captured:
            operation()
        _assert_value_safe(
            captured.value,
            private_values=(private_value,),
            error_type=RECORD_VALIDATION_ERROR_TYPE,
            message=RECORD_VALIDATION_ERROR_MESSAGE,
        )


def test_domain_consumers_reject_concrete_model_subtypes_atomically() -> None:
    private_value = secrets.token_hex(16)
    installation_id = "mh_in1_00000000000040008000000000000000"
    document = _record_document()
    document["name"] = f"private.{private_value}"
    subtype_draft = _RecordDraftSubtype.model_validate(document)
    identity = subtype_draft.identity(installation_id)
    subtype_identity = _RecordIdentitySubtype.model_validate(identity.model_dump(mode="python"))

    operations = (
        (
            lambda: finalize_record(subtype_draft, installation_id=installation_id),
            RECORD_VALIDATION_ERROR_TYPE,
            RECORD_VALIDATION_ERROR_MESSAGE,
        ),
        (
            lambda: identity_module.derive_record_id(subtype_identity),
            IDENTITY_VALIDATION_ERROR_TYPE,
            IDENTITY_VALIDATION_ERROR_MESSAGE,
        ),
    )
    for operation, error_type, message in operations:
        with pytest.raises(ValidationError) as captured:
            operation()
        _assert_value_safe(
            captured.value,
            private_values=(private_value,),
            error_type=error_type,
            message=message,
        )

    target = object.__new__(RecordDraftV1)
    with pytest.raises(ValidationError) as captured:
        RecordDraftV1.__pydantic_validator__.validate_python(
            subtype_draft,
            self_instance=target,
        )
    _assert_value_safe(
        captured.value,
        private_values=(private_value,),
        error_type=RECORD_VALIDATION_ERROR_TYPE,
        message=RECORD_VALIDATION_ERROR_MESSAGE,
    )
    assert target.__dict__ == {}
    assert not hasattr(target, "__pydantic_fields_set__")


def test_foreign_pydantic_lookalikes_are_not_normalized_into_domain_models() -> None:
    private_value = f"private-{secrets.token_hex(16)}"
    foreign_actor = _ForeignActor(type="operator", id=private_value)
    document = _record_document()
    document["data"] = _ForeignEvent(
        category=private_value,
        status="healthy",
    )
    operations = (
        lambda: ActorReferenceV1.model_validate(foreign_actor),
        lambda: TypeAdapter(ActorReferenceV1).validate_python(foreign_actor),
        lambda: RecordDraftV1.model_validate(document),
    )

    for operation in operations:
        with pytest.raises(ValidationError) as captured:
            operation()
        _assert_value_safe(
            captured.value,
            private_values=(private_value,),
            error_type=RECORD_VALIDATION_ERROR_TYPE,
            message=RECORD_VALIDATION_ERROR_MESSAGE,
        )


def test_wrong_domain_model_instances_are_not_structurally_coerced() -> None:
    private_value = f"private-{secrets.token_hex(16)}"
    document = _record_document()
    document["data"] = _WrongDomainEvent(
        category=private_value,
        status="healthy",
    )

    with pytest.raises(ValidationError) as captured:
        RecordDraftV1.model_validate(document)
    _assert_value_safe(
        captured.value,
        private_values=(private_value,),
        error_type=RECORD_VALIDATION_ERROR_TYPE,
        message=RECORD_VALIDATION_ERROR_MESSAGE,
    )


def test_exact_nested_domain_instances_are_revalidated() -> None:
    draft = RecordDraftV1.model_validate(_record_document())
    document = draft.model_dump(mode="python")
    for field_name in ("source", "collector", "target", "correlation", "data"):
        document[field_name] = getattr(draft, field_name)

    assert RecordDraftV1.model_validate(document) == draft


def test_bypass_constructed_instances_are_revalidated_without_warning_leaks() -> None:
    private_value = secrets.token_urlsafe(32)
    invalid = BaseModel.model_construct.__func__(
        ActorReferenceV1,
        type="operator",
        id=_HostileRepresentation(private_value),
    )
    operations = (
        lambda: ActorReferenceV1.model_validate(invalid),
        lambda: TypeAdapter(ActorReferenceV1).validate_python(invalid),
        lambda: TypeAdapter(list[ActorReferenceV1]).validate_python([invalid]),
    )

    with warnings.catch_warnings(record=True) as emitted:
        warnings.simplefilter("always")
        for operation in operations:
            with pytest.raises(ValidationError) as captured:
                operation()
            _assert_value_safe(
                captured.value,
                private_values=(private_value,),
                error_type=RECORD_VALIDATION_ERROR_TYPE,
                message=RECORD_VALIDATION_ERROR_MESSAGE,
            )

    assert all(private_value not in str(item.message) for item in emitted)


def test_unchecked_construction_copy_and_file_parsing_paths_are_closed() -> None:
    private_value = secrets.token_urlsafe(32)
    valid = ActorReferenceV1(type="operator", id="operator-1")
    private_path = f"/workspace/{private_value}/record.json"
    operations = (
        lambda: ActorReferenceV1.model_construct(
            type="operator",
            id=f"{private_value}\nspoofed",
        ),
        lambda: _deprecated_construct(private_value),
        lambda: valid.model_copy(update={"id": private_value}),
        lambda: valid.model_copy(update=_HostileMapping(private_value)),
        lambda: valid.copy(update={"id": private_value}),
        lambda: valid.copy(include={"id"}),
        lambda: ActorReferenceV1.__pydantic_validator__.validate_assignment(
            valid,
            "id",
            private_value,
        ),
        lambda: ActorReferenceV1.parse_file(private_path),
        lambda: ActorReferenceV1.from_orm(_HostileRepresentation(private_value)),
        lambda: ActorReferenceV1.parse_raw(
            private_value.encode(),
            proto="pickle",
            allow_pickle=True,
        ),
    )

    for operation in operations:
        with pytest.raises(ValidationError) as captured:
            operation()
        _assert_value_safe(
            captured.value,
            private_values=(private_value, private_path),
            error_type=RECORD_VALIDATION_ERROR_TYPE,
            message=RECORD_VALIDATION_ERROR_MESSAGE,
        )

    assert valid.model_copy(deep=True) == valid
    assert ActorReferenceV1.parse_raw('{"type":"operator","id":"operator-2"}').id == ("operator-2")

    record = finalize_record(
        RecordDraftV1.model_validate(_record_document()),
        installation_id="mh_in1_00000000000040008000000000000000",
    )
    forged_record_id = f"mh_{'a' * 51}q"
    for operation in (
        lambda: record.model_copy(update={"record_id": forged_record_id}),
        lambda: record.copy(update={"record_id": forged_record_id}),
    ):
        with pytest.raises(ValidationError) as captured:
            operation()
        _assert_value_safe(
            captured.value,
            private_values=(forged_record_id,),
            error_type=RECORD_VALIDATION_ERROR_TYPE,
            message=RECORD_VALIDATION_ERROR_MESSAGE,
        )


@pytest.mark.parametrize(
    ("make_value", "field_name", "error_type", "message"),
    [
        (
            lambda: ActorReferenceV1(type="operator", id="operator-1"),
            "id",
            RECORD_VALIDATION_ERROR_TYPE,
            RECORD_VALIDATION_ERROR_MESSAGE,
        ),
        (
            lambda: ObservationCoordinateV1(kind="route", parts={"route": "home"}),
            "kind",
            IDENTITY_VALIDATION_ERROR_TYPE,
            IDENTITY_VALIDATION_ERROR_MESSAGE,
        ),
    ],
)
@pytest.mark.parametrize("operation", ["assign", "delete"])
@pytest.mark.parametrize("name_kind", ["declared", "unknown", "private", "dunder_private"])
def test_frozen_model_mutation_is_value_safe_for_every_domain_family(
    make_value: Callable[[], BaseModel],
    field_name: str,
    error_type: str,
    message: str,
    operation: str,
    name_kind: str,
) -> None:
    private_value = secrets.token_urlsafe(32)
    value = make_value()
    before = dict(value.__dict__)
    attribute = {
        "declared": field_name,
        "unknown": f"unknown_{private_value}",
        "private": f"_{private_value}",
        "dunder_private": f"__{private_value}",
    }[name_kind]

    with pytest.raises(ValidationError) as captured:
        if operation == "assign":
            setattr(value, attribute, _HostileRepresentation(private_value))
        else:
            delattr(value, attribute)

    _assert_value_safe(
        captured.value,
        private_values=(private_value,),
        error_type=error_type,
        message=message,
    )
    assert value.__dict__ == before
    assert private_value not in repr(value.__dict__)
    copied = value.model_copy(deep=True)
    assert copied == value
    assert private_value not in repr(copied.__dict__)


@pytest.mark.parametrize(
    ("make_value", "replacement", "error_type", "message"),
    [
        (
            lambda: ActorReferenceV1(type="operator", id="operator-1"),
            lambda private: {"type": "agent", "id": private},
            RECORD_VALIDATION_ERROR_TYPE,
            RECORD_VALIDATION_ERROR_MESSAGE,
        ),
        (
            lambda: ObservationCoordinateV1(kind="route", parts={"route": "home"}),
            lambda private: {"kind": private, "parts": {"route": "changed"}},
            IDENTITY_VALIDATION_ERROR_TYPE,
            IDENTITY_VALIDATION_ERROR_MESSAGE,
        ),
    ],
)
def test_initialized_models_reject_reinitialization_and_self_instance_validation(
    make_value: Callable[[], BaseModel],
    replacement: Callable[[str], dict[str, object]],
    error_type: str,
    message: str,
) -> None:
    private_value = f"private-{secrets.token_hex(16)}"
    value = make_value()
    before = dict(value.__dict__)
    document = replacement(private_value)
    operations = (
        lambda: value.__init__(**document),
        lambda: BaseModel.__init__(value, **document),
        lambda: type(value).__pydantic_validator__.validate_python(
            document,
            self_instance=value,
        ),
        lambda: type(value).__pydantic_validator__.validate_json(
            json.dumps(document),
            self_instance=value,
        ),
    )

    for operation in operations:
        with pytest.raises(ValidationError) as captured:
            operation()
        _assert_value_safe(
            captured.value,
            private_values=(private_value,),
            error_type=error_type,
            message=message,
        )
        assert value.__dict__ == before


@pytest.mark.parametrize(
    ("make_value", "error_type", "message"),
    [
        (
            lambda: ActorReferenceV1(type="operator", id="operator-1"),
            RECORD_VALIDATION_ERROR_TYPE,
            RECORD_VALIDATION_ERROR_MESSAGE,
        ),
        (
            lambda: ObservationCoordinateV1(kind="route", parts={"route": "home"}),
            IDENTITY_VALIDATION_ERROR_TYPE,
            IDENTITY_VALIDATION_ERROR_MESSAGE,
        ),
    ],
)
def test_pickle_state_export_and_restoration_are_disabled_value_safe(
    make_value: Callable[[], BaseModel],
    error_type: str,
    message: str,
) -> None:
    private_value = f"private-{secrets.token_hex(16)}"
    value = make_value()
    before = dict(value.__dict__)
    hostile_state = {
        "__dict__": {"type": "operator", "id": f"{private_value}\nspoofed"},
        "__pydantic_extra__": None,
        "__pydantic_fields_set__": {"type", "id"},
        "__pydantic_private__": None,
    }
    operations = (
        lambda: value.__getstate__(),
        lambda: value.__setstate__(hostile_state),
        lambda: pickle.dumps(value),
    )

    for operation in operations:
        with pytest.raises(ValidationError) as captured:
            operation()
        _assert_value_safe(
            captured.value,
            private_values=(private_value,),
            error_type=error_type,
            message=message,
        )
        assert value.__dict__ == before


def test_validator_proxy_supports_non_mutating_pydantic_introspection() -> None:
    validator = ActorReferenceV1.__pydantic_validator__
    valid = ActorReferenceV1(type="operator", id="operator-1")

    assert validator.title
    assert validator.get_default_value() is None
    assert validator.isinstance_python(valid)
    assert not validator.isinstance_python(
        {"type": "operator", "id": "operator-1", "unexpected": "value"},
        extra="allow",
    )

    ActorReferenceV1._install_value_safe_validator()
    assert ActorReferenceV1.__pydantic_validator__ is validator


def test_domain_consumers_revalidate_apparently_typed_inputs() -> None:
    private_value = secrets.token_urlsafe(32)
    installation_id = "mh_in1_00000000000040008000000000000000"
    draft = RecordDraftV1.model_validate(_record_document())
    draft_values = draft.model_dump(mode="python")
    draft_values["data"] = _HostileRepresentation(private_value)
    forged_draft = BaseModel.model_construct.__func__(RecordDraftV1, **draft_values)

    with pytest.raises(ValidationError) as captured:
        finalize_record(forged_draft, installation_id=installation_id)
    _assert_value_safe(
        captured.value,
        private_values=(private_value,),
        error_type=RECORD_VALIDATION_ERROR_TYPE,
        message=RECORD_VALIDATION_ERROR_MESSAGE,
    )

    identity = draft.identity(installation_id)
    identity_values = identity.model_dump(mode="python")
    identity_values["name"] = f"{private_value}\nspoofed"
    forged_identity = BaseModel.model_construct.__func__(
        type(identity),
        **identity_values,
    )
    with pytest.raises(ValidationError) as captured:
        identity_module.derive_record_id(forged_identity)
    _assert_value_safe(
        captured.value,
        private_values=(private_value,),
        error_type=IDENTITY_VALIDATION_ERROR_TYPE,
        message=IDENTITY_VALIDATION_ERROR_MESSAGE,
    )


def test_validator_proxy_survives_forced_model_rebuild() -> None:
    schema_before = ActorReferenceV1.model_json_schema()

    assert ActorReferenceV1.model_rebuild(force=True) is True

    private_value = secrets.token_urlsafe(32)
    malformed = f'{{"type":"operator","id":"{private_value}"'
    with pytest.raises(ValidationError) as captured:
        ActorReferenceV1.__pydantic_validator__.validate_json(malformed)
    _assert_value_safe(
        captured.value,
        private_values=(private_value,),
        error_type=RECORD_VALIDATION_ERROR_TYPE,
        message=RECORD_VALIDATION_ERROR_MESSAGE,
    )
    assert ActorReferenceV1.model_json_schema() == schema_before


def test_identity_validation_detaches_nested_rejected_values() -> None:
    private_value = secrets.token_urlsafe(32)
    document = {
        "kind": "source.revision",
        "parts": {"revision": f"{private_value}\nspoofed"},
    }

    with pytest.raises(ValidationError) as captured:
        TypeAdapter(ObservationCoordinateV1).validate_python(document)

    _assert_value_safe(
        captured.value,
        private_values=(private_value,),
        error_type=IDENTITY_VALIDATION_ERROR_TYPE,
        message=IDENTITY_VALIDATION_ERROR_MESSAGE,
    )


class _HostileTimezone(tzinfo):
    def __init__(self, private_value: str) -> None:
        self.private_value = private_value

    def utcoffset(self, value: datetime | None) -> None:
        raise RuntimeError(self.private_value)

    def dst(self, value: datetime | None) -> None:
        return None

    def tzname(self, value: datetime | None) -> str:
        return "hostile"


class _CountingUtcTimezone(tzinfo):
    def __init__(self, *, fail_after: int | None = None, private_value: str = "") -> None:
        self.calls = 0
        self.fail_after = fail_after
        self.private_value = private_value

    def utcoffset(self, value: datetime | None) -> timedelta:
        self.calls += 1
        if self.fail_after is not None and self.calls > self.fail_after:
            raise RuntimeError(self.private_value)
        return timedelta(0)

    def dst(self, value: datetime | None) -> timedelta:
        return timedelta(0)

    def tzname(self, value: datetime | None) -> str:
        return "mutable-utc"


class _PrivateBaseFailure(BaseException):
    pass


class _BaseFailureTimezone(tzinfo):
    def __init__(self, failure: BaseException) -> None:
        self.failure = failure

    def utcoffset(self, value: datetime | None) -> timedelta:
        raise self.failure

    def dst(self, value: datetime | None) -> timedelta:
        return timedelta(0)


def _run_document(started_at: datetime, ended_at: datetime | None = None) -> dict[str, object]:
    return {
        "run_id": "run-1",
        "run_type": "collector.run",
        "status": "success",
        "started_at": started_at,
        "ended_at": started_at if ended_at is None else ended_at,
        "duration_ms": 0,
    }


def test_non_pydantic_validator_exceptions_are_normalized_without_graphs() -> None:
    private_value = secrets.token_urlsafe(32)
    hostile_time = datetime(2026, 7, 21, 15, 0, tzinfo=_HostileTimezone(private_value))

    with pytest.raises(ValidationError) as captured:
        RunDataV1(
            run_id="run-1",
            run_type="collector.run",
            status="success",
            started_at=hostile_time,
            ended_at=hostile_time,
            duration_ms=0,
        )

    _assert_value_safe(
        captured.value,
        private_values=(private_value,),
        error_type=RECORD_VALIDATION_ERROR_TYPE,
        message=RECORD_VALIDATION_ERROR_MESSAGE,
    )


@pytest.mark.parametrize(
    "failure_type",
    [KeyboardInterrupt, SystemExit, _PrivateBaseFailure],
)
def test_base_exceptions_from_untrusted_validation_callbacks_are_value_safe(
    failure_type: type[BaseException],
) -> None:
    private_value = secrets.token_urlsafe(32)

    def document() -> dict[str, object]:
        failure = failure_type(private_value)
        hostile_time = datetime(2026, 7, 21, 15, 0, tzinfo=_BaseFailureTimezone(failure))
        return _run_document(hostile_time)

    operations = (
        lambda: RunDataV1(**document()),
        lambda: RunDataV1.model_validate(document()),
        lambda: TypeAdapter(RunDataV1).validate_python(document()),
        lambda: RunDataV1.__pydantic_validator__.validate_python(document()),
    )

    for operation in operations:
        with pytest.raises(ValidationError) as captured:
            operation()
        _assert_value_safe(
            captured.value,
            private_values=(private_value,),
            error_type=RECORD_VALIDATION_ERROR_TYPE,
            message=RECORD_VALIDATION_ERROR_MESSAGE,
        )


@pytest.mark.parametrize("failure_type", [KeyboardInterrupt, SystemExit, _PrivateBaseFailure])
def test_canonical_and_content_hash_boundaries_contain_timezone_base_exceptions(
    failure_type: type[BaseException],
) -> None:
    private_value = secrets.token_urlsafe(32)

    def hostile_time() -> datetime:
        return datetime(
            2026,
            7,
            21,
            tzinfo=_BaseFailureTimezone(failure_type(private_value)),
        )

    with pytest.raises(CanonicalizationError) as canonical_failure:
        canonical_json_bytes({"when": hostile_time()})
    with pytest.raises(identity_module.IdentityError) as identity_failure:
        identity_module.derive_content_hash({"when": hostile_time()})

    for failure in (canonical_failure.value, identity_failure.value):
        surfaces = (
            str(failure),
            repr(failure),
            repr(failure.args),
            "".join(traceback.format_exception(failure)),
        )
        assert all(private_value not in surface for surface in surfaces)


def test_validation_runs_once_and_commits_self_instance_atomically() -> None:
    started_tz = _CountingUtcTimezone(fail_after=1, private_value="started-private")
    ended_tz = _CountingUtcTimezone(fail_after=1, private_value="ended-private")
    started_at = datetime(2026, 7, 21, 15, 0, tzinfo=started_tz)
    ended_at = datetime(2026, 7, 21, 15, 1, tzinfo=ended_tz)

    accepted = RunDataV1.model_validate(_run_document(started_at, ended_at))

    assert started_tz.calls == 1
    assert ended_tz.calls == 1
    assert type(accepted.started_at) is datetime
    assert accepted.started_at.tzinfo is UTC
    assert type(accepted.ended_at) is datetime
    assert accepted.ended_at.tzinfo is UTC

    private_value = secrets.token_urlsafe(32)
    for operation_name in ("proxy", "init"):
        target = object.__new__(RunDataV1)
        valid_time = datetime(2026, 7, 21, 15, 0, tzinfo=UTC)
        hostile_time = datetime(2026, 7, 21, 15, 1, tzinfo=_HostileTimezone(private_value))
        document = _run_document(valid_time, hostile_time)

        with pytest.raises(ValidationError) as captured:
            if operation_name == "proxy":
                RunDataV1.__pydantic_validator__.validate_python(
                    document,
                    self_instance=target,
                )
            else:
                target.__init__(**document)

        _assert_value_safe(
            captured.value,
            private_values=(private_value,),
            error_type=RECORD_VALIDATION_ERROR_TYPE,
            message=RECORD_VALIDATION_ERROR_MESSAGE,
        )
        assert target.__dict__ == {}
        for name in (
            "__pydantic_fields_set__",
            "__pydantic_extra__",
            "__pydantic_private__",
        ):
            assert not hasattr(target, name)


class _HostileSelfInstance:
    def __init__(self, failure: BaseException) -> None:
        self.failure = failure

    @property
    def __pydantic_fields_set__(self) -> object:
        raise self.failure


@pytest.mark.parametrize("failure_type", [RuntimeError, KeyboardInterrupt, _PrivateBaseFailure])
@pytest.mark.parametrize("mode", ["python", "json"])
def test_wrong_type_self_instances_are_rejected_without_descriptor_access(
    failure_type: type[BaseException],
    mode: str,
) -> None:
    private_value = secrets.token_urlsafe(32)
    hostile = _HostileSelfInstance(failure_type(private_value))
    document = {"type": "operator", "id": "operator-1"}

    with pytest.raises(ValidationError) as captured:
        if mode == "python":
            ActorReferenceV1.__pydantic_validator__.validate_python(
                document,
                self_instance=hostile,
            )
        else:
            ActorReferenceV1.__pydantic_validator__.validate_json(
                json.dumps(document),
                self_instance=hostile,
            )

    _assert_value_safe(
        captured.value,
        private_values=(private_value,),
        error_type=RECORD_VALIDATION_ERROR_TYPE,
        message=RECORD_VALIDATION_ERROR_MESSAGE,
    )


def test_atomic_commit_detaches_optional_pydantic_state_and_rejects_wrong_results() -> None:
    validator = ActorReferenceV1.__pydantic_validator__
    target = object.__new__(ActorReferenceV1)
    validated = ActorReferenceV1(type="operator", id="operator-1")
    extra = {"safe": "extra"}
    private = {"_safe": "private"}
    object.__setattr__(validated, "__pydantic_extra__", extra)
    object.__setattr__(validated, "__pydantic_private__", private)

    committed = validator._commit_self_instance(target, validated)

    assert committed is target
    assert target.__pydantic_extra__ == extra
    assert target.__pydantic_extra__ is not extra
    assert target.__pydantic_private__ == private
    assert target.__pydantic_private__ is not private

    with pytest.raises(TypeError, match="unexpected model type"):
        validator._commit_self_instance(object.__new__(ActorReferenceV1), object())


def _public_models(module: ModuleType) -> set[type[BaseModel]]:
    return {
        value
        for name, value in vars(module).items()
        if not name.startswith("_")
        and isinstance(value, type)
        and issubclass(value, BaseModel)
        and value.__module__ == module.__name__
    }


def test_every_public_domain_model_inherits_the_value_safe_guard() -> None:
    identity_models = _public_models(identity_module)
    record_models = _public_models(record_module)

    assert len(identity_models) == 5
    assert len(record_models) == 23
    assert all(issubclass(model, ValueSafeIdentityModel) for model in identity_models)
    assert all(issubclass(model, ValueSafeRecordModel) for model in record_models)


def test_redaction_precedes_draft_finalization_and_canonical_wire_output() -> None:
    private_value = secrets.token_urlsafe(32)
    redacted = LayeredRedactor(
        Pseudonymizer(bytes(range(32))),
        known_secrets=(private_value,),
    ).redact(
        f"failure at /workspace/{private_value}/app.py, from "
        f"file://private-host/share/{private_value}.json"
    )
    document = _record_document()
    document["data"] = {
        "type": "event",
        "category": "availability",
        "status": "failed",
        "message": redacted.value,
    }

    record = finalize_record(
        RecordDraftV1.model_validate(document),
        installation_id="mh_in1_00000000000040008000000000000000",
    )
    wire = canonical_json_bytes(record.model_dump(mode="python", exclude_none=True))

    assert private_value.encode() not in wire
    assert b"private-host" not in wire
    assert b"file:" not in wire.lower()
    assert b"local-path:mh_ps1_e1_path_" in wire
