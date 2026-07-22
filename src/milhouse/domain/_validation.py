"""Value-safe Pydantic boundaries for public Milhouse domain models."""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from types import UnionType
from typing import (
    Annotated,
    Any,
    ClassVar,
    Literal,
    NoReturn,
    Self,
    TypeVar,
    Union,
    cast,
    get_args,
    get_origin,
)

from pydantic import BaseModel, GetCoreSchemaHandler, GetJsonSchemaHandler, ValidationError
from pydantic.config import ExtraValues
from pydantic.json_schema import JsonSchemaValue
from pydantic_core import CoreSchema, PydanticCustomError, SchemaValidator, core_schema

IDENTITY_VALIDATION_ERROR_TYPE = "milhouse_identity_invalid"
IDENTITY_VALIDATION_ERROR_MESSAGE = "identity input is invalid"
RECORD_VALIDATION_ERROR_TYPE = "milhouse_record_invalid"
RECORD_VALIDATION_ERROR_MESSAGE = "record input is invalid"

_VALUE_SAFE_SCHEMA_MARKER = "milhouse_value_safe_validation"
_ResultT = TypeVar("_ResultT")


def _safe_validation_error(*, title: str, error_type: str, message: str) -> ValidationError:
    return ValidationError.from_exception_data(
        title,
        [
            {
                "type": PydanticCustomError(error_type, message),
                "loc": (),
                "input": None,
            }
        ],
        hide_input=True,
    )


def _safe_operation(
    operation: Callable[[], _ResultT],
    *,
    title: str,
    error_type: str,
    message: str,
) -> _ResultT:
    failed = False
    result: _ResultT | None = None
    try:
        result = operation()
    except BaseException:
        failed = True
    if failed:
        safe_error = _safe_validation_error(
            title=title,
            error_type=error_type,
            message=message,
        )
        raise safe_error from None
    return cast(_ResultT, result)


def _dump_exact_model_instance(value: Any, *, expected_type: Any) -> Any:
    if type(value) is not expected_type:
        return value
    instance_values = object.__getattribute__(value, "__dict__")
    fields = expected_type.model_fields
    for field_name, field_value in instance_values.items():
        if field_name in fields:
            _normalize_annotated_value(field_value, fields[field_name].annotation)
    return BaseModel.model_dump(
        value,
        mode="python",
        round_trip=True,
        warnings=False,
    )


def _exact_model_annotation_type(annotation: Any) -> type[BaseModel] | None:
    while get_origin(annotation) is Annotated:
        annotation = get_args(annotation)[0]
    if isinstance(annotation, type) and issubclass(annotation, BaseModel):
        return annotation
    return None


def _normalize_annotated_value(value: Any, annotation: Any) -> Any:
    """Normalize only model instances explicitly named by a field annotation."""

    while get_origin(annotation) is Annotated:
        annotation = get_args(annotation)[0]

    origin = get_origin(annotation)
    if origin in (Union, UnionType):
        expected_model_types = tuple(
            model_type
            for option in get_args(annotation)
            if (model_type := _exact_model_annotation_type(option)) is not None
        )
        if isinstance(value, BaseModel) and expected_model_types:
            concrete_type = type(value)
            if concrete_type not in expected_model_types:
                raise TypeError("nested model has an unexpected concrete type")
            return _dump_exact_model_instance(value, expected_type=concrete_type)
        for option in get_args(annotation):
            normalized = _normalize_annotated_value(value, option)
            if normalized is not value:
                return normalized
        return value

    expected_model_type = _exact_model_annotation_type(annotation)
    if expected_model_type is not None:
        if isinstance(value, BaseModel) and type(value) is not expected_model_type:
            raise TypeError("nested model has an unexpected concrete type")
        return _dump_exact_model_instance(value, expected_type=expected_model_type)

    arguments = get_args(annotation)
    if origin is list and len(arguments) == 1 and isinstance(value, list):
        return [_normalize_annotated_value(item, arguments[0]) for item in value]
    if origin is dict and len(arguments) == 2 and isinstance(value, dict):
        return {key: _normalize_annotated_value(item, arguments[1]) for key, item in value.items()}
    return value


def _normalize_model_instance(value: Any, *, source_type: Any) -> Any:
    if isinstance(value, BaseModel):
        if type(value) is not source_type:
            raise TypeError("model has an unexpected concrete type")
        return _dump_exact_model_instance(value, expected_type=source_type)
    if (
        isinstance(value, dict)
        and isinstance(source_type, type)
        and issubclass(source_type, BaseModel)
    ):
        fields = source_type.model_fields
        return {
            key: _normalize_annotated_value(item, fields[key].annotation) if key in fields else item
            for key, item in value.items()
        }
    return value


def _value_safe_schema(
    source_type: Any,
    handler: GetCoreSchemaHandler,
    *,
    title: str,
    error_type: str,
    message: str,
) -> CoreSchema:
    schema = handler(source_type)
    strict_validator = SchemaValidator(schema)

    def validate_without_value_bearing_errors(
        value: Any,
        _validator: core_schema.ValidatorFunctionWrapHandler,
        info: core_schema.ValidationInfo,
    ) -> Any:
        def validate() -> Any:
            if info.mode == "json":
                # A nested model default is created after JSON decoding, so its own wrapper still
                # observes JSON mode even though the value is now an exact trusted model instance.
                # Revalidate that detached instance through the strict Python path; attempting to
                # JSON-encode it would reject a valid omitted field before the parent model exists.
                if type(value) is source_type:
                    candidate = _normalize_model_instance(value, source_type=source_type)
                    return strict_validator.validate_python(
                        candidate,
                        strict=True,
                        extra="forbid",
                        from_attributes=False,
                        context=info.context,
                        allow_partial=False,
                    )
                encoded = json.dumps(
                    value,
                    allow_nan=False,
                    ensure_ascii=False,
                    separators=(",", ":"),
                ).encode("utf-8")
                return strict_validator.validate_json(
                    encoded,
                    strict=True,
                    extra="forbid",
                    context=info.context,
                    allow_partial=False,
                )

            # Prevalidate independently so caller overrides cannot weaken strict types,
            # extra-field rejection, attribute extraction, or instance revalidation.
            candidate = _normalize_model_instance(value, source_type=source_type)
            return strict_validator.validate_python(
                candidate,
                strict=True,
                extra="forbid",
                from_attributes=False,
                context=info.context,
                allow_partial=False,
            )

        return _safe_operation(
            validate,
            title=title,
            error_type=error_type,
            message=message,
        )

    return core_schema.with_info_wrap_validator_function(
        validate_without_value_bearing_errors,
        schema,
        metadata={_VALUE_SAFE_SCHEMA_MARKER: True},
    )


def _strip_value_safe_wrappers(value: Any) -> Any:
    if isinstance(value, dict):
        metadata = value.get("metadata")
        if (
            value.get("type") == "function-wrap"
            and isinstance(metadata, dict)
            and metadata.get(_VALUE_SAFE_SCHEMA_MARKER) is True
        ):
            return _strip_value_safe_wrappers(value["schema"])
        return {key: _strip_value_safe_wrappers(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_strip_value_safe_wrappers(item) for item in value]
    return value


def _unwrapped_json_schema(
    schema: CoreSchema,
    handler: GetJsonSchemaHandler,
) -> JsonSchemaValue:
    """Keep validation-only guards out of the public domain JSON schemas."""

    return handler(cast(CoreSchema, _strip_value_safe_wrappers(schema)))


class _ValueSafeValidatorProxy:
    """Enforce fixed validation semantics at Pydantic's outer parser boundary."""

    __slots__ = ("__validator", "_error_type", "_message", "_model_type", "_title")

    def __init__(
        self,
        validator: Any,
        *,
        model_type: type[BaseModel],
        title: str,
        error_type: str,
        message: str,
    ) -> None:
        self.__validator = validator
        self._model_type = model_type
        self._title = title
        self._error_type = error_type
        self._message = message

    def _call(self, operation: Callable[[], _ResultT]) -> _ResultT:
        return _safe_operation(
            operation,
            title=self._title,
            error_type=self._error_type,
            message=self._message,
        )

    def _validated_self_instance(self, value: Any | None) -> Any | None:
        if value is None:
            return None
        if type(value) is not self._model_type:
            raise TypeError("self_instance has an unexpected model type")
        try:
            object.__getattribute__(value, "__pydantic_fields_set__")
        except (AttributeError, TypeError):
            has_fields_set = False
        else:
            has_fields_set = True
        try:
            instance_values = object.__getattribute__(value, "__dict__")
        except (AttributeError, TypeError):
            instance_values = None
        if not has_fields_set and instance_values == {}:
            return value
        safe_error = _safe_validation_error(
            title=self._title,
            error_type=self._error_type,
            message=self._message,
        )
        raise safe_error from None

    def _commit_self_instance(self, target: Any | None, validated: Any) -> Any:
        if target is None:
            return validated
        if type(validated) is not self._model_type:
            raise TypeError("validator returned an unexpected model type")

        values = dict(object.__getattribute__(validated, "__dict__"))
        fields_set = set(object.__getattribute__(validated, "__pydantic_fields_set__"))
        extra = object.__getattribute__(validated, "__pydantic_extra__")
        if isinstance(extra, dict):
            extra = dict(extra)
        private = object.__getattribute__(validated, "__pydantic_private__")
        if isinstance(private, dict):
            private = dict(private)

        try:
            object.__setattr__(target, "__pydantic_fields_set__", fields_set)
            object.__setattr__(target, "__pydantic_extra__", extra)
            object.__setattr__(target, "__pydantic_private__", private)
            object.__setattr__(target, "__dict__", values)
        except BaseException:  # pragma: no cover - pristine exact BaseModel storage is writable
            object.__setattr__(target, "__dict__", {})
            for name in (
                "__pydantic_fields_set__",
                "__pydantic_extra__",
                "__pydantic_private__",
            ):
                try:
                    object.__delattr__(target, name)
                except AttributeError:
                    pass
            raise
        return target

    @property
    def title(self) -> str:
        return str(self.__validator.title)

    def validate_python(
        self,
        value: Any,
        *,
        strict: bool | None = None,
        extra: ExtraValues | None = None,
        from_attributes: bool | None = None,
        context: Any | None = None,
        self_instance: Any | None = None,
        allow_partial: bool | Literal["off", "on", "trailing-strings"] = False,
        by_alias: bool | None = None,
        by_name: bool | None = None,
    ) -> Any:
        def validate() -> Any:
            target = self._validated_self_instance(self_instance)
            validated = self.__validator.validate_python(
                value,
                strict=True,
                extra="forbid",
                from_attributes=False,
                context=context,
                self_instance=None,
                allow_partial=False,
                by_alias=by_alias,
                by_name=by_name,
            )
            return self._commit_self_instance(target, validated)

        return self._call(validate)

    def validate_json(
        self,
        value: str | bytes | bytearray,
        *,
        strict: bool | None = None,
        extra: ExtraValues | None = None,
        context: Any | None = None,
        self_instance: Any | None = None,
        allow_partial: bool | Literal["off", "on", "trailing-strings"] = False,
        by_alias: bool | None = None,
        by_name: bool | None = None,
    ) -> Any:
        def validate() -> Any:
            target = self._validated_self_instance(self_instance)
            validated = self.__validator.validate_json(
                value,
                strict=True,
                extra="forbid",
                context=context,
                self_instance=None,
                allow_partial=False,
                by_alias=by_alias,
                by_name=by_name,
            )
            return self._commit_self_instance(target, validated)

        return self._call(validate)

    def validate_strings(
        self,
        value: Any,
        *,
        strict: bool | None = None,
        extra: ExtraValues | None = None,
        context: Any | None = None,
        allow_partial: bool | Literal["off", "on", "trailing-strings"] = False,
        by_alias: bool | None = None,
        by_name: bool | None = None,
    ) -> Any:
        return self._call(
            lambda: self.__validator.validate_strings(
                value,
                strict=True,
                extra="forbid",
                context=context,
                allow_partial=False,
                by_alias=by_alias,
                by_name=by_name,
            )
        )

    def validate_assignment(
        self,
        instance: Any,
        field_name: str,
        field_value: Any,
        *,
        strict: bool | None = None,
        extra: ExtraValues | None = None,
        from_attributes: bool | None = None,
        context: Any | None = None,
        by_alias: bool | None = None,
        by_name: bool | None = None,
    ) -> Any:
        safe_error = _safe_validation_error(
            title=self._title,
            error_type=self._error_type,
            message=self._message,
        )
        raise safe_error from None

    def isinstance_python(
        self,
        value: Any,
        *,
        strict: bool | None = None,
        extra: ExtraValues | None = None,
        from_attributes: bool | None = None,
        context: Any | None = None,
        self_instance: Any | None = None,
        by_alias: bool | None = None,
        by_name: bool | None = None,
    ) -> bool:
        try:
            return bool(
                self.__validator.isinstance_python(
                    value,
                    strict=True,
                    extra="forbid",
                    from_attributes=False,
                    context=context,
                    self_instance=None,
                    by_alias=by_alias,
                    by_name=by_name,
                )
            )
        except Exception:
            return False

    def get_default_value(
        self,
        *,
        strict: bool | None = None,
        context: Any | None = None,
    ) -> Any:
        return self._call(lambda: self.__validator.get_default_value(strict=True, context=context))


class _ValueSafeModel(BaseModel):
    _validation_error_title: ClassVar[str] = "MilhouseModelV1"
    _validation_error_type: ClassVar[str] = "milhouse_model_invalid"
    _validation_error_message: ClassVar[str] = "model input is invalid"

    def _raise_value_safe_mutation_error(self) -> NoReturn:
        safe_error = _safe_validation_error(
            title=type(self)._validation_error_title,
            error_type=type(self)._validation_error_type,
            message=type(self)._validation_error_message,
        )
        raise safe_error from None

    def __setattr__(self, name: str, value: Any) -> NoReturn:
        """Reject public and underscore mutation without retaining rejected values."""

        self._raise_value_safe_mutation_error()

    def __delattr__(self, name: str) -> NoReturn:
        """Reject deletion through the same fixed, value-free boundary."""

        self._raise_value_safe_mutation_error()

    def __getstate__(self) -> NoReturn:
        """Disable pickle state export for public domain models."""

        self._raise_value_safe_mutation_error()

    def __setstate__(self, state: Any) -> NoReturn:
        """Disable unchecked pickle state restoration for public domain models."""

        self._raise_value_safe_mutation_error()

    @classmethod
    def __get_pydantic_core_schema__(
        cls,
        source_type: Any,
        handler: GetCoreSchemaHandler,
    ) -> CoreSchema:
        return _value_safe_schema(
            source_type,
            handler,
            title=cls._validation_error_title,
            error_type=cls._validation_error_type,
            message=cls._validation_error_message,
        )

    @classmethod
    def __get_pydantic_json_schema__(
        cls,
        schema: CoreSchema,
        handler: GetJsonSchemaHandler,
    ) -> JsonSchemaValue:
        return _unwrapped_json_schema(schema, handler)

    @classmethod
    def __pydantic_on_complete__(cls) -> None:
        super().__pydantic_on_complete__()
        cls._install_value_safe_validator()

    @classmethod
    def _install_value_safe_validator(cls) -> None:
        validator = cls.__dict__.get("__pydantic_validator__")
        if validator is None or isinstance(validator, _ValueSafeValidatorProxy):
            return
        cls.__pydantic_validator__ = cast(
            Any,
            _ValueSafeValidatorProxy(
                validator,
                model_type=cls,
                title=cls._validation_error_title,
                error_type=cls._validation_error_type,
                message=cls._validation_error_message,
            ),
        )

    @classmethod
    def model_rebuild(
        cls,
        *,
        force: bool = False,
        raise_errors: bool = True,
        _parent_namespace_depth: int = 2,
        _types_namespace: Mapping[str, object] | None = None,
    ) -> bool | None:
        rebuilt = super().model_rebuild(
            force=force,
            raise_errors=raise_errors,
            _parent_namespace_depth=_parent_namespace_depth,
            _types_namespace=_types_namespace,
        )
        if cls.__pydantic_complete__:  # pragma: no branch - supported models rebuild completely
            cls._install_value_safe_validator()
        return rebuilt

    @classmethod
    def model_construct(cls, _fields_set: set[str] | None = None, **values: Any) -> Self:
        """Retain Pydantic's API name while refusing unchecked construction."""

        return cls.model_validate(values)

    def model_copy(
        self,
        *,
        update: Mapping[str, Any] | None = None,
        deep: bool = False,
    ) -> Self:
        """Return a revalidated copy while rejecting unchecked field updates."""

        if update is not None:
            safe_error = _safe_validation_error(
                title=type(self)._validation_error_title,
                error_type=type(self)._validation_error_type,
                message=type(self)._validation_error_message,
            )
            raise safe_error from None

        def copy_and_validate() -> Any:
            values = BaseModel.model_dump(
                self,
                mode="python",
                round_trip=True,
                warnings=False,
            )
            return type(self).model_validate(values)

        return cast(
            Self,
            _safe_operation(
                copy_and_validate,
                title=type(self)._validation_error_title,
                error_type=type(self)._validation_error_type,
                message=type(self)._validation_error_message,
            ),
        )

    def copy(
        self,
        *,
        include: Any = None,
        exclude: Any = None,
        update: dict[str, Any] | None = None,
        deep: bool = False,
    ) -> Self:
        """Route the legacy copy API through validation and reject partial models."""

        if include is not None or exclude is not None:
            safe_error = _safe_validation_error(
                title=type(self)._validation_error_title,
                error_type=type(self)._validation_error_type,
                message=type(self)._validation_error_message,
            )
            raise safe_error from None
        return self.model_copy(update=update, deep=deep)

    @classmethod
    def parse_raw(
        cls,
        b: str | bytes,
        *,
        content_type: str | None = None,
        encoding: str = "utf8",
        proto: Any = None,
        allow_pickle: bool = False,
    ) -> Self:
        """Treat the legacy raw parser as JSON only; never dispatch pickle parsers."""

        return cls.model_validate_json(b)

    @classmethod
    def parse_file(
        cls,
        path: Any,
        *,
        content_type: str | None = None,
        encoding: str = "utf8",
        proto: Any = None,
        allow_pickle: bool = False,
    ) -> Self:
        """Disable Pydantic's legacy arbitrary-path parser for domain models."""

        safe_error = _safe_validation_error(
            title=cls._validation_error_title,
            error_type=cls._validation_error_type,
            message=cls._validation_error_message,
        )
        raise safe_error from None

    @classmethod
    def from_orm(cls, obj: Any) -> Self:
        """Disable attribute extraction at the domain validation boundary."""

        safe_error = _safe_validation_error(
            title=cls._validation_error_title,
            error_type=cls._validation_error_type,
            message=cls._validation_error_message,
        )
        raise safe_error from None


class ValueSafeIdentityModel(_ValueSafeModel):
    """Base for identity models with fixed, rejected-value-free failures."""

    _validation_error_title = "MilhouseIdentityV1"
    _validation_error_type = IDENTITY_VALIDATION_ERROR_TYPE
    _validation_error_message = IDENTITY_VALIDATION_ERROR_MESSAGE


class ValueSafeRecordModel(_ValueSafeModel):
    """Base for record models with fixed, rejected-value-free failures."""

    _validation_error_title = "MilhouseRecordV1"
    _validation_error_type = RECORD_VALIDATION_ERROR_TYPE
    _validation_error_message = RECORD_VALIDATION_ERROR_MESSAGE


__all__ = [
    "IDENTITY_VALIDATION_ERROR_MESSAGE",
    "IDENTITY_VALIDATION_ERROR_TYPE",
    "RECORD_VALIDATION_ERROR_MESSAGE",
    "RECORD_VALIDATION_ERROR_TYPE",
    "ValueSafeIdentityModel",
    "ValueSafeRecordModel",
]
