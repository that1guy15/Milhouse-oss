"""Strict record identity projections and deterministic digest wires."""

from __future__ import annotations

import base64
import hashlib
import math
import re
from typing import Annotated, Literal, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from milhouse.core.canonical import (
    MAX_CANONICAL_INT,
    MIN_CANONICAL_INT,
    CanonicalizationError,
    canonical_json_bytes,
)
from milhouse.core.errors import MilhouseValueError
from milhouse.core.immutable import freeze_dict

MachineIdV1 = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_-]{0,63}$")]
MachineNameV1 = Annotated[
    str,
    StringConstraints(
        pattern=r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$",
        max_length=128,
    ),
]
Sha256HexV1 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
InstallationIdV1 = Annotated[
    str,
    StringConstraints(pattern=r"^mh_in1_[0-9a-f]{12}4[0-9a-f]{3}[89ab][0-9a-f]{15}$"),
]
ObservationNamespaceIdV1 = Annotated[
    str,
    StringConstraints(pattern=r"^mh_ns1_[0-9a-f]{12}4[0-9a-f]{3}[89ab][0-9a-f]{15}$"),
]
RedactionVersionV1 = Annotated[str, StringConstraints(pattern=r"^r[1-9][0-9]*-e[1-9][0-9]*$")]
RecordTypeV1 = Literal[
    "event",
    "metric",
    "span",
    "run",
    "alert",
    "incident",
    "feedback_item",
    "feedback_transition",
    "audit",
]
ScopeV1 = Literal["installation", "target"]
ObservationScalarV1 = bool | int | float | str

_RECORD_ID = re.compile(r"^mh_[a-z2-7]{51}[aq]$")
_DEDUPE_KEY = re.compile(r"^mh_d1_[a-z2-7]{51}[aq]$")
_RECORD_ID_DOMAIN = b"milhouse-record-id-v1\0"
_CONTENT_DOMAIN = b"milhouse-content-v1\0"
_DEDUPE_DOMAIN = b"milhouse-dedupe-v1\0"


def _contains_unsafe_identifier_characters(value: str) -> bool:
    return any(
        ord(character) < 0x20 or ord(character) == 0x7F or 0xD800 <= ord(character) <= 0xDFFF
        for character in value
    )


class IdentityError(MilhouseValueError):
    """Safe identity derivation or validation failure."""


class _StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        frozen=True,
        hide_input_in_errors=True,
        validate_default=True,
    )


class SourceIdentityV1(_StrictModel):
    id: MachineIdV1
    type: MachineNameV1
    observation_namespace_id: ObservationNamespaceIdV1
    source_generation_digest: Sha256HexV1


class DedupeSourceV1(_StrictModel):
    type: MachineNameV1
    id: MachineIdV1
    observation_namespace_id: ObservationNamespaceIdV1


class ObservationCoordinateV1(_StrictModel):
    kind: MachineNameV1
    parts: dict[MachineNameV1, ObservationScalarV1]

    @field_validator("parts")
    @classmethod
    def validate_parts(
        cls, value: dict[MachineNameV1, ObservationScalarV1]
    ) -> dict[MachineNameV1, ObservationScalarV1]:
        if not 1 <= len(value) <= 16:
            raise ValueError("MH_IDENTITY_OBSERVATION_PARTS: expected 1 through 16 parts")
        for part in value.values():
            if type(part) is int and not MIN_CANONICAL_INT <= part <= MAX_CANONICAL_INT:
                raise ValueError(
                    "MH_IDENTITY_OBSERVATION_INTEGER: integer part is outside signed 64-bit"
                )
            if type(part) is float:
                if not math.isfinite(part):
                    raise ValueError("MH_IDENTITY_OBSERVATION_FLOAT: float part must be finite")
                if part.is_integer() and not MIN_CANONICAL_INT <= int(part) <= MAX_CANONICAL_INT:
                    raise ValueError(
                        "MH_IDENTITY_OBSERVATION_FLOAT: integral float is outside signed 64-bit"
                    )
            if type(part) is str and _contains_unsafe_identifier_characters(part):
                raise ValueError(
                    "MH_IDENTITY_OBSERVATION_STRING: string part contains unsafe characters"
                )
            if type(part) is str and not 1 <= len(part.encode("utf-8")) <= 256:
                raise ValueError(
                    "MH_IDENTITY_OBSERVATION_STRING: string part exceeds its byte bound"
                )
        return freeze_dict(value)


class RecordIdentityV1(_StrictModel):
    identity_version: Literal[1] = 1
    installation_id: InstallationIdV1
    schema_version: Literal["1.0"] = "1.0"
    redaction_version: RedactionVersionV1
    source: SourceIdentityV1
    scope: ScopeV1
    target_id: MachineIdV1 | None = None
    record_type: RecordTypeV1
    name: MachineNameV1
    source_event_id: Annotated[str, Field(min_length=1, max_length=256)] | None = None
    source_entity_id: Annotated[str, Field(min_length=1, max_length=256)] | None = None
    observation: ObservationCoordinateV1

    @field_validator("source_event_id", "source_entity_id")
    @classmethod
    def validate_optional_opaque_id(cls, value: str | None) -> str | None:
        if value is not None and _contains_unsafe_identifier_characters(value):
            raise ValueError("MH_IDENTITY_OPAQUE_ID: identifier contains unsafe characters")
        if value is not None and len(value.encode("utf-8")) > 256:
            raise ValueError("MH_IDENTITY_OPAQUE_ID: identifier exceeds its UTF-8 byte bound")
        return value

    @model_validator(mode="after")
    def validate_scope(self) -> Self:
        if self.scope == "target" and self.target_id is None:
            raise ValueError("MH_IDENTITY_TARGET_REQUIRED: target scope requires target_id")
        if self.scope == "installation" and self.target_id is not None:
            raise ValueError("MH_IDENTITY_TARGET_FORBIDDEN: installation scope forbids target_id")
        return self


class RecordDedupeV1(_StrictModel):
    dedupe_version: Literal[1] = 1
    installation_id: InstallationIdV1
    source: DedupeSourceV1
    scope: ScopeV1
    target_id: MachineIdV1 | None = None
    record_type: RecordTypeV1
    name: MachineNameV1
    observation: ObservationCoordinateV1

    @model_validator(mode="after")
    def validate_scope(self) -> Self:
        if self.scope == "target" and self.target_id is None:
            raise ValueError("MH_DEDUPE_TARGET_REQUIRED: target scope requires target_id")
        if self.scope == "installation" and self.target_id is not None:
            raise ValueError("MH_DEDUPE_TARGET_FORBIDDEN: installation scope forbids target_id")
        return self

    @classmethod
    def from_identity(cls, identity: RecordIdentityV1) -> Self:
        return cls(
            installation_id=identity.installation_id,
            source=DedupeSourceV1(
                type=identity.source.type,
                id=identity.source.id,
                observation_namespace_id=identity.source.observation_namespace_id,
            ),
            scope=identity.scope,
            target_id=identity.target_id,
            record_type=identity.record_type,
            name=identity.name,
            observation=identity.observation,
        )


def _domain_digest(domain: bytes, projection: object) -> bytes:
    if not domain.endswith(b"\0") or any(byte > 0x7F for byte in domain):
        raise ValueError("digest domains must be NUL-terminated ASCII")
    try:
        canonical = canonical_json_bytes(projection)
    except CanonicalizationError as error:
        raise IdentityError("MH_IDENTITY_PROJECTION", "projection is not canonical") from error
    return hashlib.sha256(domain + canonical).digest()


def _base32_digest(digest: bytes) -> str:
    return base64.b32encode(digest).decode("ascii").lower().rstrip("=")


def derive_record_id(identity: RecordIdentityV1) -> str:
    projection = identity.model_dump(mode="python", exclude_none=True)
    return f"mh_{_base32_digest(_domain_digest(_RECORD_ID_DOMAIN, projection))}"


def derive_content_hash(content_projection: dict[str, object]) -> str:
    if type(content_projection) is not dict:
        raise IdentityError("MH_CONTENT_PROJECTION", "content projection must be an object")
    return _domain_digest(_CONTENT_DOMAIN, content_projection).hex()


def derive_dedupe_key(dedupe: RecordDedupeV1) -> str:
    projection = dedupe.model_dump(mode="python", exclude_none=True)
    return f"mh_d1_{_base32_digest(_domain_digest(_DEDUPE_DOMAIN, projection))}"


def _validate_digest_token(value: str, *, prefix: str, pattern: re.Pattern[str]) -> str:
    if type(value) is not str or pattern.fullmatch(value) is None:
        raise IdentityError("MH_IDENTITY_TOKEN", "digest token has an invalid wire format")
    encoded = value[len(prefix) :]
    try:
        decoded = base64.b32decode(f"{encoded.upper()}====", casefold=False)
    except ValueError as error:
        raise IdentityError("MH_IDENTITY_TOKEN", "digest token is not canonical base32") from error
    if len(decoded) != 32 or _base32_digest(decoded) != encoded:
        raise IdentityError("MH_IDENTITY_TOKEN", "digest token has noncanonical pad bits")
    return value


def validate_record_id(value: str) -> str:
    return _validate_digest_token(value, prefix="mh_", pattern=_RECORD_ID)


def validate_dedupe_key(value: str) -> str:
    return _validate_digest_token(value, prefix="mh_d1_", pattern=_DEDUPE_KEY)
