from __future__ import annotations

from collections.abc import Callable

import pytest

from milhouse.config import ConfigError
from milhouse.core import CanonicalizationError, TimeError
from milhouse.core.errors import (
    UNEXPECTED_ERROR_CODE,
    MilhouseError,
    MilhouseValueError,
    NormalizedError,
    normalize_error,
)
from milhouse.domain.identity import IdentityError
from milhouse.domain.records import RecordError
from milhouse.privacy import PrivacyError
from milhouse.resources import ResourceManifestError


@pytest.mark.parametrize(
    ("factory", "builtin_type", "code", "rendered"),
    [
        (
            lambda: ConfigError("config.test.failure", "configuration failed"),
            Exception,
            "config.test.failure",
            "config.test.failure: configuration failed",
        ),
        (
            lambda: CanonicalizationError("MH_CANONICAL_TEST", "canonicalization failed"),
            ValueError,
            "MH_CANONICAL_TEST",
            "MH_CANONICAL_TEST: canonicalization failed",
        ),
        (
            lambda: TimeError("MH_TIME_TEST", "time failed"),
            ValueError,
            "MH_TIME_TEST",
            "MH_TIME_TEST: time failed",
        ),
        (
            lambda: IdentityError("MH_IDENTITY_TEST", "identity failed"),
            ValueError,
            "MH_IDENTITY_TEST",
            "MH_IDENTITY_TEST: identity failed",
        ),
        (
            lambda: RecordError("MH_RECORD_TEST", "record failed"),
            ValueError,
            "MH_RECORD_TEST",
            "MH_RECORD_TEST: record failed",
        ),
        (
            lambda: PrivacyError("MH_PRIVACY_TEST", "privacy failed"),
            ValueError,
            "MH_PRIVACY_TEST",
            "MH_PRIVACY_TEST: privacy failed",
        ),
        (
            lambda: ResourceManifestError("resource failed"),
            ValueError,
            "MH_RESOURCE_MANIFEST",
            "resource failed",
        ),
    ],
)
def test_product_errors_share_stable_fields_without_losing_compatibility(
    factory: Callable[[], MilhouseError],
    builtin_type: type[BaseException],
    code: str,
    rendered: str,
) -> None:
    error = factory()

    assert isinstance(error, MilhouseError)
    assert isinstance(error, builtin_type)
    assert error.code == code
    assert error.message in rendered
    assert str(error) == rendered
    assert code in repr(error)


def test_value_error_base_preserves_builtin_catch_behavior() -> None:
    error = MilhouseValueError("MH_TEST_FAILURE", "test failure")

    assert isinstance(error, ValueError)
    assert error.args == ("MH_TEST_FAILURE: test failure",)


def test_stable_error_properties_are_read_only() -> None:
    error = ConfigError("config.test.failure", "configuration failed")

    with pytest.raises(AttributeError):
        error.code = "config.changed.failure"  # type: ignore[misc]
    with pytest.raises(AttributeError):
        error.message = "changed"  # type: ignore[misc]


@pytest.mark.parametrize(
    "code",
    [
        None,
        "",
        "lower_without_a_namespace",
        "MH-bad-code",
        "config.BAD",
        "x" * 129,
        "config.test.\ud800",
    ],
)
def test_stable_error_rejects_invalid_codes_without_echoing_them(code: object) -> None:
    with pytest.raises(ValueError) as captured:
        MilhouseError(code, "safe message")  # type: ignore[arg-type]

    assert str(captured.value) == "stable error code is invalid"


@pytest.mark.parametrize(
    "message",
    [None, "", "line one\nline two", "control\x7f", "\ud800", "x" * 2_049],
)
def test_stable_error_rejects_unsafe_messages_without_echoing_them(message: object) -> None:
    with pytest.raises(ValueError) as captured:
        MilhouseError("MH_TEST_FAILURE", message)  # type: ignore[arg-type]

    assert str(captured.value) == "stable error message is invalid"
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None


def test_normalize_error_preserves_only_known_code() -> None:
    runtime_canary = "runtime-secret-message-4c3d8d"
    error = ConfigError("config.test.failure", runtime_canary)

    normalized = normalize_error(error)

    assert normalized.code == "config.test.failure"
    assert normalized.expected is True
    assert runtime_canary not in repr(normalized)


def test_normalize_unknown_error_never_renders_or_traverses_it() -> None:
    runtime_canary = "runtime-secret-graph-ecbbca"

    def hostile_render(_error: BaseException) -> str:
        raise AssertionError("unknown exception rendering is forbidden")

    hostile_type = type(
        f"RuntimeCanary_{runtime_canary}",
        (Exception,),
        {"__str__": hostile_render, "__repr__": hostile_render},
    )
    error = hostile_type(runtime_canary)
    error.__cause__ = RuntimeError(runtime_canary)
    error.__context__ = ValueError(runtime_canary)
    error.add_note(runtime_canary)

    normalized = normalize_error(error)

    assert normalized.code == UNEXPECTED_ERROR_CODE
    assert normalized.expected is False
    assert runtime_canary not in repr(normalized)


def test_normalize_tampered_stable_error_fails_closed() -> None:
    error = ConfigError("config.test.failure", "configuration failed")
    object.__setattr__(error, "_code", "runtime-secret-invalid-code")

    normalized = normalize_error(error)

    assert normalized.code == UNEXPECTED_ERROR_CODE
    assert normalized.expected is False


def test_unknown_normalized_errors_do_not_share_mutable_state() -> None:
    first = normalize_error(RuntimeError("runtime detail"))
    object.__setattr__(first, "code", "MH_TAMPERED")

    second = normalize_error(RuntimeError("another runtime detail"))

    assert second.code == UNEXPECTED_ERROR_CODE
    assert second.expected is False


def test_normalized_error_can_only_be_created_by_the_normalizer() -> None:
    with pytest.raises(TypeError):
        NormalizedError()
    with pytest.raises(TypeError):
        NormalizedError(code="MH_TEST_FAILURE", expected=True)  # type: ignore[call-arg]


@pytest.mark.parametrize(
    ("code", "expected"),
    [("bad-code", True), ("MH_TEST_FAILURE", 1)],
)
def test_normalized_error_validates_its_safe_fields(code: str, expected: object) -> None:
    with pytest.raises(ValueError):
        NormalizedError._create(code=code, expected=expected)  # type: ignore[arg-type]
