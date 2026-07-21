import re
from dataclasses import asdict

import pytest

from milhouse.privacy import PrivacyError, Pseudonymizer

KEY = bytes(range(32))


def test_pseudonyms_are_deterministic_normalized_and_domain_separated() -> None:
    pseudonymizer = Pseudonymizer(KEY, epoch=3)

    composed = pseudonymizer.pseudonymize("email", "café@example.test\r\n")
    decomposed = pseudonymizer.pseudonymize("email", "café@example.test\n")
    fingerprint = pseudonymizer.fingerprint("email", "café@example.test\n")

    assert composed == decomposed
    assert re.fullmatch(r"mh_ps1_e3_email_[a-z2-7]{26}", composed)
    assert re.fullmatch(r"mh_fp1_e3_email_[a-z2-7]{51}[aq]", fingerprint)
    assert composed not in fingerprint
    assert "example.test" not in composed
    assert pseudonymizer.key_id == "mh_pk1_23162f1e256b1d24"


def test_pseudonyms_change_across_keys_epochs_kinds_and_domains() -> None:
    value = "synthetic-identifier"
    first = Pseudonymizer(KEY, epoch=1)
    values = {
        first.pseudonymize("email", value),
        first.pseudonymize("path", value),
        first.fingerprint("email", value),
        Pseudonymizer(KEY, epoch=2).pseudonymize("email", value),
        Pseudonymizer(bytes(reversed(KEY)), epoch=1).pseudonymize("email", value),
    }

    assert len(values) == 5


def test_pseudonymizer_repr_never_contains_key_material() -> None:
    pseudonymizer = Pseudonymizer(b"S" * 32)

    assert "SSSS" not in repr(pseudonymizer)
    assert "_key" not in repr(pseudonymizer)
    assert not hasattr(pseudonymizer, "__dict__")
    with pytest.raises(AttributeError):
        pseudonymizer.epoch = 2  # type: ignore[misc]
    with pytest.raises(TypeError):
        asdict(pseudonymizer)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("key", "epoch", "code"),
    [
        (b"short", 1, "MH_PRIVACY_KEY_LENGTH"),
        (b"x" * 33, 1, "MH_PRIVACY_KEY_LENGTH"),
        (bytearray(32), 1, "MH_PRIVACY_KEY_LENGTH"),
        (KEY, 0, "MH_PRIVACY_EPOCH"),
        (KEY, True, "MH_PRIVACY_EPOCH"),
        (KEY, 2_147_483_648, "MH_PRIVACY_EPOCH"),
    ],
)
def test_pseudonymizer_rejects_invalid_key_or_epoch_without_values(
    key: object, epoch: object, code: str
) -> None:
    with pytest.raises(PrivacyError) as captured:
        Pseudonymizer(key, epoch=epoch)  # type: ignore[arg-type]

    assert captured.value.code == code
    assert repr(key) not in str(captured.value)


@pytest.mark.parametrize(
    ("kind", "value", "code"),
    [
        ("Bad Kind", "value", "MH_PRIVACY_KIND"),
        ("x" * 33, "value", "MH_PRIVACY_KIND"),
        ("email", "", "MH_PRIVACY_INPUT_EMPTY"),
        ("email", "x" * 1_048_577, "MH_PRIVACY_INPUT_LARGE"),
        ("email", "bad\ud800value", "MH_PRIVACY_UNICODE"),
        ("email", b"bytes", "MH_PRIVACY_INPUT_TYPE"),
    ],
)
def test_pseudonym_inputs_fail_with_stable_value_safe_errors(
    kind: object, value: object, code: str
) -> None:
    with pytest.raises(PrivacyError) as captured:
        Pseudonymizer(KEY).pseudonymize(kind, value)  # type: ignore[arg-type]

    assert captured.value.code == code
    assert repr(value) not in str(captured.value)
