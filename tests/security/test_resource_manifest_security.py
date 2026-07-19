import secrets

import pytest

from milhouse.resources import ResourceManifest, ResourceManifestError, read_resource_text


def _valid_manifest() -> dict[str, object]:
    return {
        "manifest_version": 1,
        "distribution": "milhouse-observability",
        "import_package": "milhouse",
        "resources": ["py.typed"],
    }


def _manifest_rejection_is_safe(
    candidate: dict[str, object], sensitive_value: str
) -> tuple[bool, bool]:
    try:
        ResourceManifest.from_mapping(candidate)
    except Exception as exc:  # reduce every failure to safe booleans before pytest sees it
        return isinstance(exc, ResourceManifestError), sensitive_value not in str(exc)
    return False, True


def test_manifest_rejects_runtime_generated_sensitive_fields_without_echoing_values() -> None:
    adversarial_value = "".join(("gh", "p", "_", secrets.token_urlsafe(32)))
    candidate = _valid_manifest()
    candidate["credential"] = adversarial_value

    rejected_with_expected_type, message_was_safe = _manifest_rejection_is_safe(
        candidate, adversarial_value
    )
    candidate.clear()
    del adversarial_value, candidate

    assert rejected_with_expected_type, "manifest must reject an unknown sensitive field"
    assert message_was_safe, "manifest rejection must use a value-free error"


def test_manifest_safety_helper_reduces_a_leaking_error_to_safe_status(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    sensitive_value = "".join(("gh", "p", "_", secrets.token_urlsafe(32)))
    candidate = _valid_manifest()
    candidate["credential"] = sensitive_value

    def leaking_rejection(_value: object) -> ResourceManifest:
        if not isinstance(_value, dict):
            raise TypeError("synthetic mapping required")
        raise ResourceManifestError(str(_value["credential"]))

    monkeypatch.setattr(ResourceManifest, "from_mapping", leaking_rejection)
    safe_status = _manifest_rejection_is_safe(candidate, sensitive_value)
    captured = capsys.readouterr()
    output_was_empty = not captured.out and not captured.err
    candidate.clear()
    del sensitive_value, candidate, captured

    assert safe_status == (True, False)
    assert output_was_empty, "contained rejection must not write to pytest capture streams"


@pytest.mark.parametrize(
    "relative_path",
    ("../__init__.py", "/etc/passwd", "resources\\manifest.json", "./py.typed"),
)
def test_resource_reader_rejects_paths_outside_the_declared_namespace(
    relative_path: str,
) -> None:
    with pytest.raises(ResourceManifestError):
        read_resource_text(relative_path)
