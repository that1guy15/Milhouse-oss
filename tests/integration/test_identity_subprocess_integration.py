from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

FIXTURE_PATH = Path(__file__).resolve().parents[1] / "fixtures/w02/identity-portability-v1.json"
MAX_FIXTURE_BYTES = 256 * 1024
MAX_CHILD_OUTPUT_BYTES = 64 * 1024
CHILD_TIMEOUT_SECONDS = 10

RUN_ENVIRONMENTS = (
    ("0", "C", "UTC0", "natural"),
    ("1", "en_US.UTF-8", "EST5EDT", "reverse"),
    ("314159", "POSIX", "GMT0", "rotate"),
)

CHILD_SCRIPT = r"""
import hashlib
import json
import locale
import os
import sys
import time
from datetime import datetime

MAX_INPUT_BYTES = 256 * 1024
MAX_VECTORS = 16
MAX_VARIANTS = 8


class PortabilityFailure(Exception):
    pass


def require_object(value):
    if type(value) is not dict:
        raise PortabilityFailure
    return value


def require_list(value):
    if type(value) is not list:
        raise PortabilityFailure
    return value


def strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise PortabilityFailure
        result[key] = value
    return result


def reject_constant(_value):
    raise PortabilityFailure


def reorder(value, mode):
    if type(value) is dict:
        items = list(value.items())
        if mode == "natural":
            pass
        elif mode == "reverse":
            items.reverse()
        elif mode == "rotate":
            if items:
                items = items[1:] + items[:1]
        else:
            raise PortabilityFailure
        return {key: reorder(member, mode) for key, member in items}
    if type(value) is list:
        return [reorder(member, mode) for member in value]
    return value


def materialize_datetimes(value):
    if type(value) is dict:
        if set(value) == {"$datetime"}:
            timestamp = value["$datetime"]
            if type(timestamp) is not str:
                raise PortabilityFailure
            parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            if parsed.tzinfo is None or parsed.utcoffset() is None:
                raise PortabilityFailure
            return parsed
        return {key: materialize_datetimes(member) for key, member in value.items()}
    if type(value) is list:
        return [materialize_datetimes(member) for member in value]
    return value


def require_variants(vector, key):
    variants = require_list(vector.get(key))
    if not 1 <= len(variants) <= MAX_VARIANTS:
        raise PortabilityFailure
    return variants


def one_value(values):
    if not values or any(value != values[0] for value in values[1:]):
        raise PortabilityFailure
    return values[0]


def compute_vector(vector, mode):
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

    vector_id = vector.get("id")
    installation_id = vector.get("installation_id")
    if type(vector_id) is not str or type(installation_id) is not str:
        raise PortabilityFailure

    identity_results = []
    for raw_variant in require_variants(vector, "identity_variants"):
        variant = require_object(materialize_datetimes(reorder(raw_variant, mode)))
        identity = RecordIdentityV1.model_validate(variant)
        identity_results.append(
            (
                canonical_json_bytes(
                    identity.model_dump(mode="python", exclude_none=True)
                ).hex(),
                derive_record_id(identity),
                derive_dedupe_key(RecordDedupeV1.from_identity(identity)),
            )
        )
    identity_canonical_hex, record_id, dedupe_key = one_value(identity_results)

    content_results = []
    for raw_variant in require_variants(vector, "content_variants"):
        variant = require_object(materialize_datetimes(reorder(raw_variant, mode)))
        content_results.append(derive_content_hash(variant))
    content_hash = one_value(content_results)

    envelope_results = []
    for raw_variant in require_variants(vector, "draft_variants"):
        variant = require_object(reorder(raw_variant, mode))
        wire = json.dumps(
            variant,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        )
        draft = RecordDraftV1.model_validate_json(wire)
        envelope = finalize_record(draft, installation_id=installation_id)
        canonical_envelope = canonical_json_bytes(
            envelope.model_dump(mode="python", exclude_none=True)
        )
        envelope_results.append(
            (
                envelope.record_id,
                envelope.dedupe_key,
                envelope.content_hash,
                hashlib.sha256(canonical_envelope).hexdigest(),
            )
        )
    (
        envelope_record_id,
        envelope_dedupe_key,
        envelope_content_hash,
        envelope_canonical_sha256,
    ) = one_value(envelope_results)
    if envelope_record_id != record_id or envelope_dedupe_key != dedupe_key:
        raise PortabilityFailure

    return {
        "id": vector_id,
        "expected": {
            "identity_canonical_hex": identity_canonical_hex,
            "record_id": record_id,
            "dedupe_wire": dedupe_key,
            "content_hash": content_hash,
            "finalized_envelope": {
                "record_id": envelope_record_id,
                "dedupe_wire": envelope_dedupe_key,
                "content_hash": envelope_content_hash,
                "canonical_sha256": envelope_canonical_sha256,
            },
        },
    }


def main():
    if len(sys.argv) != 3 or not sys.flags.safe_path or not sys.flags.no_user_site:
        raise PortabilityFailure
    mode = sys.argv[1]
    if os.environ.get("PYTHONHASHSEED") != sys.argv[2]:
        raise PortabilityFailure
    locale.setlocale(locale.LC_ALL, "")
    if hasattr(time, "tzset"):
        time.tzset()

    raw_fixture = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    if len(raw_fixture) > MAX_INPUT_BYTES:
        raise PortabilityFailure
    fixture = require_object(
        json.loads(
            raw_fixture,
            object_pairs_hook=strict_object,
            parse_constant=reject_constant,
        )
    )
    if fixture.get("fixture_schema") != "milhouse.identity-portability.v1":
        raise PortabilityFailure
    vectors = require_list(fixture.get("vectors"))
    if not 1 <= len(vectors) <= MAX_VECTORS:
        raise PortabilityFailure

    result = {
        "fixture_schema": fixture["fixture_schema"],
        "vectors": [compute_vector(require_object(vector), mode) for vector in vectors],
    }
    encoded = json.dumps(
        result,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    if len(encoded) > 64 * 1024:
        raise PortabilityFailure
    sys.stdout.buffer.write(encoded)


try:
    main()
except BaseException:
    raise SystemExit(70) from None
"""


def _expected_output(fixture: dict[str, object]) -> bytes:
    vectors = fixture["vectors"]
    assert isinstance(vectors, list)
    expected_vectors: list[dict[str, object]] = []
    for vector in vectors:
        assert isinstance(vector, dict)
        expected_vectors.append(
            {
                "id": vector["id"],
                "expected": vector["expected"],
            }
        )
    expected = {
        "fixture_schema": fixture["fixture_schema"],
        "vectors": expected_vectors,
    }
    return json.dumps(
        expected,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def test_identity_outputs_are_portable_across_isolated_process_environments() -> None:
    fixture_bytes = FIXTURE_PATH.read_bytes()
    assert 0 < len(fixture_bytes) <= MAX_FIXTURE_BYTES
    fixture = json.loads(fixture_bytes)
    assert isinstance(fixture, dict)
    expected_output = _expected_output(fixture)
    assert len(expected_output) <= MAX_CHILD_OUTPUT_BYTES

    outputs: list[bytes] = []
    for run_number, (hash_seed, selected_locale, timezone, reorder_mode) in enumerate(
        RUN_ENVIRONMENTS,
        start=1,
    ):
        child_environment = {
            "LC_ALL": selected_locale,
            "LANG": selected_locale,
            "TZ": timezone,
            "PYTHONHASHSEED": hash_seed,
            "PYTHONIOENCODING": "utf-8",
            "PYTHONNOUSERSITE": "1",
            "PYTHONUTF8": "1",
        }
        with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
            try:
                completed = subprocess.run(
                    [
                        sys.executable,
                        "-s",
                        "-P",
                        "-c",
                        CHILD_SCRIPT,
                        reorder_mode,
                        hash_seed,
                    ],
                    input=fixture_bytes,
                    stdout=stdout_file,
                    stderr=stderr_file,
                    check=False,
                    env=child_environment,
                    timeout=CHILD_TIMEOUT_SECONDS,
                )
            except subprocess.TimeoutExpired:
                raise AssertionError(
                    f"identity portability child run {run_number} timed out"
                ) from None
            except OSError:
                raise AssertionError(
                    f"identity portability child run {run_number} could not start"
                ) from None

            stdout_size = os.fstat(stdout_file.fileno()).st_size
            stderr_size = os.fstat(stderr_file.fileno()).st_size
            stdout_file.seek(0)
            stderr_file.seek(0)
            child_stdout = stdout_file.read(MAX_CHILD_OUTPUT_BYTES + 1)
            child_stderr = stderr_file.read(MAX_CHILD_OUTPUT_BYTES + 1)

        assert stdout_size <= MAX_CHILD_OUTPUT_BYTES, (
            f"identity portability child run {run_number} exceeded the stdout bound"
        )
        assert stderr_size <= MAX_CHILD_OUTPUT_BYTES, (
            f"identity portability child run {run_number} exceeded the stderr bound"
        )
        assert completed.returncode == 0, f"identity portability child run {run_number} failed"
        assert child_stderr == b"", f"identity portability child run {run_number} wrote to stderr"
        assert child_stdout == expected_output, (
            f"identity portability child run {run_number} did not match the fixture"
        )
        outputs.append(child_stdout)

    assert all(output == outputs[0] for output in outputs[1:])
