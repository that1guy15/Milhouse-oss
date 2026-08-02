"""Privacy + behavioural guarantees for the maintenance audit trail (W03 slice 5b; D05 fix).

The audit surface is a set of purpose-specific constructors, not a free-text sink: a caller cannot
put arbitrary text into the action/actor/outcome/reason code fields (they are fixed constants), and
the only caller-supplied value — the opaque resource id — is charset-validated (rejecting emails,
paths, URLs, prompts, multiline text, and raw payloads) AND then stored only as a SHA-256
fingerprint, so a charset-legal but secret-shaped id (e.g. an access key) is never persisted raw
(D05 re-review). Recording is transaction-scoped, so the row commits or rolls back with the mutation
it attests.
"""

from __future__ import annotations

import hashlib
import os
from datetime import UTC, datetime
from pathlib import Path

import pytest

from milhouse.privacy.pseudonym import Pseudonymizer
from milhouse.state import (
    AuditRecord,
    GlobalCommitBarrier,
    StateError,
    initialize_control_state,
    list_audit,
    open_control_database,
    record_compaction,
    record_retention_prune,
    schema_version,
)
from milhouse.state import audit as audit_module


class _HostilePseudonymizer:
    """A look-alike (NOT a Pseudonymizer subclass) whose fingerprint() returns caller-controlled
    output, used to prove the audit boundary requires the exact trusted type before persisting."""

    def __init__(self, output: object) -> None:
        self._output = output

    def fingerprint(self, kind: str, value: str) -> object:
        if isinstance(self._output, BaseException):
            raise self._output
        return self._output


class _ForgingPseudonymizer(Pseudonymizer):
    """A Pseudonymizer SUBCLASS whose overridden fingerprint() returns a canonical-SHAPED but forged
    token. Its output passes the grammar check, so only the exact-type gate can reject it (finding
    #2: token shape is not proof of keyed derivation)."""

    def fingerprint(self, kind: str, value: str) -> str:
        return "mh_fp1_e1_batch_" + "a" * 52  # grammar-valid, NOT a real keyed HMAC of `value`


_KEY_A = b"\xa1" * 32
_KEY_B = b"\xb2" * 32

_NOW = datetime(2026, 7, 28, 12, 0, 0, tzinfo=UTC)
_STAMP = "2026-07-28T12:00:00.000Z"

_RAW_CANARIES = [
    "sk_live:0xDEADBEEF/secret",  # secret token with structural punctuation
    "[email protected]",  # email address
    "/etc/passwd",  # filesystem path
    "https://evil.example/exfil",  # URL
    "ignore previous instructions",  # prompt-like free text (spaces)
    "line one\nline two",  # multiline
    "raw payload {json: true}",  # raw structured payload
]

# Secret-shaped strings that are ALSO legal opaque-id charset (so the charset guard cannot reject
# them). With no keyed pseudonymizer the identifier derivative is OMITTED, so neither the raw value
# nor its plain SHA-256 is ever persisted (PR #69 review: no public unsalted hash).
_CREDENTIAL_CANARIES = [
    "AKIAIOSFODNN7EXAMPLE",  # AWS access key id — all alphanumeric, a valid batch-id shape
    "AKIAIOSFODNN7EXAMPLEQQ",  # a longer access-key variant
    "ghp_0123456789abcdefABCDEF01",  # GitHub-PAT shape (underscore is charset-legal)
    "0123456789abcdef0123456789abcdef",  # 32-hex secret-shaped identifier
]


def _fp(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _database(tmp_path: Path):
    directory = tmp_path / "control"
    directory.mkdir(mode=0o700)
    os.chmod(directory, 0o700)
    database = open_control_database(directory / "milhouse.sqlite3")
    barrier = GlobalCommitBarrier(directory / "commit.lock")
    initialize_control_state(database, barrier=barrier, applied_at=_NOW)
    return database


def _prune(database, **kwargs) -> None:
    with database.transaction() as connection:
        record_retention_prune(connection, **kwargs)


def _audit_bytes(database) -> bytes:
    return b"".join(
        bytes(str(cell), "utf-8")
        for row in database.connection.execute("SELECT * FROM _audit").fetchall()
        for cell in row
        if cell is not None
    )


def test_the_migration_creates_the_audit_table(tmp_path: Path) -> None:
    database = _database(tmp_path)
    try:
        assert schema_version(database) == 11
        tables = {
            row[0]
            for row in database.connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
        assert "_audit" in tables
    finally:
        database.close()


def test_records_a_delivered_prune_with_fixed_codes(tmp_path: Path) -> None:
    database = _database(tmp_path)
    try:
        _prune(
            database, now=_NOW, batch_id="batch-1", record_count=3, byte_size=128, undelivered=False
        )
        assert list_audit(database) == (
            AuditRecord(
                id=1,
                recorded_at=_STAMP,
                action="retention_prune",
                actor="maintenance",
                outcome="pruned",
                resource=None,  # no keyed pseudonymizer wired → identifier omitted
                reason="expired",
                record_count=3,
                byte_size=128,
                content_sha256=None,  # retention prune has no compaction old/new byte digests
                file_sha256=None,
            ),
        )
    finally:
        database.close()


def test_records_an_undelivered_prune_as_the_critical_codes(tmp_path: Path) -> None:
    database = _database(tmp_path)
    try:
        _prune(
            database, now=_NOW, batch_id="batch-1", record_count=1, byte_size=64, undelivered=True
        )
        row = list_audit(database)[0]
        assert (row.outcome, row.reason) == ("pruned_undelivered", "expired_undelivered")
    finally:
        database.close()


@pytest.mark.parametrize("canary", _RAW_CANARIES)
def test_a_raw_canary_resource_is_rejected_before_any_write(tmp_path: Path, canary: str) -> None:
    database = _database(tmp_path)
    try:
        with pytest.raises(StateError) as captured:
            _prune(
                database, now=_NOW, batch_id=canary, record_count=1, byte_size=1, undelivered=False
            )
        assert captured.value.code == "MH_STATE_AUDIT"
        # The canary never reached SQLite: no row exists and no db byte contains it.
        assert list_audit(database) == ()
        assert canary.encode("utf-8") not in _audit_bytes(database)
        # ...nor does it leak into the error text, cause, or context.
        assert canary not in str(captured.value)
        assert captured.value.__cause__ is None
        assert captured.value.__context__ is None
    finally:
        database.close()


@pytest.mark.parametrize("canary", _CREDENTIAL_CANARIES)
def test_a_secret_shaped_legal_id_is_omitted_without_a_key(tmp_path: Path, canary: str) -> None:
    # PR #69 review: a plain SHA-256 of a legal-but-secret-shaped id is dictionary-recoverable and
    # cross-installation correlatable. With no keyed pseudonymizer wired, the derivative is omitted
    # entirely — neither the raw value NOR its public SHA-256 reaches control state.
    database = _database(tmp_path)
    try:
        _prune(database, now=_NOW, batch_id=canary, record_count=1, byte_size=1, undelivered=False)
        row = list_audit(database)[0]
        assert row.resource is None
        assert canary.encode("utf-8") not in _audit_bytes(database)
        assert _fp(canary).encode("utf-8") not in _audit_bytes(database)  # no public unsalted hash
    finally:
        database.close()


@pytest.mark.parametrize("canary", _CREDENTIAL_CANARIES)
def test_a_keyed_pseudonymizer_stores_a_keyed_token_not_a_public_hash(
    tmp_path: Path, canary: str
) -> None:
    # When a key is wired, the identifier is persisted as a keyed HMAC pseudonym — never the raw
    # value and never its public SHA-256 (which a dictionary attack could reverse/correlate).
    database = _database(tmp_path)
    try:
        pseudonymizer = Pseudonymizer(_KEY_A)
        _prune(
            database,
            now=_NOW,
            batch_id=canary,
            record_count=1,
            byte_size=1,
            undelivered=False,
            pseudonymizer=pseudonymizer,
        )
        row = list_audit(database)[0]
        assert row.resource == pseudonymizer.fingerprint("batch", canary)
        assert row.resource is not None and row.resource.startswith("mh_fp1_")
        assert canary.encode("utf-8") not in _audit_bytes(database)
        assert _fp(canary).encode("utf-8") not in _audit_bytes(database)
    finally:
        database.close()


def test_keyed_tokens_are_installation_scoped_and_correlate_within_one(tmp_path: Path) -> None:
    # Same id + same key -> identical token (authorized same-installation correlation); same id +
    # different key -> different token (no cross-installation correlation).
    database = _database(tmp_path)
    try:
        key_a1, key_a2, key_b = Pseudonymizer(_KEY_A), Pseudonymizer(_KEY_A), Pseudonymizer(_KEY_B)
        assert key_a1.fingerprint("batch", "batch-1") == key_a2.fingerprint("batch", "batch-1")
        assert key_a1.fingerprint("batch", "batch-1") != key_b.fingerprint("batch", "batch-1")
    finally:
        database.close()


def test_migration_8_clears_legacy_unsalted_audit_resources(tmp_path: Path) -> None:
    # PR #69 review: any slice-5b-era row that stored a plain SHA-256 resource must be cleared on
    # upgrade so no reversible identifier survives.
    from milhouse.state import CONTROL_MIGRATIONS, migrate

    directory = tmp_path / "control"
    directory.mkdir(mode=0o700)
    os.chmod(directory, 0o700)
    database = open_control_database(directory / "milhouse.sqlite3")
    barrier = GlobalCommitBarrier(directory / "commit.lock")
    try:
        migrate(database, CONTROL_MIGRATIONS[:7], barrier=barrier, applied_at=_NOW)  # v7 (pre-fix)
        assert schema_version(database) == 7
        legacy = _fp("batch-legacy")
        with database.transaction() as connection:
            connection.execute(
                "INSERT INTO _audit (recorded_at, action, actor, outcome, resource, reason, "
                "record_count, byte_size) VALUES "
                "(?, 'retention_prune', 'maintenance', 'pruned', ?, 'expired', 1, 1)",
                (_STAMP, legacy),
            )
        # At v7 the digest columns migration 9 adds do not exist yet, so read the resource directly.
        assert database.connection.execute("SELECT resource FROM _audit").fetchone()[0] == legacy

        migrate(database, CONTROL_MIGRATIONS, barrier=barrier, applied_at=_NOW)  # apply 8..11
        assert schema_version(database) == 11
        assert list_audit(database)[0].resource is None  # reversible hash cleared
        assert legacy.encode("utf-8") not in _audit_bytes(database)
    finally:
        database.close()


def test_the_action_actor_outcome_reason_codes_cannot_be_influenced(tmp_path: Path) -> None:
    # There is no free-text parameter for the code fields — the constructor fixes them — so a caller
    # can only ever produce the fixed retention codes, never arbitrary text.
    database = _database(tmp_path)
    try:
        _prune(
            database, now=_NOW, batch_id="batch-1", record_count=1, byte_size=1, undelivered=False
        )
        row = list_audit(database)[0]
        assert (row.action, row.actor) == ("retention_prune", "maintenance")
        assert row.outcome in {"pruned", "pruned_undelivered"}
        assert row.reason in {"expired", "expired_undelivered"}
    finally:
        database.close()


def test_ids_are_monotonic_and_append_ordered(tmp_path: Path) -> None:
    database = _database(tmp_path)
    try:
        for index in range(1, 4):
            _prune(
                database,
                now=_NOW,
                batch_id=f"batch-{index}",
                record_count=1,
                byte_size=1,
                undelivered=False,
            )
        rows = list_audit(database)
        assert [r.id for r in rows] == [1, 2, 3]
        assert [r.resource for r in rows] == [None, None, None]  # omitted without a keyed key
    finally:
        database.close()


def test_a_prune_audit_rolls_back_with_a_failed_caller_transaction(tmp_path: Path) -> None:
    database = _database(tmp_path)
    try:
        with pytest.raises(RuntimeError, match="boom"):
            with database.transaction() as connection:
                record_retention_prune(
                    connection,
                    now=_NOW,
                    batch_id="batch-1",
                    record_count=1,
                    byte_size=1,
                    undelivered=False,
                )
                raise RuntimeError("boom")
        assert list_audit(database) == ()
    finally:
        database.close()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("batch_id", ""),
        ("batch_id", 5),
        ("batch_id", "x" * 300),
        ("record_count", -1),
        ("record_count", True),
        ("record_count", 2**63),
        ("byte_size", -1),
        ("undelivered", "yes"),
        ("undelivered", 1),
    ],
)
def test_malformed_prune_arguments_are_rejected(tmp_path: Path, field: str, value: object) -> None:
    database = _database(tmp_path)
    try:
        kwargs: dict[str, object] = {
            "now": _NOW,
            "batch_id": "batch-1",
            "record_count": 1,
            "byte_size": 1,
            "undelivered": False,
        }
        kwargs[field] = value
        with pytest.raises(StateError) as captured:
            with database.transaction() as connection:
                record_retention_prune(connection, **kwargs)  # type: ignore[arg-type]
        assert captured.value.code == "MH_STATE_AUDIT"
        assert list_audit(database) == ()
    finally:
        database.close()


def test_a_prune_rejects_a_naive_timestamp(tmp_path: Path) -> None:
    database = _database(tmp_path)
    try:
        with pytest.raises(StateError) as captured:
            with database.transaction() as connection:
                record_retention_prune(
                    connection,
                    now=datetime(2026, 7, 28, 12),  # naive
                    batch_id="batch-1",
                    record_count=1,
                    byte_size=1,
                    undelivered=False,
                )
        assert captured.value.code == "MH_STATE_AUDIT"
    finally:
        database.close()


def test_list_filters_by_action_and_respects_the_limit(tmp_path: Path) -> None:
    database = _database(tmp_path)
    try:
        for index in range(1, 4):
            _prune(
                database,
                now=_NOW,
                batch_id=f"batch-{index}",
                record_count=1,
                byte_size=1,
                undelivered=False,
            )
        assert len(list_audit(database, action="retention_prune")) == 3
        assert list_audit(database, action="nonexistent") == ()
        assert len(list_audit(database, limit=2)) == 2
    finally:
        database.close()


@pytest.mark.parametrize("limit", [0, -1, 100_001])
def test_list_rejects_a_bad_limit(tmp_path: Path, limit: int) -> None:
    database = _database(tmp_path)
    try:
        with pytest.raises(StateError) as captured:
            list_audit(database, limit=limit)
        assert captured.value.code == "MH_STATE_AUDIT"
    finally:
        database.close()


def test_list_rejects_a_malformed_action_filter(tmp_path: Path) -> None:
    database = _database(tmp_path)
    try:
        with pytest.raises(StateError) as captured:
            list_audit(database, action="")
        assert captured.value.code == "MH_STATE_AUDIT"
    finally:
        database.close()


def test_a_read_against_a_broken_store_normalizes_to_a_stable_code(tmp_path: Path) -> None:
    database = _database(tmp_path)
    try:
        with database.transaction() as connection:
            connection.execute("DROP TABLE _audit")
        with pytest.raises(StateError) as captured:
            list_audit(database)
        assert captured.value.code == "MH_STATE_AUDIT"
        assert captured.value.__cause__ is None
        assert captured.value.__context__ is None
    finally:
        database.close()


def test_a_write_against_a_broken_store_normalizes_to_a_stable_code(tmp_path: Path) -> None:
    database = _database(tmp_path)
    try:
        with database.transaction() as connection:
            connection.execute("DROP TABLE _audit")
        with pytest.raises(StateError) as captured:
            with database.transaction() as connection:
                record_retention_prune(
                    connection,
                    now=_NOW,
                    batch_id="batch-1",
                    record_count=1,
                    byte_size=1,
                    undelivered=False,
                )
        assert captured.value.code == "MH_STATE_AUDIT"
        assert captured.value.__cause__ is None
        assert captured.value.__context__ is None
    finally:
        database.close()


_HOSTILE_TOKENS = [
    "AKIAIOSFODNN7EXAMPLE",  # a secret-shaped canary — not a keyed token
    "mh_fp1_e1_batch_" + "!" * 52,  # right prefix, invalid base32 body
    "mh_fp1_e1_secret_" + "a" * 52,  # wrong kind
    "mh_ps1_e1_batch_" + "a" * 52,  # a pseudonym, not a fingerprint
    "mh_fp1_e1_batch_" + "a" * 200,  # overlong
    "mh_fp1_e1_batch_" + "a" * 52,  # a grammar-VALID canonical token — a look-alike still fails
    "",  # empty
]


@pytest.mark.parametrize("bad", _HOSTILE_TOKENS)
def test_a_hostile_pseudonymizer_output_is_rejected_and_nothing_is_persisted(
    tmp_path: Path, bad: str
) -> None:
    # PR review: the pseudonymizer is untrusted at the audit boundary. A look-alike (not the exact
    # Pseudonymizer type) is rejected by the type gate before its output is even trusted — even a
    # grammar-VALID canonical token from a look-alike persists nothing (finding #2).
    database = _database(tmp_path)
    try:
        with pytest.raises(StateError) as captured:
            _prune(
                database,
                now=_NOW,
                batch_id="batch-1",
                record_count=1,
                byte_size=1,
                undelivered=False,
                pseudonymizer=_HostilePseudonymizer(bad),  # type: ignore[arg-type]
            )
        assert captured.value.code == "MH_STATE_AUDIT"
        assert list_audit(database) == ()  # nothing persisted at all
        if bad:  # (the empty token is vacuously a substring of everything)
            assert bad.encode("utf-8") not in _audit_bytes(database)
    finally:
        database.close()


def test_a_pseudonymizer_subclass_with_canonical_output_is_rejected(tmp_path: Path) -> None:
    # Finding #2: token SHAPE is not proof of keyed derivation. A Pseudonymizer SUBCLASS can
    # override fingerprint() to return a canonical-shaped token forged from caller input; the shape
    # check alone would admit it, so the audit boundary requires the EXACT concrete Pseudonymizer
    # type. The subclass is rejected and nothing is persisted, even though its output IS grammar-ok.
    database = _database(tmp_path)
    try:
        forged = _ForgingPseudonymizer(_KEY_A)
        # Prove the forged output would pass the grammar check, so the TYPE gate is what rejects it.
        assert audit_module._FINGERPRINT_TOKEN.fullmatch(forged.fingerprint("batch", "batch-1"))
        with pytest.raises(StateError) as captured:
            _prune(
                database,
                now=_NOW,
                batch_id="batch-1",
                record_count=1,
                byte_size=1,
                undelivered=False,
                pseudonymizer=forged,
            )
        assert captured.value.code == "MH_STATE_AUDIT"
        assert list_audit(database) == ()  # nothing persisted
    finally:
        database.close()


@pytest.mark.parametrize("output", [None, RuntimeError("boom")])
def test_a_pseudonymizer_that_misbehaves_is_contained(tmp_path: Path, output: object) -> None:
    # A pseudonymizer that returns a non-string or raises is contained: fixed code, nothing stored.
    database = _database(tmp_path)
    try:
        with pytest.raises(StateError) as captured:
            _prune(
                database,
                now=_NOW,
                batch_id="batch-1",
                record_count=1,
                byte_size=1,
                undelivered=False,
                pseudonymizer=_HostilePseudonymizer(output),  # type: ignore[arg-type]
            )
        assert captured.value.code == "MH_STATE_AUDIT"
        assert list_audit(database) == ()
    finally:
        database.close()


def test_record_compaction_with_a_key_stores_keyed_lineage_for_both_segments(
    tmp_path: Path,
) -> None:
    # PR #72 review: when a keyed pseudonymizer is supplied, compaction records an attributable
    # old->new lineage as two keyed identifiers — never a raw id or a public SHA-256.
    database = _database(tmp_path)
    try:
        pseudonymizer = Pseudonymizer(_KEY_A)
        old_id, new_id = "batch-old", "c" + "0" * 64
        old_content, old_file = "a" * 64, "b" * 64
        new_content, new_file = "c" * 64, "d" * 64
        with database.transaction() as connection:
            record_compaction(
                connection,
                now=_NOW,
                old_batch_id=old_id,
                new_batch_id=new_id,
                old_record_count=2,
                old_byte_size=200,
                new_record_count=1,
                new_byte_size=100,
                old_content_sha256=old_content,
                old_file_sha256=old_file,
                new_content_sha256=new_content,
                new_file_sha256=new_file,
                pseudonymizer=pseudonymizer,
            )
        rows = list_audit(database, action="compaction")
        assert [r.outcome for r in rows] == ["compacted_from", "compacted_into"]
        assert rows[0].resource == pseudonymizer.fingerprint("batch", old_id)
        assert rows[1].resource == pseudonymizer.fingerprint("batch", new_id)
        assert all(r.resource is not None and r.resource.startswith("mh_fp1_") for r in rows)
        # Plan §§4.8-4.9: each row carries its segment's verified content + file digests as
        # immutable evidence of the retired (from) and replacement (into) bytes.
        assert (rows[0].content_sha256, rows[0].file_sha256) == (old_content, old_file)
        assert (rows[1].content_sha256, rows[1].file_sha256) == (new_content, new_file)
        blob = _audit_bytes(database)
        assert old_id.encode("utf-8") not in blob and new_id.encode("utf-8") not in blob
        assert _fp(old_id).encode("utf-8") not in blob and _fp(new_id).encode("utf-8") not in blob
    finally:
        database.close()


def test_record_compaction_rejects_a_malformed_digest_and_rolls_back(tmp_path: Path) -> None:
    # P1 (review finding #4): the old/new content/file digests are validated and written in the
    # SAME transaction as the ledger swap, so a malformed digest fails closed and nothing persists.
    database = _database(tmp_path)
    try:
        with pytest.raises(StateError) as captured, database.transaction() as connection:
            record_compaction(
                connection,
                now=_NOW,
                old_batch_id="batch-old",
                new_batch_id="c" + "0" * 64,
                old_record_count=2,
                old_byte_size=200,
                new_record_count=1,
                new_byte_size=100,
                old_content_sha256="not-a-digest",  # invalid
                old_file_sha256="b" * 64,
                new_content_sha256="c" * 64,
                new_file_sha256="d" * 64,
                pseudonymizer=Pseudonymizer(_KEY_A),
            )
        assert captured.value.code == "MH_STATE_AUDIT"
        assert list_audit(database, action="compaction") == ()  # rolled back, nothing persisted
    finally:
        database.close()
