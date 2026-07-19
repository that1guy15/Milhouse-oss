from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from scripts import check_private_identifiers
from scripts.check_private_identifiers import (
    Finding,
    PrivateIdentifierError,
    main,
    safe_location,
    scan_repository,
    scan_text,
)


def _concrete_owner() -> str:
    return "local" + "-operator-27"


def _concrete_host() -> str:
    return "studio" + "-node-27"


@pytest.mark.parametrize(
    "text_factory",
    (
        lambda: "/" + "Users" + "/" + _concrete_owner() + "/project/file.txt",
        lambda: "/" + "home" + "/" + _concrete_owner() + "/project/file.txt",
        lambda: "C:" + "\\" + "Users" + "\\" + _concrete_owner() + "\\project",
        lambda: "/mnt/c/" + "Users" + "/" + _concrete_owner() + "/project",
        lambda: "~" + _concrete_owner() + "/project",
        lambda: "/" + "root" + "/operator-state/file.txt",
        lambda: "/private/var/" + "folders/ab/" + _concrete_owner() + "/cache",
    ),
)
def test_scan_text_rejects_concrete_local_paths(text_factory) -> None:
    findings = scan_text(text_factory())
    assert findings
    assert all(finding.rule.startswith("concrete") for finding in findings)


def test_scan_text_allows_documented_placeholders_and_provenance_facts() -> None:
    synthetic = "\n".join(
        (
            "/" + "Users" + "/example/private.txt",
            "/" + "home" + "/runner/work/project",
            "C:" + "\\" + "Users" + "\\example\\private.txt",
            "/" + "root" + "/private.txt",
            "/absolute/path/to/project",
            "example.local",
            '"hostname": "synthetic-node"',
            "public-owner/Milhouse-oss@example-commit",
            "private-owner/milhouse@donor-reference",
        )
    )

    assert scan_text(synthetic) == ()


@pytest.mark.parametrize(
    "placeholder",
    ("127.0.0.1", "$MACHINE_NAME", "${MACHINE_NAME}", "<machine-id>"),
)
def test_machine_assignment_placeholder_forms_remain_explicitly_safe(placeholder: str) -> None:
    assignment = "host" + f'name = "{placeholder}"'
    assert scan_text(assignment) == ()


def test_placeholder_matches_do_not_hide_later_concrete_identifiers() -> None:
    owner = _concrete_owner()
    host = _concrete_host()
    content = "\n".join(
        (
            "~example/project",
            "~" + owner + "/project",
            "/private/var/folders/ab/synthetic/cache",
            "/private/var/folders/ab/" + owner + "/cache",
            "hostname=localhost",
            "machine_id=" + host,
        )
    )

    rules = {finding.rule for finding in scan_text(content)}

    assert "concrete named home path" in rules
    assert "concrete macOS machine-local temporary path" in rules
    assert "concrete machine identifier assignment" in rules


def test_scan_text_rejects_machine_identifier_literals() -> None:
    host = _concrete_host()
    content = "\n".join(
        (
            host + ".local",
            '"host' + 'name": "' + host + '"',
            "computer-" + "name: " + host,
            "machine_" + 'id = "' + "9876" + "abcdeffedcba" + '"',
        )
    )

    findings = scan_text(content)

    assert {finding.rule for finding in findings} == {
        "concrete local hostname",
        "concrete machine identifier assignment",
    }


def test_diagnostics_never_repeat_matched_identifier() -> None:
    owner = _concrete_owner()
    relative = "fixtures/" + "/".join(("Users", owner, "sample.txt"))
    finding = Finding(
        relative_path=relative,
        rule="concrete POSIX home path",
        line=3,
        column=4,
    )

    location = safe_location(finding)

    assert owner not in location
    assert location.startswith("tracked-file-")


def _git(repository: Path, *arguments: str) -> None:
    subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=True,
        capture_output=True,
    )


def test_git_prerequisite_errors_are_normalized(monkeypatch: pytest.MonkeyPatch) -> None:
    def timeout(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        raise subprocess.TimeoutExpired("git", 1)

    monkeypatch.setattr(check_private_identifiers.subprocess, "run", timeout)
    with pytest.raises(PrivateIdentifierError, match="Git prerequisite failed"):
        check_private_identifiers._run_git(Path("."), ("status",))

    monkeypatch.setattr(
        check_private_identifiers.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 2, stdout=b"", stderr=b""),
    )
    with pytest.raises(PrivateIdentifierError, match="Git prerequisite failed"):
        check_private_identifiers._run_git(Path("."), ("status",))


def test_repository_root_rejects_missing_nondirectory_invalid_and_nested_sources(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(PrivateIdentifierError, match="does not exist"):
        check_private_identifiers._repository_root(tmp_path / "missing")

    file_root = tmp_path / "file"
    file_root.write_text("synthetic\n", encoding="utf-8")
    with pytest.raises(PrivateIdentifierError, match="must be a directory"):
        check_private_identifiers._repository_root(file_root)

    repository = tmp_path / "repository"
    repository.mkdir()
    monkeypatch.setattr(check_private_identifiers, "_run_git", lambda *_args: b"\xff\n")
    with pytest.raises(PrivateIdentifierError, match="invalid repository root"):
        check_private_identifiers._repository_root(repository)

    other = tmp_path / "other"
    other.mkdir()
    monkeypatch.setattr(
        check_private_identifiers,
        "_run_git",
        lambda *_args: os.fsencode(other) + b"\n",
    )
    with pytest.raises(PrivateIdentifierError, match="must be the Git repository root"):
        check_private_identifiers._repository_root(repository)


@pytest.mark.parametrize(
    ("raw", "message"),
    (
        (b"path-without-terminator", "malformed"),
        (b"\xff\0", "valid UTF-8"),
        (b"../escape\0", "unsafe"),
        (b"safe\0safe\0", "duplicate"),
    ),
)
def test_git_path_decoder_rejects_untrusted_inventory(
    raw: bytes,
    message: str,
) -> None:
    with pytest.raises(PrivateIdentifierError, match=message):
        check_private_identifiers._decode_git_paths(raw, "tracked-file path")


def test_tracked_path_inventory_rejects_empty_inconsistent_and_fully_deleted_sets(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(check_private_identifiers, "_run_git", lambda *_args: b"")
    with pytest.raises(PrivateIdentifierError, match="no tracked files"):
        check_private_identifiers._tracked_paths(tmp_path)

    def inconsistent(_repository: Path, arguments: tuple[str, ...]) -> bytes:
        return b"other\0" if "--deleted" in arguments else b"safe\0"

    monkeypatch.setattr(check_private_identifiers, "_run_git", inconsistent)
    with pytest.raises(PrivateIdentifierError, match="inconsistent deleted"):
        check_private_identifiers._tracked_paths(tmp_path)

    def fully_deleted(_repository: Path, arguments: tuple[str, ...]) -> bytes:
        return b"safe\0" if "ls-files" in arguments else b""

    monkeypatch.setattr(check_private_identifiers, "_run_git", fully_deleted)
    with pytest.raises(PrivateIdentifierError, match="no current tracked files"):
        check_private_identifiers._tracked_paths(tmp_path)


def test_tracked_text_reader_rejects_nonfiles_and_bounds_text_but_skips_binary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(PrivateIdentifierError, match="missing or is not a regular file"):
        check_private_identifiers._read_tracked_text(tmp_path)

    binary = tmp_path / "binary"
    binary.write_bytes(b"binary\0payload")
    assert check_private_identifiers._read_tracked_text(binary) is None

    monkeypatch.setattr(check_private_identifiers, "MAX_TEXT_BYTES", 2)
    assert check_private_identifiers._read_tracked_text(binary) is None

    oversized_text = tmp_path / "oversized.txt"
    oversized_text.write_text("bounded text", encoding="utf-8")
    with pytest.raises(PrivateIdentifierError, match="exceeds the 16 MiB safety bound"):
        check_private_identifiers._read_tracked_text(oversized_text)


def test_tracked_symlink_read_failure_is_normalized(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "target"
    target.write_text("synthetic\n", encoding="utf-8")
    link = tmp_path / "link"
    link.symlink_to(target)
    monkeypatch.setattr(
        check_private_identifiers.os,
        "readlink",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("synthetic race")),
    )

    with pytest.raises(PrivateIdentifierError, match="cannot read a tracked symbolic-link"):
        check_private_identifiers._read_tracked_text(link)


def test_repository_scan_uses_tracked_current_tree_only(tmp_path: Path) -> None:
    _git(tmp_path, "init", "--quiet")
    safe = tmp_path / "safe.txt"
    safe.write_text("synthetic repository text\n", encoding="utf-8")
    _git(tmp_path, "add", "safe.txt")
    untracked = tmp_path / "untracked.txt"
    untracked.write_text(
        "/" + "Users" + "/" + _concrete_owner() + "/untracked\n",
        encoding="utf-8",
    )

    findings, text_count = scan_repository(tmp_path)

    assert findings == ()
    assert text_count == 1

    safe.write_text(
        "/" + "home" + "/" + _concrete_owner() + "/tracked\n",
        encoding="utf-8",
    )
    findings, text_count = scan_repository(tmp_path)
    assert len(findings) == 1
    assert findings[0].relative_path == "safe.txt"
    assert text_count == 1


def test_repository_scan_checks_symbolic_link_text(tmp_path: Path) -> None:
    _git(tmp_path, "init", "--quiet")
    safe = tmp_path / "safe.txt"
    safe.write_text("safe\n", encoding="utf-8")
    link = tmp_path / "tracked-link"
    os.symlink("/" + "home" + "/" + _concrete_owner() + "/target", link)
    _git(tmp_path, "add", "safe.txt", "tracked-link")

    findings, text_count = scan_repository(tmp_path)

    assert len(findings) == 1
    assert findings[0].relative_path == "tracked-link"
    assert text_count == 2


def test_cli_failure_does_not_echo_matched_content(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _git(tmp_path, "init", "--quiet")
    owner = _concrete_owner()
    tracked = tmp_path / "tracked.txt"
    tracked.write_text(
        "/" + "Users" + "/" + owner + "/project\n",
        encoding="utf-8",
    )
    _git(tmp_path, "add", "tracked.txt")

    with pytest.raises(SystemExit) as raised:
        main(["--repository", str(tmp_path)])

    assert raised.value.code == 1
    output = capsys.readouterr()
    assert owner not in output.err
    assert "concrete POSIX home path" in output.err


def test_repository_scan_excludes_deleted_paths_and_rejects_non_utf8_text(
    tmp_path: Path,
) -> None:
    _git(tmp_path, "init", "--quiet")
    tracked = tmp_path / "tracked.txt"
    tracked.write_text("safe\n", encoding="utf-8")
    remaining = tmp_path / "remaining.txt"
    remaining.write_text("also safe\n", encoding="utf-8")
    _git(tmp_path, "add", "tracked.txt", "remaining.txt")
    tracked.unlink()

    findings, text_count = scan_repository(tmp_path)
    assert findings == ()
    assert text_count == 1

    remaining.write_bytes(b"non-utf8-\xff-text")
    with pytest.raises(PrivateIdentifierError, match="valid UTF-8"):
        scan_repository(tmp_path)


def test_repository_scan_rejects_an_inventory_without_utf8_text(tmp_path: Path) -> None:
    _git(tmp_path, "init", "--quiet")
    binary = tmp_path / "fixture.bin"
    binary.write_bytes(b"synthetic\0binary")
    _git(tmp_path, "add", "fixture.bin")

    with pytest.raises(PrivateIdentifierError, match="no tracked UTF-8 text files"):
        scan_repository(tmp_path)


def test_private_identifier_main_reports_clean_and_bounds_finding_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        check_private_identifiers,
        "scan_repository",
        lambda _repository: ((), 3),
    )
    assert main(["--repository", str(tmp_path)]) == 0
    assert "3 tracked text file(s) passed" in capsys.readouterr().out

    findings = tuple(
        Finding(
            relative_path=f"fixtures/safe-{index}.txt",
            rule="synthetic finding category",
            line=1,
            column=1,
        )
        for index in range(check_private_identifiers.MAX_REPORTED_FINDINGS + 1)
    )
    monkeypatch.setattr(
        check_private_identifiers,
        "scan_repository",
        lambda _repository: (findings, len(findings)),
    )
    with pytest.raises(SystemExit) as raised:
        main(["--repository", str(tmp_path)])

    assert raised.value.code == 1
    assert "1 additional finding(s) suppressed" in capsys.readouterr().err


def test_scanner_sources_do_not_trigger_their_own_rules() -> None:
    root = Path(__file__).resolve().parents[2]
    for relative in (
        "scripts/check_private_identifiers.py",
        "tests/unit/test_tool_private_identifiers.py",
    ):
        assert scan_text((root / relative).read_text(encoding="utf-8")) == ()
