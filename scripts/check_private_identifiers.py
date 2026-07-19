#!/usr/bin/env python3
"""Fail when tracked repository text contains concrete local machine identifiers."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import subprocess
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import NoReturn

MAX_TEXT_BYTES = 16 * 1024 * 1024
MAX_REPORTED_FINDINGS = 50

# These names are conventional documentation/test identities, not local accounts. The allowlist is
# intentionally narrow: adding a value requires it to remain obviously synthetic in any context.
PLACEHOLDER_IDENTIFIERS = frozenset(
    {
        "alice",
        "bob",
        "build",
        "ci",
        "contributor",
        "developer",
        "devbox",
        "example",
        "host",
        "hostname",
        "jenkins",
        "machine",
        "milhouse",
        "none",
        "null",
        "operator",
        "owner",
        "person",
        "redacted",
        "runner",
        "sample",
        "shared",
        "synthetic",
        "test",
        "unknown",
        "unset",
        "user",
        "username",
    }
)
PLACEHOLDER_PREFIXES = ("example-", "milhouse-", "sample-", "synthetic-", "test-")

POSIX_HOME = re.compile(r"/(?:Users|home)/(?P<identifier>[A-Za-z0-9._-]+)(?=/|\b)")
WINDOWS_HOME = re.compile(
    r"(?i)(?<![A-Za-z0-9])(?:[A-Z]:[\\/]+|/mnt/[a-z]/)Users[\\/]+"
    r"(?P<identifier>[A-Za-z0-9._-]+)(?=[\\/]|\b)"
)
NAMED_TILDE_HOME = re.compile(r"(?<![A-Za-z0-9._-])~(?P<identifier>[A-Za-z0-9._-]+)(?=/)")
PRIVILEGED_HOME = re.compile(r"(?<![A-Za-z0-9._-])/r[o]ot/(?P<tail>[A-Za-z0-9._-]+)")
MACOS_TEMP = re.compile(
    r"(?<![A-Za-z0-9._-])/(?:pr[i]vate/)?v[a]r/folders/"
    r"(?P<bucket>[A-Za-z0-9_-]{2,})/(?P<identifier>[A-Za-z0-9_-]{8,})(?=/|\b)"
)
LOCAL_HOSTNAME = re.compile(
    r"(?i)(?<![A-Za-z0-9._-])(?P<identifier>[A-Za-z0-9][A-Za-z0-9_-]{1,62})"
    r"\.local\b"
)
IDENTIFIER_KEY = (
    r"(?:host[_ -]?name|local[_ -]?host[_ -]?name|machine[_ -]?(?:name|id)|"
    r"computer[_ -]?name|device[_ -]?(?:name|id)|node[_ -]?name|"
    r"(?:hardware|platform|system)[_ -]?uuid|serial[_ -]?number|"
    r"(?:mac|hardware)[_ -]?address)"
)
IDENTIFIER_ASSIGNMENT = re.compile(
    r"(?P<key_quote>[\"']?)"
    rf"(?P<key>{IDENTIFIER_KEY})"
    r"(?P=key_quote)\s*[:=]\s*"
    r"(?P<value_quote>[\"'])(?P<identifier>[^\r\n\"']{1,128})(?P=value_quote)",
    re.IGNORECASE,
)
BARE_IDENTIFIER_ASSIGNMENT = re.compile(
    rf"^\s*(?:export\s+)?{IDENTIFIER_KEY}\s*[:=]\s*"
    r"(?P<identifier>[A-Za-z0-9][A-Za-z0-9._:-]{1,127})\s*(?:#.*)?$",
    re.IGNORECASE | re.MULTILINE,
)


class PrivateIdentifierError(RuntimeError):
    """Raised when the tracked-tree scan cannot produce trustworthy evidence."""


@dataclass(frozen=True)
class TextFinding:
    """One category-only match within text."""

    rule: str
    line: int
    column: int


@dataclass(frozen=True)
class Finding:
    """One category-only tracked-file finding."""

    relative_path: str
    rule: str
    line: int
    column: int


def fail(message: str) -> NoReturn:
    """Exit without echoing matched identifier content."""

    print(f"private-identifiers: {message}", file=sys.stderr)
    raise SystemExit(1)


def _is_placeholder(identifier: str) -> bool:
    normalized = identifier.strip().casefold()
    if normalized in PLACEHOLDER_IDENTIFIERS:
        return True
    if normalized in {
        "0.0.0.0",
        "127.0.0.1",
        "::1",
        "example.com",
        "example.invalid",
        "host.docker.internal",
        "localhost",
        "false",
        "true",
    }:
        return True
    if normalized.startswith(("${", "$")):
        return True
    if normalized.startswith("<") and normalized.endswith(">"):
        return True
    return normalized.startswith(PLACEHOLDER_PREFIXES)


def _line_and_column(text: str, offset: int) -> tuple[int, int]:
    line = text.count("\n", 0, offset) + 1
    previous_newline = text.rfind("\n", 0, offset)
    column = offset + 1 if previous_newline < 0 else offset - previous_newline
    return line, column


def _append_match(
    findings: list[TextFinding],
    text: str,
    match: re.Match[str],
    rule: str,
) -> None:
    line, column = _line_and_column(text, match.start())
    findings.append(TextFinding(rule=rule, line=line, column=column))


def scan_text(text: str) -> tuple[TextFinding, ...]:
    """Return privacy-safe findings without retaining matched identifier values."""

    findings: list[TextFinding] = []

    for match in POSIX_HOME.finditer(text):
        if not _is_placeholder(match.group("identifier")):
            _append_match(findings, text, match, "concrete POSIX home path")
            break

    for match in WINDOWS_HOME.finditer(text):
        if not _is_placeholder(match.group("identifier")):
            _append_match(findings, text, match, "concrete Windows home path")
            break

    for match in NAMED_TILDE_HOME.finditer(text):
        if not _is_placeholder(match.group("identifier")):
            _append_match(findings, text, match, "concrete named home path")
            break

    for match in PRIVILEGED_HOME.finditer(text):
        # Existing negative-test prose uses this one literal placeholder leaf without asserting a
        # real privileged-user location. Any other privileged-home path remains prohibited.
        if match.group("tail").casefold() != "private.txt":
            _append_match(findings, text, match, "concrete privileged home path")
            break

    for match in MACOS_TEMP.finditer(text):
        if not _is_placeholder(match.group("identifier")):
            _append_match(findings, text, match, "concrete macOS machine-local temporary path")
            break

    for match in LOCAL_HOSTNAME.finditer(text):
        if not _is_placeholder(match.group("identifier")):
            _append_match(findings, text, match, "concrete local hostname")
            break

    for match in IDENTIFIER_ASSIGNMENT.finditer(text):
        if not _is_placeholder(match.group("identifier")):
            _append_match(findings, text, match, "concrete machine identifier assignment")
            break

    for match in BARE_IDENTIFIER_ASSIGNMENT.finditer(text):
        if not _is_placeholder(match.group("identifier")):
            _append_match(findings, text, match, "concrete machine identifier assignment")
            break

    return tuple(sorted(set(findings), key=lambda item: (item.line, item.column, item.rule)))


def _run_git(repository: Path, arguments: Sequence[str]) -> bytes:
    try:
        completed = subprocess.run(
            ["git", "-C", str(repository), *arguments],
            check=False,
            capture_output=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PrivateIdentifierError("Git prerequisite failed") from exc
    if completed.returncode != 0:
        raise PrivateIdentifierError("Git prerequisite failed")
    return completed.stdout


def _repository_root(repository: Path) -> Path:
    try:
        root = repository.resolve(strict=True)
    except OSError as exc:
        raise PrivateIdentifierError("repository root does not exist") from exc
    if not root.is_dir():
        raise PrivateIdentifierError("repository root must be a directory")
    raw_top_level = _run_git(root, ("rev-parse", "--path-format=absolute", "--show-toplevel"))
    try:
        top_level = Path(raw_top_level.rstrip(b"\n").decode("utf-8")).resolve(strict=True)
    except (OSError, UnicodeError) as exc:
        raise PrivateIdentifierError("Git returned an invalid repository root") from exc
    if top_level != root:
        raise PrivateIdentifierError("scan source must be the Git repository root")
    return root


def _decode_git_paths(raw: bytes, label: str) -> tuple[str, ...]:
    if not raw:
        return ()
    encoded_paths = raw.split(b"\0")
    if encoded_paths[-1] != b"":
        raise PrivateIdentifierError(f"Git returned a malformed {label} list")
    paths: list[str] = []
    for encoded in encoded_paths[:-1]:
        try:
            relative = encoded.decode("utf-8")
        except UnicodeError as exc:
            raise PrivateIdentifierError(f"{label} must be valid UTF-8") from exc
        candidate = PurePosixPath(relative)
        if (
            not relative
            or candidate.is_absolute()
            or any(part in {"", ".", ".."} for part in candidate.parts)
            or candidate.as_posix() != relative
        ):
            raise PrivateIdentifierError(f"Git returned an unsafe {label}")
        paths.append(relative)
    if len(paths) != len(set(paths)):
        raise PrivateIdentifierError(f"Git returned duplicate {label}")
    return tuple(paths)


def _tracked_paths(repository: Path) -> tuple[str, ...]:
    paths = _decode_git_paths(
        _run_git(repository, ("ls-files", "-z", "--cached")),
        "tracked-file path",
    )
    if not paths:
        raise PrivateIdentifierError("repository has no tracked files")
    deleted = set(
        _decode_git_paths(
            _run_git(repository, ("ls-files", "-z", "--deleted")),
            "deleted tracked-file path",
        )
    )
    if not deleted.issubset(paths):
        raise PrivateIdentifierError("Git returned inconsistent deleted tracked-file paths")
    current_paths = set(paths) - deleted
    if not current_paths:
        raise PrivateIdentifierError("repository has no current tracked files")
    return tuple(sorted(current_paths))


def _read_tracked_text(path: Path) -> str | None:
    if path.is_symlink():
        try:
            return os.readlink(path)
        except OSError as exc:
            raise PrivateIdentifierError("cannot read a tracked symbolic-link target") from exc
    if not path.is_file():
        raise PrivateIdentifierError("a tracked path is missing or is not a regular file")
    try:
        size = path.stat().st_size
        if size > MAX_TEXT_BYTES:
            with path.open("rb") as stream:
                sample = stream.read(8192)
            if b"\0" in sample:
                return None
            raise PrivateIdentifierError("a tracked text file exceeds the 16 MiB safety bound")
        raw = path.read_bytes()
    except OSError as exc:
        raise PrivateIdentifierError("cannot read a tracked file") from exc
    if b"\0" in raw:
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeError as exc:
        raise PrivateIdentifierError("tracked non-binary text must be valid UTF-8") from exc


def scan_repository(repository: Path) -> tuple[tuple[Finding, ...], int]:
    """Scan tracked current-tree text and return findings plus the text-file count."""

    root = _repository_root(repository)
    findings: list[Finding] = []
    text_file_count = 0
    for relative in _tracked_paths(root):
        text = _read_tracked_text(root / PurePosixPath(relative))
        if text is None:
            continue
        text_file_count += 1
        for item in scan_text(relative + "\n" + text):
            # Prefixing the relative path lets the same rules inspect tracked names. Adjust content
            # line numbers while preserving line 1 for a finding in the tracked name itself.
            line = item.line if item.line == 1 else item.line - 1
            findings.append(
                Finding(
                    relative_path=relative,
                    rule=item.rule,
                    line=line,
                    column=item.column,
                )
            )
    if text_file_count == 0:
        raise PrivateIdentifierError("repository has no tracked UTF-8 text files")
    return tuple(
        sorted(
            findings,
            key=lambda item: (item.relative_path, item.line, item.column, item.rule),
        )
    ), text_file_count


def safe_location(finding: Finding) -> str:
    """Return a useful location without repeating a sensitive tracked filename."""

    if scan_text(finding.relative_path):
        digest = hashlib.sha256(finding.relative_path.encode("utf-8")).hexdigest()[:12]
        return f"tracked-file-{digest}:{finding.line}:{finding.column}"
    return f"{finding.relative_path}:{finding.line}:{finding.column}"


def parse_args(arguments: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repository",
        type=Path,
        default=Path.cwd(),
        help="Git repository root to scan (default: current directory)",
    )
    return parser.parse_args(arguments)


def main(arguments: Sequence[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if arguments is None else arguments)
    try:
        findings, text_file_count = scan_repository(args.repository)
    except PrivateIdentifierError as exc:
        fail(str(exc))
    if findings:
        for finding in findings[:MAX_REPORTED_FINDINGS]:
            print(
                f"private-identifiers: {safe_location(finding)}: {finding.rule}",
                file=sys.stderr,
            )
        remaining = len(findings) - MAX_REPORTED_FINDINGS
        if remaining > 0:
            print(
                f"private-identifiers: {remaining} additional finding(s) suppressed",
                file=sys.stderr,
            )
        fail(f"{len(findings)} prohibited private identifier finding(s)")
    print(f"private-identifiers: {text_file_count} tracked text file(s) passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
