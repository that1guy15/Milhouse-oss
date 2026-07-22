"""Layered, bounded free-text redaction for untrusted operational evidence."""

from __future__ import annotations

import base64
import binascii
import html
import ipaddress
import json
import math
import re
import unicodedata
from bisect import bisect_left, bisect_right
from collections.abc import Callable
from dataclasses import dataclass
from typing import NoReturn
from urllib.parse import parse_qsl, unquote, unquote_to_bytes, urlencode, urlsplit, urlunsplit

from milhouse.core.immutable import freeze_dict
from milhouse.privacy.pseudonym import PrivacyError, Pseudonymizer
from milhouse.privacy.sanitize import sanitize_local_path, sanitize_url

MAX_REDACTION_INPUT_BYTES = 65_536
MAX_REDACTED_TEXT_BYTES = 10_240
MAX_KNOWN_SECRETS = 128
MIN_KNOWN_SECRET_BYTES = 8
MAX_KNOWN_SECRET_BYTES = 4_096
MAX_URLS_PER_TEXT = 100

_REDACTION_POLICY_VERSION = 2
_PRIVATE_KEY_BLOCK = re.compile(
    r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----.*?"
    r"-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----",
    re.DOTALL,
)
_CREDENTIAL_HEADER = re.compile(
    r"^[ \t]*(?P<name>authorization|proxy-authorization|cookie|set-cookie|"
    r"x-api-key|x-auth-token)\s*:[^\n]*$",
    re.IGNORECASE | re.MULTILINE,
)
_CREDENTIAL_ASSIGNMENT = re.compile(
    r"\b(?P<name>api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|"
    r"password|passwd|secret|token)\b(?P<separator>\s*[:=]\s*)"
    r"[^\n]*",
    re.IGNORECASE,
)
_UNQUOTED_PATH_PART = r"(?:\\[ \t]|[^\s<>\"`])+"
_URL = re.compile(rf"https?://{_UNQUOTED_PATH_PART}", re.IGNORECASE)
_FILE_URI = re.compile(
    rf"(?<!\w)file:(?://)?{_UNQUOTED_PATH_PART}",
    re.IGNORECASE,
)
_EMAIL = re.compile(
    r"(?<![\w.!#$%&'*+/=?^`{|}~-])"
    r"[\w.!#$%&'*+/=?^`{|}~-]{1,64}@"
    r"(?P<domain>[\w-](?:[\w.-]{0,251}[\w-])?)"
    r"(?![\w-]|\.[\w-])",
    re.IGNORECASE,
)
_IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
_BRACKETED_IPV6 = re.compile(r"\[[0-9A-Fa-f:.%]+\]")
_UNBRACKETED_IPV6 = re.compile(
    r"(?<![\w:])"
    r"(?=[0-9A-Fa-f:.%_-]*:[0-9A-Fa-f:.%_-]*:)"
    r"[0-9A-Fa-f:.]*[0-9A-Fa-f:](?:%[A-Za-z0-9_.-]{1,64})?"
    r"(?![\w:.%])"
)
_PHONE = re.compile(
    r"(?<!\w)(?:\+\d{1,3}[ .-]?)?(?:\(?\d{3}\)?[ .-]?)"
    r"\d{3}[ .-]\d{4}(?!\w)"
)
_FILESYSTEM_URL_ROOT_PATTERN = (
    r"Applications|Library|System|Users|Volumes|__w|bin|boot|dev|etc|home|lib|"
    r"lib32|lib64|media|mnt|opt|private|proc|root|run|sbin|srv|sys|tmp|usr|var|"
    r"workspace|workspaces"
)
_URL_POSIX_PATH = re.compile(rf"(?:^|/)(?:{_FILESYSTEM_URL_ROOT_PATTERN})(?:/|$)[^\s<>\"`]*")
_URL_LABELED_POSIX_PATH = re.compile(
    r":[\\/]+"
    rf"(?:{_FILESYSTEM_URL_ROOT_PATTERN})(?:/|$)",
)
_POSIX_PATH = re.compile(rf"(?<![<\w])/{{1,2}}(?!/)(?![.,;:!?\)}}](?:\s|$)){_UNQUOTED_PATH_PART}")
_TILDE_PATH = re.compile(rf"(?<!\w)~[A-Za-z0-9._-]*/{_UNQUOTED_PATH_PART}")
_RELATIVE_PATH = re.compile(rf"(?<![\w.])(?:(?:\.\./)+|\./){_UNQUOTED_PATH_PART}")
_WINDOWS_PATH = re.compile(rf"(?<!\w)[A-Za-z]:[\\/]{_UNQUOTED_PATH_PART}")
_UNC_AUTHORITY = r"[^\\/\s<>\"'`]+"
_UNC_PATH = re.compile(
    rf"(?<!\\)(?:\\\\\?\\UNC\\{_UNC_AUTHORITY}\\{_UNQUOTED_PATH_PART}|"
    rf"\\\\{_UNC_AUTHORITY}\\{_UNQUOTED_PATH_PART})",
    re.IGNORECASE,
)
_QUOTED_PATH_ANCHOR = re.compile(
    rf"(?<!\w)(?:file:(?://)?|[A-Za-z]:[\\/]|"
    rf"\\\\\?\\UNC\\(?:{_UNC_AUTHORITY}\\)?|"
    rf"\\\\(?:{_UNC_AUTHORITY}\\)?|"
    rf"(?:(?:\.\./)+|\./)|~[A-Za-z0-9._-]*/|/{{1,2}})(?=[\"'`])",
    re.IGNORECASE,
)
_LABELED_PATH_PREFIX = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,63}:[\\/]")
_LABELED_VALUE_PREFIX = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,63}(?:=|:(?![\\/]))")
_PERCENT_ESCAPE = re.compile(r"%[0-9A-F]{2}", re.IGNORECASE)
_TRAILING_URL_PUNCTUATION = ".,;:!?)}]"
_TILDE_PATH_PREFIX = re.compile(r"^~[A-Za-z0-9._-]*/")
_CODE_OPEN = re.compile(r"<code(?:[ \t]+[^<>\r\n]*)?>", re.IGNORECASE)
_CODE_CLOSE = re.compile(r"</code[ \t]*>", re.IGNORECASE)
_MARKDOWN_FENCE_OPEN = re.compile(r"(?m)^[ \t]{0,3}(?P<fence>`{3,}|~{3,})[^\r\n]*\r?\n")
_MARKDOWN_FENCE_CLOSE = re.compile(r"(?m)^[ \t]{0,3}(?P<fence>`{3,}|~{3,})[ \t]*(?:\r?\n|\Z)")
_CLOSING_DELIMITER_BOUNDARY = frozenset(".,;:!?)}]>")
_PATH_DELIMITERS = frozenset("\"'`")
_PATH_SEPARATORS = frozenset("/\\")
_SECRET_MARKER = "[mh:s]"
_CREDENTIAL_MARKER = "[mh:c]"
_PRIVATE_KEY_MARKER = "[mh:k]"
_URL_MARKER = "[mh:u]"
_PATH_MARKER = "[mh:p]"


@dataclass(frozen=True, slots=True)
class RedactionResult:
    """One privacy-safe text result plus non-sensitive rule-category counts."""

    value: str
    counts: dict[str, int]

    def __post_init__(self) -> None:
        object.__setattr__(self, "counts", freeze_dict(dict(self.counts)))

    @property
    def changed(self) -> bool:
        return bool(self.counts)

    @property
    def total(self) -> int:
        return sum(self.counts.values())


def _increment(counts: dict[str, int], category: str, amount: int = 1) -> None:
    counts[category] = counts.get(category, 0) + amount


def _split_contextual_candidate(match: re.Match[str]) -> tuple[str, str]:
    """Separate prose punctuation and a paired single quote from one marked value."""

    candidate = match.group(0)
    core = candidate.rstrip(_TRAILING_URL_PUNCTUATION)
    trailing = candidate[len(core) :]
    preceding = match.string[match.start() - 1] if match.start() else ""
    if preceding == "'" and core.endswith("'"):
        core = core[:-1]
        trailing = "'" + trailing
    return core, trailing


def _is_escaped(value: str, index: int) -> bool:
    backslashes = 0
    cursor = index - 1
    while cursor >= 0 and value[cursor] == "\\":
        backslashes += 1
        cursor -= 1
    return backslashes % 2 == 1


def _has_closing_boundary(value: str, index: int) -> bool:
    return (
        index >= len(value) or value[index].isspace() or value[index] in _CLOSING_DELIMITER_BOUNDARY
    )


def _has_local_path_prefix(value: str, start: int = 0) -> bool:
    limit = len(value)
    while start < limit and value[start] in " \t\r\n":
        start += 1
    if start >= limit:
        return False
    if value[start : start + 5].casefold() == "file:":
        return True
    if value.startswith(("../", "./", "\\/"), start):
        return True
    if value[start] == "/":
        return start + 1 < limit and value[start + 1] not in " \t\r\n"
    if value.startswith("\\\\", start):
        return True
    if start + 2 < limit and value[start].isalpha() and value[start + 1] == ":":
        return value[start + 2] in "/\\"
    prefix = value[start : min(limit, start + 132)]
    return _TILDE_PATH_PREFIX.match(prefix) is not None


def _pseudonymize_marked_path(
    value: str,
    *,
    pseudonymize: Callable[[str], str],
) -> str:
    leading_length = len(value) - len(value.lstrip(" \t\r\n"))
    trailing_start = len(value.rstrip(" \t\r\n"))
    candidate = value[leading_length:trailing_start]
    return f"{value[:leading_length]}{pseudonymize(candidate)}{value[trailing_start:]}"


def _protected_span_end(
    index: int,
    *,
    spans: tuple[tuple[int, int], ...],
    starts: tuple[int, ...],
) -> int | None:
    position = bisect_right(starts, index) - 1
    if position >= 0 and index < spans[position][1]:
        return spans[position][1]
    return None


def _raw_path_spans(value: str) -> tuple[tuple[int, int], ...]:
    candidates: list[tuple[int, int]] = []
    candidates.extend(match.span() for match in _QUOTED_PATH_ANCHOR.finditer(value))
    for pattern in (
        _FILE_URI,
        _UNC_PATH,
        _WINDOWS_PATH,
        _RELATIVE_PATH,
        _TILDE_PATH,
        _POSIX_PATH,
    ):
        for match in pattern.finditer(value):
            core, _ = _split_contextual_candidate(match)
            if core.endswith("'"):
                core = core[:-1]
            if core:
                candidates.append((match.start(), match.start() + len(core)))
    if not candidates:
        return ()
    merged: list[tuple[int, int]] = []
    for start, end in sorted(candidates):
        if merged and start <= merged[-1][1]:
            previous_start, previous_end = merged[-1]
            merged[-1] = (previous_start, max(previous_end, end))
        else:
            merged.append((start, end))
    return tuple(merged)


def _path_delimiter_length(value: str, index: int) -> int:
    if value[index] != "`":
        return 1
    run_end = index + 1
    while run_end < len(value) and value[run_end] == "`":
        run_end += 1
    return run_end - index


def _is_native_windows_path(value: str, start: int) -> bool:
    return value.startswith("\\\\", start) or (
        start + 2 < len(value)
        and value[start].isalpha()
        and value[start + 1] == ":"
        and value[start + 2] in _PATH_SEPARATORS
    )


def _is_contextual_path_delimiter(
    value: str,
    *,
    index: int,
    delimiter_length: int,
    path_start: int,
    native_windows: bool,
) -> bool:
    before = value[index - 1] if index > path_start else ""
    after_index = index + delimiter_length
    after = value[after_index] if after_index < len(value) else ""
    return after in _PATH_SEPARATORS or before == "/" or (before == "\\" and native_windows)


def _find_path_segment_close(
    value: str,
    *,
    opening: int,
    delimiter_length: int,
    allow_direct: bool = False,
) -> int | None:
    delimiter = value[opening]
    cursor = opening + delimiter_length
    line_end = value.find("\n", cursor)
    if line_end < 0:
        line_end = len(value)
    direct_close: int | None = None
    while True:
        closing = value.find(delimiter, cursor, line_end)
        if closing < 0:
            return direct_close
        close_end = closing + 1
        if delimiter == "`":
            while close_end < line_end and value[close_end] == "`":
                close_end += 1
            if close_end - closing != delimiter_length:
                cursor = close_end
                continue
        if delimiter in {'"', "`"} and _is_escaped(value, closing):
            cursor = close_end
            continue
        if (
            close_end >= len(value)
            or value[close_end] in _PATH_SEPARATORS | _PATH_DELIMITERS
            or _has_closing_boundary(value, close_end)
        ):
            return close_end
        if allow_direct and direct_close is None:
            direct_close = close_end
        cursor = close_end


def _find_contextual_path_delimiter(
    value: str,
    *,
    path_start: int,
    search_start: int,
    search_end: int,
    native_windows: bool,
) -> tuple[int, int] | None:
    cursor = search_start
    while cursor < search_end:
        if value[cursor] not in _PATH_DELIMITERS:
            cursor += 1
            continue
        delimiter_length = _path_delimiter_length(value, cursor)
        contextual = _is_contextual_path_delimiter(
            value,
            index=cursor,
            delimiter_length=delimiter_length,
            path_start=path_start,
            native_windows=native_windows,
        )
        if contextual:
            return cursor, delimiter_length
        close_end = _find_path_segment_close(
            value,
            opening=cursor,
            delimiter_length=delimiter_length,
            allow_direct=True,
        )
        if close_end is None:
            if value[cursor] in '"`' or _has_unmarked_path_suffix(value, search_end - 1):
                return cursor, delimiter_length
            cursor += delimiter_length
            continue
        candidate = value[cursor + delimiter_length : close_end - delimiter_length]
        if value[cursor] in '"`' or any(
            character.isspace() or character in _PATH_SEPARATORS for character in candidate
        ):
            return cursor, delimiter_length
        cursor += delimiter_length
    return None


def _has_unmarked_path_suffix(value: str, start: int) -> bool:
    cursor = start
    crossed_line = False
    while cursor < len(value) and value[cursor].isspace():
        crossed_line = crossed_line or value[cursor] in "\n\u2028\u2029"
        cursor += 1
    skipped_delimiter = False
    while cursor < len(value) and value[cursor] in '"`<>':
        skipped_delimiter = True
        cursor += 1
    if cursor >= len(value):
        return False
    if _has_local_path_prefix(value, cursor):
        return skipped_delimiter
    if _LABELED_PATH_PREFIX.match(value, cursor) is not None:
        return False
    if crossed_line:
        return True
    token_end = cursor
    while token_end < len(value) and not value[token_end].isspace():
        token_end += 1
    for character in value[cursor:token_end]:
        if character in _PATH_SEPARATORS:
            return True
    return False


def _raise_ambiguous_path_continuation() -> NoReturn:
    raise PrivacyError(
        "MH_PRIVACY_REDACT_DELIMITER",
        "marked local path has an ambiguous whitespace continuation",
    )


def _protected_placeholder_end(value: str, *, start: int, prefix: str) -> int | None:
    if not prefix or not value.startswith(prefix, start):
        return None
    cursor = start + len(prefix)
    digit_start = cursor
    while cursor < len(value) and value[cursor].isdigit():
        cursor += 1
    if cursor == digit_start or not value.startswith("END", cursor):
        return None
    return cursor + 3


def _find_unquoted_path_continuation_end(
    value: str,
    start: int,
    *,
    protected_placeholder_prefix: str = "",
) -> int | None:
    if start >= len(value) or not value[start].isspace() or value[start] == "\n":
        return None
    cursor = start
    saw_unseparated_token = False
    pending_unseparated_token = False
    continuation_end: int | None = None
    while cursor < len(value):
        while cursor < len(value) and value[cursor].isspace() and value[cursor] != "\n":
            cursor += 1
        if _has_local_path_prefix(value, cursor):
            if saw_unseparated_token:
                _raise_ambiguous_path_continuation()
            break
        if cursor < len(value) and value[cursor] == "\n":
            if saw_unseparated_token:
                _raise_ambiguous_path_continuation()
            break
        if (
            cursor >= len(value)
            or value[cursor] in "<>\"'`"
            or _LABELED_PATH_PREFIX.match(value, cursor) is not None
            or _LABELED_VALUE_PREFIX.match(value, cursor) is not None
        ):
            break
        token_start = cursor
        while cursor < len(value) and not value[cursor].isspace() and value[cursor] not in "<>\"'`":
            cursor += 1
        token_end = cursor
        candidate_end = token_end
        while candidate_end > token_start and value[candidate_end - 1] in _TRAILING_URL_PUNCTUATION:
            candidate_end -= 1
        if protected_placeholder_prefix:
            placeholder_start = value.find(
                protected_placeholder_prefix,
                token_start,
                candidate_end,
            )
            if placeholder_start >= 0:
                placeholder_end = _protected_placeholder_end(
                    value,
                    start=placeholder_start,
                    prefix=protected_placeholder_prefix,
                )
                if (
                    placeholder_start != token_start
                    or placeholder_end != candidate_end
                    or saw_unseparated_token
                    or pending_unseparated_token
                ):
                    _raise_ambiguous_path_continuation()
                break
        has_separator = _token_has_path_separator(value[token_start:candidate_end])
        if has_separator:
            if continuation_end is None and saw_unseparated_token:
                _raise_ambiguous_path_continuation()
            continuation_end = candidate_end
            pending_unseparated_token = False
        elif continuation_end is None:
            saw_unseparated_token = True
        else:
            pending_unseparated_token = True
        if candidate_end < token_end:
            break
    if pending_unseparated_token:
        _raise_ambiguous_path_continuation()
    return continuation_end


def _is_closing_outer_path_delimiter(
    *,
    path_start: int,
    closing: int,
    delimiter_length: int,
    value: str,
    first_openers: dict[tuple[str, int], int],
) -> bool:
    opening = first_openers.get((value[closing], delimiter_length))
    return opening is not None and opening < path_start


def _first_outer_path_delimiter_openers(value: str) -> dict[tuple[str, int], int]:
    first_openers: dict[tuple[str, int], int] = {}
    cursor = 0
    while cursor < len(value):
        delimiter = value[cursor]
        if delimiter not in _PATH_DELIMITERS:
            cursor += 1
            continue
        if delimiter != "`":
            if _has_local_path_prefix(value, cursor + 1):
                first_openers.setdefault((delimiter, 1), cursor)
            cursor += 1
            continue
        run_end = cursor + 1
        while run_end < len(value) and value[run_end] == delimiter:
            run_end += 1
        if _has_local_path_prefix(value, run_end):
            for opening in range(cursor, run_end):
                first_openers.setdefault((delimiter, run_end - opening), opening)
        cursor = run_end
    return first_openers


def _raise_unclosed_marked_path() -> NoReturn:
    raise PrivacyError(
        "MH_PRIVACY_REDACT_DELIMITER",
        "marked local path has no closing delimiter",
    )


def _extend_quoted_path_candidate(
    value: str,
    *,
    path_start: int,
    close_end: int,
    native_windows: bool,
) -> int:
    if close_end >= len(value) or _has_closing_boundary(value, close_end):
        return close_end
    cursor = close_end
    candidate_end = close_end
    while cursor < len(value):
        character = value[cursor]
        if character == "\n" or character.isspace() or character in "<>":
            break
        if character == "\\" and cursor + 1 < len(value) and value[cursor + 1] in " \t":
            cursor += 2
            candidate_end = cursor
            continue
        if character in _PATH_DELIMITERS:
            delimiter_length = _path_delimiter_length(value, cursor)
            opening = _find_contextual_path_delimiter(
                value,
                path_start=path_start,
                search_start=cursor,
                search_end=cursor + delimiter_length,
                native_windows=native_windows,
            )
            if opening is not None:
                next_close = _find_path_segment_close(
                    value,
                    opening=cursor,
                    delimiter_length=delimiter_length,
                    allow_direct=True,
                )
                if next_close is None:
                    _raise_unclosed_marked_path()
                cursor = next_close
                candidate_end = next_close
                continue
            if character in '"`':
                if _has_unmarked_path_suffix(value, cursor):
                    _raise_unclosed_marked_path()
                break
        cursor += 1
        candidate_end = cursor
    while candidate_end > close_end and value[candidate_end - 1] in _TRAILING_URL_PUNCTUATION:
        candidate_end -= 1
    return candidate_end


def _redact_raw_path_continuations(
    value: str,
    *,
    pseudonymize: Callable[[str], str],
    protected_placeholder_prefix: str = "",
) -> tuple[str, int]:
    output: list[str] = []
    cursor = 0
    count = 0
    first_openers = _first_outer_path_delimiter_openers(value)
    for start, end in _raw_path_spans(value):
        if start < cursor or (start > 0 and value[start - 1] in "\"'`"):
            continue
        native_windows = _is_native_windows_path(value, start)
        opening = _find_contextual_path_delimiter(
            value,
            path_start=start,
            search_start=start,
            search_end=min(len(value), end + 1),
            native_windows=native_windows,
        )
        if opening is None:
            continuation_end = _find_unquoted_path_continuation_end(
                value,
                end,
                protected_placeholder_prefix=protected_placeholder_prefix,
            )
            if continuation_end is not None:
                output.append(value[cursor:start])
                output.append(pseudonymize(value[start:continuation_end]))
                cursor = continuation_end
                count += 1
            continue
        opening_index, delimiter_length = opening
        if opening_index >= end and _is_closing_outer_path_delimiter(
            path_start=start,
            closing=opening_index,
            delimiter_length=delimiter_length,
            value=value,
            first_openers=first_openers,
        ):
            continue
        close_end = _find_path_segment_close(
            value,
            opening=opening_index,
            delimiter_length=delimiter_length,
            allow_direct=True,
        )
        if close_end is None:
            if value[opening_index] in '"`' or _has_unmarked_path_suffix(value, end):
                _raise_unclosed_marked_path()
            continue
        continuation_end = _extend_quoted_path_candidate(
            value,
            path_start=start,
            close_end=close_end,
            native_windows=native_windows,
        )
        output.append(value[cursor:start])
        output.append(pseudonymize(value[start:continuation_end]))
        cursor = continuation_end
        count += 1
    if not count:
        return value, 0
    output.append(value[cursor:])
    return "".join(output), count


def _find_independent_backtick_path_end(value: str, *, opening: int) -> int | None:
    delimiter_length = _path_delimiter_length(value, opening)
    content_start = opening + delimiter_length
    if not _has_local_path_prefix(value, content_start):
        return None
    close_end = _find_path_segment_close(
        value,
        opening=opening,
        delimiter_length=delimiter_length,
    )
    if close_end is None:
        return None
    outer_quote = value[opening - 1 : opening]
    if outer_quote not in {'"', "'"}:
        return close_end if _has_closing_boundary(value, close_end) else None
    if value[close_end : close_end + 1] != outer_quote or not _has_closing_boundary(
        value, close_end + 1
    ):
        return None
    return close_end + 1


@dataclass(frozen=True, slots=True)
class _BacktickRun:
    start: int
    end: int
    length: int
    line: int
    escaped: bool


@dataclass(frozen=True, slots=True)
class _OuterWrapperSuffixIndex:
    separators: tuple[int, ...]
    closers: dict[tuple[int, str], tuple[int, ...]]

    def has_ambiguous_suffix(
        self,
        *,
        start: int,
        delimiter_length: int,
        outer_wrapper_quote: str,
    ) -> bool:
        separator_index = bisect_left(self.separators, start)
        if separator_index >= len(self.separators):
            return False
        separator = self.separators[separator_index]
        closers = self.closers.get((delimiter_length, outer_wrapper_quote), ())
        return bisect_right(closers, separator) < len(closers)


def _backtick_runs(value: str) -> tuple[_BacktickRun, ...]:
    runs: list[_BacktickRun] = []
    cursor = 0
    line = 0
    while cursor < len(value):
        if value[cursor] == "\n":
            line += 1
            cursor += 1
            continue
        if value[cursor] != "`":
            cursor += 1
            continue
        end = cursor + 1
        while end < len(value) and value[end] == "`":
            end += 1
        runs.append(
            _BacktickRun(
                start=cursor,
                end=end,
                length=end - cursor,
                line=line,
                escaped=_is_escaped(value, cursor),
            )
        )
        cursor = end
    return tuple(runs)


def _build_outer_wrapper_suffix_index(
    value: str,
    *,
    protected_spans: tuple[tuple[int, int], ...],
    protected_starts: tuple[int, ...],
) -> _OuterWrapperSuffixIndex:
    runs = _backtick_runs(value)
    run_by_start = {run.start: run for run in runs}
    next_close: dict[tuple[int, int], int] = {}
    independent_close: dict[int, int] = {}
    for run in reversed(runs):
        key = (run.line, run.length)
        close_end = next_close.get(key)
        if close_end is not None and _has_local_path_prefix(value, run.end):
            outer_quote = value[run.start - 1 : run.start]
            if outer_quote not in {'"', "'"}:
                if _has_closing_boundary(value, close_end):
                    independent_close[run.start] = close_end
            elif value[close_end : close_end + 1] == outer_quote and _has_closing_boundary(
                value,
                close_end + 1,
            ):
                independent_close[run.start] = close_end + 1
        if not run.escaped and (
            run.end >= len(value)
            or value[run.end] in _PATH_SEPARATORS | _PATH_DELIMITERS
            or _has_closing_boundary(value, run.end)
        ):
            next_close[key] = run.end

    separators: list[int] = []
    closers: dict[tuple[int, str], list[int]] = {}
    cursor = 0
    while cursor < len(value):
        protected_end = _protected_span_end(
            cursor,
            spans=protected_spans,
            starts=protected_starts,
        )
        if protected_end is not None:
            cursor = protected_end
            continue
        current_run = run_by_start.get(cursor)
        if current_run is not None:
            independent_end = independent_close.get(cursor)
            if independent_end is not None:
                cursor = independent_end
                continue
            outer_quote = value[current_run.end : current_run.end + 1]
            if (
                outer_quote in {'"', "'"}
                and (current_run.length > 1 or not current_run.escaped)
                and _has_closing_boundary(value, current_run.end + 1)
            ):
                closers.setdefault((current_run.length, outer_quote), []).append(current_run.start)
            cursor = current_run.end
            continue
        if value[cursor] in _PATH_SEPARATORS:
            separators.append(cursor)
        cursor += 1
    return _OuterWrapperSuffixIndex(
        separators=tuple(separators),
        closers={key: tuple(positions) for key, positions in closers.items()},
    )


def _find_closing_delimiter(
    value: str,
    *,
    opening_quote: int,
    quote_character: str,
    delimiter_length: int,
    escaped_delimiter: bool,
    protected_spans: tuple[tuple[int, int], ...],
    protected_starts: tuple[int, ...],
    suffix_index: _OuterWrapperSuffixIndex,
) -> tuple[int, int] | None:
    cursor = opening_quote + delimiter_length
    line_end = value.find("\n", cursor)
    if line_end < 0:
        line_end = len(value)
    outer_wrapper_quote = value[opening_quote - 1 : opening_quote]
    if outer_wrapper_quote not in {'"', "'"}:
        outer_wrapper_quote = ""
    while True:
        closing_quote = value.find(quote_character, cursor, line_end)
        if closing_quote < 0:
            return None
        protected_end = _protected_span_end(
            closing_quote,
            spans=protected_spans,
            starts=protected_starts,
        )
        if protected_end is not None:
            cursor = protected_end
            continue
        if quote_character == "`":
            run_end = closing_quote + 1
            while run_end < len(value) and value[run_end] == "`":
                run_end += 1
            is_candidate = run_end - closing_quote == delimiter_length and (
                delimiter_length > 1 or not _is_escaped(value, closing_quote)
            )
            closes_outer_quote_wrapper = (
                is_candidate
                and bool(outer_wrapper_quote)
                and value[run_end : run_end + 1] == outer_wrapper_quote
                and _has_closing_boundary(value, run_end + 1)
            )
            if closes_outer_quote_wrapper and suffix_index.has_ambiguous_suffix(
                start=run_end + 1,
                delimiter_length=delimiter_length,
                outer_wrapper_quote=outer_wrapper_quote,
            ):
                _raise_unclosed_marked_path()
            if is_candidate:
                following = value[run_end : run_end + 1]
                if following in {'"', "'"} and not closes_outer_quote_wrapper:
                    _raise_unclosed_marked_path()
                if following == "<" and not value.startswith("</", run_end):
                    _raise_unclosed_marked_path()
                if (
                    _has_closing_boundary(value, run_end)
                    or closes_outer_quote_wrapper
                    or value.startswith("</", run_end)
                ):
                    return closing_quote, run_end
            cursor = run_end
            continue
        escaped = _is_escaped(value, closing_quote)
        if escaped_delimiter:
            if escaped and _has_closing_boundary(value, closing_quote + 1):
                return closing_quote - 1, closing_quote + 1
        elif not escaped and _has_closing_boundary(value, closing_quote + 1):
            return closing_quote, closing_quote + 1
        cursor = closing_quote + 1


def _redact_delimited_paths(
    value: str,
    *,
    pseudonymize: Callable[[str], str],
    protected_placeholder_prefix: str = "",
) -> tuple[str, int]:
    count = 0
    fence_output: list[str] = []
    fence_cursor = 0
    fence_search = 0
    while fence_open := _MARKDOWN_FENCE_OPEN.search(value, fence_search):
        opening = fence_open.group("fence")
        fence_close = next(
            (
                candidate
                for candidate in _MARKDOWN_FENCE_CLOSE.finditer(value, fence_open.end())
                if candidate.group("fence")[0] == opening[0]
                and len(candidate.group("fence")) >= len(opening)
            ),
            None,
        )
        if fence_close is None:
            if _has_local_path_prefix(value, fence_open.end()):
                raise PrivacyError(
                    "MH_PRIVACY_REDACT_DELIMITER",
                    "marked local path has no closing delimiter",
                )
            break
        candidate = value[fence_open.end() : fence_close.start()]
        fence_output.append(value[fence_cursor : fence_open.end()])
        if _has_local_path_prefix(candidate):
            fence_output.append(_pseudonymize_marked_path(candidate, pseudonymize=pseudonymize))
            count += 1
        else:
            fence_output.append(candidate)
        fence_output.append(value[fence_close.start() : fence_close.end()])
        fence_cursor = fence_close.end()
        fence_search = fence_cursor
    fence_output.append(value[fence_cursor:])
    value = "".join(fence_output)

    code_output: list[str] = []
    code_cursor = 0
    code_search = 0
    while code_open := _CODE_OPEN.search(value, code_search):
        code_close = _CODE_CLOSE.search(value, code_open.end())
        if code_close is None:
            if _has_local_path_prefix(value, code_open.end()):
                raise PrivacyError(
                    "MH_PRIVACY_REDACT_DELIMITER",
                    "marked local path has no closing delimiter",
                )
            break
        candidate = value[code_open.end() : code_close.start()]
        code_output.append(value[code_cursor : code_open.end()])
        if _has_local_path_prefix(candidate):
            code_output.append(_pseudonymize_marked_path(candidate, pseudonymize=pseudonymize))
            count += 1
        else:
            code_output.append(candidate)
        code_output.append(value[code_close.start() : code_close.end()])
        code_cursor = code_close.end()
        code_search = code_cursor
    code_output.append(value[code_cursor:])
    value = "".join(code_output)
    value, continuation_count = _redact_raw_path_continuations(
        value,
        pseudonymize=pseudonymize,
        protected_placeholder_prefix=protected_placeholder_prefix,
    )
    count += continuation_count
    protected_spans = _raw_path_spans(value)
    protected_starts = tuple(start for start, _ in protected_spans)
    suffix_index = _build_outer_wrapper_suffix_index(
        value,
        protected_spans=protected_spans,
        protected_starts=protected_starts,
    )
    output: list[str] = []
    cursor = 0
    search = 0
    while search < len(value):
        quote_character = value[search]
        if quote_character not in "\"'`":
            search += 1
            continue
        protected_end = _protected_span_end(
            search,
            spans=protected_spans,
            starts=protected_starts,
        )
        if protected_end is not None:
            search = protected_end
            continue
        delimiter_length = 1
        if quote_character == "`":
            while (
                search + delimiter_length < len(value) and value[search + delimiter_length] == "`"
            ):
                delimiter_length += 1
        escaped_delimiter = quote_character == '"' and _is_escaped(value, search)
        content_start = search + delimiter_length
        if not _has_local_path_prefix(value, content_start):
            search += delimiter_length
            continue
        closing = _find_closing_delimiter(
            value,
            opening_quote=search,
            quote_character=quote_character,
            delimiter_length=delimiter_length,
            escaped_delimiter=escaped_delimiter,
            protected_spans=protected_spans,
            protected_starts=protected_starts,
            suffix_index=suffix_index,
        )
        if closing is None:
            raise PrivacyError(
                "MH_PRIVACY_REDACT_DELIMITER",
                "marked local path has no closing delimiter",
            )
        content_end, close_end = closing
        candidate = value[content_start:content_end]
        output.extend(
            (
                value[cursor:content_start],
                _pseudonymize_marked_path(candidate, pseudonymize=pseudonymize),
                value[content_end:close_end],
            )
        )
        count += 1
        cursor = close_end
        search = close_end
    output.append(value[cursor:])
    return "".join(output), count


def _normalize_text(value: str) -> tuple[str, int]:
    if type(value) is not str:
        raise PrivacyError("MH_PRIVACY_REDACT_TYPE", "redaction input must be text")
    if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
        raise PrivacyError(
            "MH_PRIVACY_REDACT_UNICODE",
            "redaction input contains unsupported Unicode",
        )
    normalized = unicodedata.normalize("NFC", value.replace("\r\n", "\n").replace("\r", "\n"))
    encoded = normalized.encode("utf-8")
    if len(encoded) > MAX_REDACTION_INPUT_BYTES:
        raise PrivacyError(
            "MH_PRIVACY_REDACT_INPUT_LARGE",
            "redaction input exceeds the raw byte bound",
        )
    removed_controls = 0
    cleaned: list[str] = []
    for character in normalized:
        codepoint = ord(character)
        if character in "\n\t" or (
            codepoint >= 0x20 and codepoint != 0x7F and unicodedata.category(character) != "Cf"
        ):
            cleaned.append(character)
        else:
            removed_controls += 1
    return "".join(cleaned), removed_controls


def _validate_known_secret(value: str) -> str:
    if type(value) is not str:
        raise PrivacyError(
            "MH_PRIVACY_SECRET_TYPE",
            "known redaction values must be text",
        )
    if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
        raise PrivacyError(
            "MH_PRIVACY_SECRET_UNICODE",
            "known redaction value contains unsupported Unicode",
        )
    normalized = unicodedata.normalize("NFC", value)
    encoded = normalized.encode("utf-8")
    if not MIN_KNOWN_SECRET_BYTES <= len(encoded) <= MAX_KNOWN_SECRET_BYTES:
        raise PrivacyError(
            "MH_PRIVACY_SECRET_LENGTH",
            "known redaction value is outside the credential byte bounds",
        )
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in normalized):
        raise PrivacyError(
            "MH_PRIVACY_SECRET_CONTROL",
            "known redaction value contains unsupported controls",
        )
    return normalized


@dataclass(frozen=True, slots=True)
class _MappedTextView:
    text: str
    starts: tuple[int, ...]
    ends: tuple[int, ...]


def _is_ascii_hex(value: int) -> bool:
    return 48 <= value <= 57 or 65 <= value <= 70 or 97 <= value <= 102


def _token_has_path_separator(value: str) -> bool:
    if any(character in _PATH_SEPARATORS for character in value):
        return True
    if "%" not in value:
        return False
    first = unquote_to_bytes(value)
    second = unquote_to_bytes(first)
    return b"/" in first or b"\\" in first or b"/" in second or b"\\" in second


def _without_ascii_whitespace_view(value: str) -> _MappedTextView:
    text: list[str] = []
    starts: list[int] = []
    ends: list[int] = []
    for index, character in enumerate(value):
        if character in " \t\r\n":
            continue
        text.append(character)
        starts.append(index)
        ends.append(index + 1)
    return _MappedTextView("".join(text), tuple(starts), tuple(ends))


def _base64_encoded_secret_spans(
    value: str,
    secrets: tuple[bytes, ...],
) -> tuple[tuple[int, int], ...]:
    """Find standard/base64url aliases, including MIME whitespace and pad bits."""

    if not secrets:
        return ()
    view = _without_ascii_whitespace_view(value)
    alphabets = (
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
    )
    candidate_ends: dict[int, int] = {}
    for secret in secrets:
        for urlsafe, alphabet in ((False, alphabets[0]), (True, alphabets[1])):
            encode = base64.urlsafe_b64encode if urlsafe else base64.b64encode
            encoded = encode(secret).decode("ascii")
            unpadded = encoded.rstrip("=")
            prefix = unpadded[:-1]
            canonical_index = alphabet.index(unpadded[-1])
            unused_bits = {0: 0, 1: 4, 2: 2}[len(secret) % 3]
            first_index = (canonical_index >> unused_bits) << unused_bits
            allowed_final = frozenset(
                alphabet[index] for index in range(first_index, first_index + (1 << unused_bits))
            )
            padding = len(encoded) - len(unpadded)
            search_start = 0
            while True:
                found = view.text.find(prefix, search_start)
                if found < 0:
                    break
                final_index = found + len(prefix)
                if final_index < len(view.text) and view.text[final_index] in allowed_final:
                    normalized_end = final_index + 1
                    available_padding = 0
                    while (
                        available_padding < padding
                        and normalized_end + available_padding < len(view.text)
                        and view.text[normalized_end + available_padding] == "="
                    ):
                        available_padding += 1
                    normalized_end += available_padding
                    raw_start = view.starts[found]
                    raw_end = view.ends[normalized_end - 1]
                    candidate_ends[raw_start] = max(
                        candidate_ends.get(raw_start, 0),
                        raw_end,
                    )
                search_start = found + 1

    merged: list[tuple[int, int]] = []
    for start, end in sorted(candidate_ends.items()):
        if merged and start < merged[-1][1]:
            previous_start, previous_end = merged[-1]
            merged[-1] = (previous_start, max(previous_end, end))
        else:
            merged.append((start, end))
    return tuple(merged)


def _first_mapped_text_view(value: str) -> _MappedTextView:
    return _MappedTextView(
        value,
        tuple(range(len(value))),
        tuple(index + 1 for index in range(len(value))),
    )


_JSON_SIMPLE_ESCAPES = {
    '"': '"',
    "\\": "\\",
    "/": "/",
    "b": "\b",
    "f": "\f",
    "n": "\n",
    "r": "\r",
    "t": "\t",
}


def _next_json_decoded_view(value: _MappedTextView) -> _MappedTextView:
    output: list[str] = []
    starts: list[int] = []
    ends: list[int] = []
    cursor = 0
    while cursor < len(value.text):
        decoded = ""
        consumed = 1
        if value.text[cursor] == "\\" and cursor + 1 < len(value.text):
            escape = value.text[cursor + 1]
            if escape in _JSON_SIMPLE_ESCAPES:
                decoded = _JSON_SIMPLE_ESCAPES[escape]
                consumed = 2
            elif escape == "u" and cursor + 6 <= len(value.text):
                encoded = value.text[cursor + 2 : cursor + 6]
                if len(encoded) == 4 and all(_is_ascii_hex(ord(item)) for item in encoded):
                    codepoint = int(encoded, 16)
                    if 0xD800 <= codepoint <= 0xDBFF and cursor + 12 <= len(value.text):
                        low_prefix = value.text[cursor + 6 : cursor + 8]
                        low_encoded = value.text[cursor + 8 : cursor + 12]
                        if low_prefix == "\\u" and all(
                            _is_ascii_hex(ord(item)) for item in low_encoded
                        ):
                            low = int(low_encoded, 16)
                            if 0xDC00 <= low <= 0xDFFF:
                                codepoint = 0x10000 + ((codepoint - 0xD800) << 10) + (low - 0xDC00)
                                decoded = chr(codepoint)
                                consumed = 12
                    elif not 0xD800 <= codepoint <= 0xDFFF:
                        decoded = chr(codepoint)
                        consumed = 6
        if not decoded:
            decoded = value.text[cursor]
        raw_start = value.starts[cursor]
        raw_end = value.ends[cursor + consumed - 1]
        output.extend(decoded)
        starts.extend([raw_start] * len(decoded))
        ends.extend([raw_end] * len(decoded))
        cursor += consumed
    return _MappedTextView("".join(output), tuple(starts), tuple(ends))


_HTML_ENTITY = re.compile(
    r"(?:&#[xX][0-9A-Fa-f]{1,6}(?![0-9A-Fa-f]);?"
    r"|&#[0-9]{1,7}(?![0-9]);?"
    r"|&[A-Za-z][A-Za-z0-9]{1,31}(?![A-Za-z0-9]);?)"
)


def _next_html_decoded_view(value: _MappedTextView) -> _MappedTextView:
    output: list[str] = []
    starts: list[int] = []
    ends: list[int] = []
    cursor = 0
    while cursor < len(value.text):
        entity = _HTML_ENTITY.match(value.text, cursor)
        decoded = html.unescape(entity.group(0)) if entity is not None else ""
        if entity is None or decoded == entity.group(0):
            decoded = value.text[cursor]
            consumed = 1
        else:
            consumed = entity.end() - cursor
        raw_start = value.starts[cursor]
        raw_end = value.ends[cursor + consumed - 1]
        output.extend(decoded)
        starts.extend([raw_start] * len(decoded))
        ends.extend([raw_end] * len(decoded))
        cursor += consumed
    return _MappedTextView("".join(output), tuple(starts), tuple(ends))


def _next_percent_text_view(
    value: _MappedTextView,
    *,
    plus_as_space: bool,
) -> _MappedTextView:
    output: list[str] = []
    starts: list[int] = []
    ends: list[int] = []
    cursor = 0
    while cursor < len(value.text):
        if value.text[cursor] == "%":
            run_end = cursor
            units: list[tuple[int, int, int]] = []
            while (
                run_end + 2 < len(value.text)
                and value.text[run_end] == "%"
                and all(_is_ascii_hex(ord(item)) for item in value.text[run_end + 1 : run_end + 3])
            ):
                units.append((int(value.text[run_end + 1 : run_end + 3], 16), run_end, run_end + 3))
                run_end += 3
            if units:
                _extend_mapped_utf8_units(
                    value,
                    units=units,
                    output=output,
                    starts=starts,
                    ends=ends,
                )
                cursor = run_end
                continue
        decoded = " " if plus_as_space and value.text[cursor] == "+" else value.text[cursor]
        output.append(decoded)
        starts.append(value.starts[cursor])
        ends.append(value.ends[cursor])
        cursor += 1
    return _MappedTextView("".join(output), tuple(starts), tuple(ends))


_BASE64_TEXT_TOKEN = re.compile(
    r"(?<![A-Za-z0-9+/_-])"
    r"[A-Za-z0-9+/_-](?:[ \t\r\n]*[A-Za-z0-9+/_-]){10,}"
    r"(?:(?:[ \t\r\n]*=){1,2})?"
    r"(?![A-Za-z0-9+/_=-])"
)
_HEX_TEXT_TOKEN = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{16,}(?![0-9A-Fa-f])")


def _utf8_unit_length(first_byte: int) -> int:
    if first_byte <= 0x7F:
        return 1
    if 0xC2 <= first_byte <= 0xDF:
        return 2
    if 0xE0 <= first_byte <= 0xEF:
        return 3
    if 0xF0 <= first_byte <= 0xF4:
        return 4
    return 0


def _extend_mapped_utf8_units(
    value: _MappedTextView,
    *,
    units: list[tuple[int, int, int]],
    output: list[str],
    starts: list[int],
    ends: list[int],
) -> None:
    """Decode each valid UTF-8 unit while preserving malformed encoded neighbors."""

    unit_index = 0
    while unit_index < len(units):
        unit_length = _utf8_unit_length(units[unit_index][0])
        decoded = ""
        if unit_length and unit_index + unit_length <= len(units):
            encoded = bytes(unit[0] for unit in units[unit_index : unit_index + unit_length])
            try:
                decoded = encoded.decode("utf-8")
            except UnicodeDecodeError:
                pass
        if decoded:
            raw_start = value.starts[units[unit_index][1]]
            raw_end = value.ends[units[unit_index + unit_length - 1][2] - 1]
            output.append(decoded)
            starts.append(raw_start)
            ends.append(raw_end)
            unit_index += unit_length
            continue

        _, text_start, text_end = units[unit_index]
        output.extend(value.text[text_start:text_end])
        starts.extend(value.starts[text_start:text_end])
        ends.extend(value.ends[text_start:text_end])
        unit_index += 1


def _replace_mapped_tokens(
    value: _MappedTextView,
    *,
    pattern: re.Pattern[str],
    decode: Callable[[str], str | None],
) -> _MappedTextView:
    output: list[str] = []
    starts: list[int] = []
    ends: list[int] = []
    cursor = 0
    for match in pattern.finditer(value.text):
        output.extend(value.text[cursor : match.start()])
        starts.extend(value.starts[cursor : match.start()])
        ends.extend(value.ends[cursor : match.start()])
        decoded = decode(match.group(0))
        if decoded is None:
            output.extend(match.group(0))
            starts.extend(value.starts[match.start() : match.end()])
            ends.extend(value.ends[match.start() : match.end()])
        else:
            output.extend(decoded)
            starts.extend([value.starts[match.start()]] * len(decoded))
            ends.extend([value.ends[match.end() - 1]] * len(decoded))
        cursor = match.end()
    output.extend(value.text[cursor:])
    starts.extend(value.starts[cursor:])
    ends.extend(value.ends[cursor:])
    return _MappedTextView("".join(output), tuple(starts), tuple(ends))


def _decode_base64_text(value: str) -> str | None:
    compact = "".join(character for character in value if character not in " \t\r\n")
    unpadded = compact.rstrip("=")
    if len(unpadded) % 4 == 1:
        return None
    padded = unpadded + ("=" * (-len(unpadded) % 4))
    try:
        decoded = base64.b64decode(padded, altchars=b"-_", validate=True)
        return decoded.decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None


def _next_base64_text_view(value: _MappedTextView) -> _MappedTextView:
    return _replace_mapped_tokens(
        value,
        pattern=_BASE64_TEXT_TOKEN,
        decode=_decode_base64_text,
    )


def _next_hex_text_view(
    value: _MappedTextView,
    *,
    nibble_offset: int = 0,
) -> _MappedTextView:
    output: list[str] = []
    starts: list[int] = []
    ends: list[int] = []
    cursor = 0
    for match in _HEX_TEXT_TOKEN.finditer(value.text):
        output.extend(value.text[cursor : match.start()])
        starts.extend(value.starts[cursor : match.start()])
        ends.extend(value.ends[cursor : match.start()])
        token_start = match.start()
        token_end = match.end()
        decode_start = min(token_start + nibble_offset, token_end)
        output.extend(value.text[token_start:decode_start])
        starts.extend(value.starts[token_start:decode_start])
        ends.extend(value.ends[token_start:decode_start])
        paired_end = decode_start + ((token_end - decode_start) // 2 * 2)
        units = [
            (
                int(value.text[index : index + 2], 16),
                index,
                index + 2,
            )
            for index in range(decode_start, paired_end, 2)
        ]
        _extend_mapped_utf8_units(
            value,
            units=units,
            output=output,
            starts=starts,
            ends=ends,
        )
        output.extend(value.text[paired_end:token_end])
        starts.extend(value.starts[paired_end:token_end])
        ends.extend(value.ends[paired_end:token_end])
        cursor = token_end
    output.extend(value.text[cursor:])
    starts.extend(value.starts[cursor:])
    ends.extend(value.ends[cursor:])
    return _MappedTextView("".join(output), tuple(starts), tuple(ends))


def _cross_encoded_secret_spans(
    value: str,
    secrets: tuple[str, ...],
) -> tuple[tuple[int, int], ...]:
    """Map registered values through every ordered pair of text decoders."""

    if not secrets:
        return ()
    if (
        not any(marker in value for marker in ("%", "+", "\\", "&"))
        and _BASE64_TEXT_TOKEN.search(value) is None
        and _HEX_TEXT_TOKEN.search(value) is None
    ):
        return ()
    decoders: tuple[Callable[[_MappedTextView], _MappedTextView], ...] = (
        lambda view: _next_percent_text_view(view, plus_as_space=False),
        lambda view: _next_percent_text_view(view, plus_as_space=True),
        _next_json_decoded_view,
        _next_html_decoded_view,
        _next_base64_text_view,
        _next_hex_text_view,
        lambda view: _next_hex_text_view(view, nibble_offset=1),
    )
    initial = _first_mapped_text_view(value)
    frontier: tuple[_MappedTextView, ...] = (initial,)
    seen = {(initial.text, initial.starts, initial.ends)}
    candidate_ends: dict[int, int] = {}
    secret_bytes = tuple(secret.encode("utf-8") for secret in secrets)
    for _ in range(2):
        next_frontier: list[_MappedTextView] = []
        for view in frontier:
            for decode in decoders:
                decoded = decode(view)
                key = (decoded.text, decoded.starts, decoded.ends)
                if decoded.text == view.text or key in seen:
                    continue
                seen.add(key)
                next_frontier.append(decoded)
                for encoded_start, encoded_end in _base64_encoded_secret_spans(
                    decoded.text,
                    secret_bytes,
                ):
                    raw_start = decoded.starts[encoded_start]
                    raw_end = decoded.ends[encoded_end - 1]
                    candidate_ends[raw_start] = max(
                        candidate_ends.get(raw_start, 0),
                        raw_end,
                    )
                for secret in secrets:
                    search_start = 0
                    while True:
                        found = decoded.text.find(secret, search_start)
                        if found < 0:
                            break
                        raw_start = decoded.starts[found]
                        raw_end = decoded.ends[found + len(secret) - 1]
                        candidate_ends[raw_start] = max(
                            candidate_ends.get(raw_start, 0),
                            raw_end,
                        )
                        search_start = found + len(secret)
        frontier = tuple(next_frontier)

    merged: list[tuple[int, int]] = []
    for start, end in sorted(candidate_ends.items()):
        if merged and start < merged[-1][1]:
            previous_start, previous_end = merged[-1]
            merged[-1] = (previous_start, max(previous_end, end))
        else:
            merged.append((start, end))
    return tuple(merged)


def _percent_encoded_path_spans(value: str) -> tuple[tuple[int, int], ...]:
    """Map one/two-layer percent-encoded local paths back to raw spans."""

    if "%" not in value:
        return ()
    initial = _first_mapped_text_view(value)
    http_spans = tuple(match.span() for match in _URL.finditer(value))
    frontier: tuple[_MappedTextView, ...] = (initial,)
    seen = {(initial.text, initial.starts, initial.ends)}
    candidates: list[tuple[int, int]] = []
    for _ in range(2):
        next_frontier: list[_MappedTextView] = []
        for view in frontier:
            for plus_as_space in (False, True):
                decoded = _next_percent_text_view(view, plus_as_space=plus_as_space)
                key = (decoded.text, decoded.starts, decoded.ends)
                if decoded.text == view.text or key in seen:
                    continue
                seen.add(key)
                next_frontier.append(decoded)
                for decoded_start, decoded_end in _raw_path_spans(decoded.text):
                    raw_start = decoded.starts[decoded_start]
                    raw_end = decoded.ends[decoded_end - 1]
                    if "%" not in value[raw_start:raw_end]:
                        continue
                    if any(
                        http_start < raw_end and raw_start < http_end
                        for http_start, http_end in http_spans
                    ):
                        continue
                    while (
                        raw_end < len(value)
                        and not value[raw_end].isspace()
                        and value[raw_end] not in "<>\"'`"
                    ):
                        raw_end += 1
                    while raw_end > raw_start and value[raw_end - 1] in _TRAILING_URL_PUNCTUATION:
                        raw_end -= 1
                    candidates.append((raw_start, raw_end))
        frontier = tuple(next_frontier)

    merged: list[tuple[int, int]] = []
    for start, end in sorted(candidates):
        if merged and start <= merged[-1][1]:
            previous_start, previous_end = merged[-1]
            merged[-1] = (previous_start, max(previous_end, end))
        else:
            merged.append((start, end))
    return tuple(merged)


def _secret_variants(value: str) -> set[str]:
    encoded = value.encode("utf-8")
    variants = {
        value,
        base64.b64encode(encoded).decode("ascii"),
        base64.b64encode(encoded).decode("ascii").rstrip("="),
        base64.urlsafe_b64encode(encoded).decode("ascii"),
        base64.urlsafe_b64encode(encoded).decode("ascii").rstrip("="),
        html.escape(value, quote=True),
        json.dumps(value, ensure_ascii=True)[1:-1],
    }
    return {variant for variant in variants if variant}


class LayeredRedactor:
    """Apply allowlist-independent redaction without exposing registered values."""

    __slots__ = (
        "__known_secret_bytes",
        "__known_secret_count",
        "__known_secrets",
        "__pseudonymizer",
        "__secret_variants",
        "__separator_secret_bytes",
        "__separator_secrets",
    )

    def __init__(
        self,
        pseudonymizer: Pseudonymizer,
        *,
        known_secrets: tuple[str, ...] = (),
    ) -> None:
        if type(pseudonymizer) is not Pseudonymizer:
            raise PrivacyError(
                "MH_PRIVACY_REDACTOR_PSEUDONYMIZER",
                "redactor requires a pseudonymizer",
            )
        if type(known_secrets) is not tuple or len(known_secrets) > MAX_KNOWN_SECRETS:
            raise PrivacyError(
                "MH_PRIVACY_SECRET_SET",
                "known redaction value set is invalid or too large",
            )
        normalized = tuple(_validate_known_secret(value) for value in known_secrets)
        if len(normalized) != len(set(normalized)):
            raise PrivacyError(
                "MH_PRIVACY_SECRET_DUPLICATE",
                "known redaction value set contains duplicates",
            )
        detection_values = tuple(
            sorted(
                {
                    equivalent
                    for value in normalized
                    for equivalent in (value, unicodedata.normalize("NFD", value))
                },
                key=lambda item: (-len(item), item),
            )
        )
        variants: dict[str, bool] = {}
        for value in detection_values:
            has_separator = _token_has_path_separator(value)
            for variant in _secret_variants(value):
                variants[variant] = variants.get(variant, False) or has_separator
        self.__pseudonymizer = pseudonymizer
        self.__known_secret_count = len(normalized)
        self.__known_secrets = detection_values
        self.__known_secret_bytes = tuple(
            sorted(
                (value.encode("utf-8") for value in detection_values),
                key=lambda item: (-len(item), item),
            )
        )
        self.__separator_secrets = tuple(
            value for value in detection_values if _token_has_path_separator(value)
        )
        self.__separator_secret_bytes = tuple(
            value.encode("utf-8") for value in self.__separator_secrets
        )
        self.__secret_variants = tuple(
            sorted(
                variants.items(),
                key=lambda item: (-len(item[0]), item[0]),
            )
        )

    def __repr__(self) -> str:
        return (
            f"LayeredRedactor(version={self.version!r}, "
            f"known_secret_count={self.known_secret_count})"
        )

    @property
    def version(self) -> str:
        return f"r{_REDACTION_POLICY_VERSION}-e{self.__pseudonymizer.epoch}"

    @property
    def known_secret_count(self) -> int:
        return self.__known_secret_count

    def pseudonymize_path(self, value: str) -> str:
        """Return the shared policy's path pseudonym without exposing its key."""

        return self.redact_path(value).value

    def redact_path(self, value: str) -> RedactionResult:
        """Return one collision-safe typed path pseudonym and its rule counts."""

        token = sanitize_local_path(value, pseudonymizer=self.__pseudonymizer)
        counts = {"path": 1}
        for _ in range(MAX_KNOWN_SECRETS + 1):
            before = token
            token = self._replace_known_secrets(
                token,
                counts,
                protect_separator_replacement=None,
            )
            if token == before:
                break
        else:  # pragma: no cover - defensive bound for adversarial secret sets
            raise PrivacyError(
                "MH_PRIVACY_REDACT_INVARIANT",
                "known redaction values did not reach a stable path output",
            )
        if counts.keys() != {"path"}:
            token = _PATH_MARKER
        return RedactionResult(value=token, counts=counts)

    def _replace_known_secrets(
        self,
        value: str,
        counts: dict[str, int],
        *,
        protect_separator_replacement: Callable[[str], str] | None,
    ) -> str:
        find_encoded_spans: tuple[
            tuple[
                Callable[[str], tuple[tuple[int, int], ...]],
                Callable[[str], tuple[tuple[int, int], ...]],
            ],
            ...,
        ] = (
            (
                lambda candidate: _cross_encoded_secret_spans(
                    candidate,
                    self.__known_secrets,
                ),
                lambda candidate: _cross_encoded_secret_spans(
                    candidate,
                    self.__separator_secrets,
                ),
            ),
            (
                lambda candidate: _base64_encoded_secret_spans(
                    candidate,
                    self.__known_secret_bytes,
                ),
                lambda candidate: _base64_encoded_secret_spans(
                    candidate,
                    self.__separator_secret_bytes,
                ),
            ),
        )
        for find_spans, find_separator_spans in find_encoded_spans:
            encoded_spans = find_spans(value)
            separator_spans = find_separator_spans(value) if protect_separator_replacement else ()
            if encoded_spans:
                for start, end in reversed(encoded_spans):
                    replacement = _SECRET_MARKER
                    if protect_separator_replacement is not None and any(
                        separator_start < end and start < separator_end
                        for separator_start, separator_end in separator_spans
                    ):
                        replacement = protect_separator_replacement(replacement)
                    value = f"{value[:start]}{replacement}{value[end:]}"
                _increment(counts, "secret", len(encoded_spans))
        for variant, has_separator in self.__secret_variants:
            occurrences = value.count(variant)
            if occurrences:
                replacement = _SECRET_MARKER
                if protect_separator_replacement is not None and has_separator:
                    replacement = protect_separator_replacement(replacement)
                value = value.replace(variant, replacement)
                _increment(counts, "secret", occurrences)
        return value

    def _pseudonym(self, kind: str, value: str) -> str:
        return f"[{kind}:{self.__pseudonymizer.pseudonymize(kind, value)}]"

    def _ip_pseudonym(self, value: str) -> str:
        token = self.__pseudonymizer.pseudonymize("ip", value).replace("_", "-")
        return f"ip-{token}.invalid"

    def redact(self, value: str) -> RedactionResult:
        """Return bounded redacted text or fail without echoing the rejected value."""

        return self._redact(value, allowed_url_query_keys=frozenset())

    def redact_url(
        self,
        value: str,
        *,
        allowed_query_keys: frozenset[str] = frozenset(),
    ) -> RedactionResult:
        """Redact one URL while retaining only explicitly allowed safe query fields."""

        sanitize_url(value, allowed_query_keys=allowed_query_keys)
        return self._redact(value, allowed_url_query_keys=allowed_query_keys)

    def _redact(
        self,
        value: str,
        *,
        allowed_url_query_keys: frozenset[str],
    ) -> RedactionResult:
        text, removed_controls = _normalize_text(value)
        counts: dict[str, int] = {}
        if removed_controls:
            _increment(counts, "control", removed_controls)

        placeholder_prefix = "MHREDACTIONPLACEHOLDER"
        while placeholder_prefix in text:
            placeholder_prefix += "X"
        protected_values: list[tuple[str, str]] = []

        def protect_separator_replacement(replacement: str) -> str:
            placeholder = f"{placeholder_prefix}{len(protected_values)}END"
            protected_values.append((placeholder, replacement))
            return placeholder

        def preserve_separator_boundary(candidate: str, replacement: str) -> str:
            if _token_has_path_separator(candidate):
                return protect_separator_replacement(replacement)
            return replacement

        def pseudonymize_path(candidate: str) -> str:
            result = self.redact_path(candidate)
            for category, amount in result.counts.items():
                if category != "path":
                    _increment(counts, category, amount)
            return result.value

        encoded_path_spans = _percent_encoded_path_spans(text)
        for start, end in reversed(encoded_path_spans):
            text = f"{text[:start]}{pseudonymize_path(text[start:end])}{text[end:]}"
        if encoded_path_spans:
            _increment(counts, "path", len(encoded_path_spans))

        text = self._replace_known_secrets(
            text,
            counts,
            protect_separator_replacement=protect_separator_replacement,
        )

        def replace_private_key(match: re.Match[str]) -> str:
            _increment(counts, "private_key")
            return preserve_separator_boundary(match.group(0), _PRIVATE_KEY_MARKER)

        text = _PRIVATE_KEY_BLOCK.sub(replace_private_key, text)

        def replace_header(match: re.Match[str]) -> str:
            if match.group(0).split(":", 1)[1].strip() == _CREDENTIAL_MARKER:
                return match.group(0)
            _increment(counts, "credential")
            replacement = f"{match.group('name')}: {_CREDENTIAL_MARKER}"
            return preserve_separator_boundary(match.group(0), replacement)

        text = _CREDENTIAL_HEADER.sub(replace_header, text)

        def replace_email(match: re.Match[str]) -> str:
            labels = match.group("domain").split(".")
            if (
                len(labels) < 2
                or not 2 <= len(labels[-1]) <= 63
                or any(not label or len(label) > 63 for label in labels)
            ):
                return match.group(0)
            _increment(counts, "email")
            replacement = self._pseudonym("email", match.group(0))
            return preserve_separator_boundary(match.group(0), replacement)

        def replace_ip(match: re.Match[str]) -> str:
            candidate = match.group(0)
            unwrapped = candidate[1:-1] if candidate.startswith("[") else candidate
            try:
                normalized = str(ipaddress.ip_address(unwrapped))
            except ValueError:
                return candidate
            _increment(counts, "ip")
            return self._ip_pseudonym(normalized)

        def replace_phone(match: re.Match[str]) -> str:
            _increment(counts, "phone")
            normalized = "".join(character for character in match.group(0) if character.isdigit())
            return self._pseudonym("phone", normalized)

        def replace_path(match: re.Match[str]) -> str:
            _increment(counts, "path")
            candidate, trailing = _split_contextual_candidate(match)
            return pseudonymize_path(candidate) + trailing

        def replace_url_path(match: re.Match[str]) -> str:
            _increment(counts, "path")
            return f"/{pseudonymize_path(match.group(0))}"

        def replace_file_uri(match: re.Match[str]) -> str:
            return replace_path(match)

        def redact_url_component(component: str, *, path_component: bool = False) -> str:
            try:
                comparison = unquote(component, errors="strict")
            except UnicodeDecodeError:
                if not path_component:
                    return component
                _increment(counts, "path")
                return f"/{pseudonymize_path(component)}"
            if path_component and _PERCENT_ESCAPE.search(comparison) is not None:
                _increment(counts, "path")
                return f"/{pseudonymize_path(component)}"
            if path_component and any(
                pattern.search(comparison) is not None
                for pattern in (
                    _UNC_PATH,
                    _WINDOWS_PATH,
                    _URL_POSIX_PATH,
                    _URL_LABELED_POSIX_PATH,
                )
            ):
                _increment(counts, "path")
                return f"/{pseudonymize_path(comparison)}"
            redacted = _EMAIL.sub(replace_email, comparison)
            redacted = _BRACKETED_IPV6.sub(replace_ip, redacted)
            redacted = _UNBRACKETED_IPV6.sub(replace_ip, redacted)
            redacted = _IPV4.sub(replace_ip, redacted)
            redacted = _PHONE.sub(replace_phone, redacted)
            redacted = _UNC_PATH.sub(replace_url_path, redacted)
            redacted = _WINDOWS_PATH.sub(replace_url_path, redacted)
            redacted = _URL_POSIX_PATH.sub(replace_url_path, redacted)
            if path_component and redacted != comparison:
                _increment(counts, "path")
                return f"/{pseudonymize_path(comparison)}"
            return redacted if redacted != comparison else component

        protected_url_count = 0

        def replace_url(match: re.Match[str]) -> str:
            nonlocal protected_url_count
            if protected_url_count >= MAX_URLS_PER_TEXT:
                raise PrivacyError(
                    "MH_PRIVACY_REDACT_URLS",
                    "redaction input contains too many URLs",
                )
            trimmed, trailing = _split_contextual_candidate(match)
            try:
                result = sanitize_url(
                    trimmed,
                    allowed_query_keys=allowed_url_query_keys,
                )
            except PrivacyError:
                _increment(counts, "url")
                protected_url_count += 1
                return protect_separator_replacement(_URL_MARKER) + trailing
            removed = set(result.removed)
            parsed = urlsplit(result.value)
            url_host = parsed.hostname
            if url_host is None:  # pragma: no cover - sanitize_url guarantees this
                raise PrivacyError(
                    "MH_PRIVACY_REDACT_INVARIANT",
                    "sanitized URL lost its host",
                )
            try:
                normalized_ip = str(ipaddress.ip_address(url_host))
            except ValueError:
                safe_host = url_host
            else:
                _increment(counts, "ip")
                safe_host = self._ip_pseudonym(normalized_ip)
            if parsed.port is not None:
                safe_host = f"{safe_host}:{parsed.port}"
            path = redact_url_component(parsed.path, path_component=True)
            query_fields = [
                (key, redact_url_component(query_value))
                for key, query_value in parse_qsl(
                    parsed.query,
                    keep_blank_values=True,
                    max_num_fields=100,
                )
            ]
            rebuilt = urlunsplit(
                (
                    parsed.scheme,
                    safe_host,
                    path,
                    urlencode(query_fields, doseq=True),
                    "",
                )
            )
            final = sanitize_url(
                rebuilt,
                allowed_query_keys=allowed_url_query_keys,
            )
            removed.update(final.removed)
            if final.value != trimmed:
                _increment(counts, "url")
            for category in removed:
                _increment(counts, f"url_{category}")
            placeholder = protect_separator_replacement(final.value)
            protected_url_count += 1
            return placeholder + trailing

        text = _URL.sub(replace_url, text)

        def replace_assignment(match: re.Match[str]) -> str:
            replacement = f"{match.group('name')}{match.group('separator')}{_CREDENTIAL_MARKER}"
            if match.group(0) == replacement:
                return replacement
            _increment(counts, "credential")
            return preserve_separator_boundary(match.group(0), replacement)

        text = _CREDENTIAL_ASSIGNMENT.sub(replace_assignment, text)
        text = _EMAIL.sub(replace_email, text)
        text, delimited_paths = _redact_delimited_paths(
            text,
            pseudonymize=pseudonymize_path,
            protected_placeholder_prefix=placeholder_prefix,
        )
        if delimited_paths:
            _increment(counts, "path", delimited_paths)
        text = _FILE_URI.sub(replace_file_uri, text)

        text = _BRACKETED_IPV6.sub(replace_ip, text)
        text = _UNBRACKETED_IPV6.sub(replace_ip, text)
        text = _IPV4.sub(replace_ip, text)
        text = _PHONE.sub(replace_phone, text)
        text = _UNC_PATH.sub(replace_path, text)
        text = _WINDOWS_PATH.sub(replace_path, text)
        text = _RELATIVE_PATH.sub(replace_path, text)
        text = _TILDE_PATH.sub(replace_path, text)
        text = _POSIX_PATH.sub(replace_path, text)

        for placeholder, safe_value in reversed(protected_values):
            text = text.replace(placeholder, safe_value)

        # Pseudonyms and category markers are generated after the first known-secret
        # pass. Scrub the fully restored output to prevent deterministic token or
        # marker text from reintroducing a registered value. The compact marker is
        # shorter than the minimum registered secret, so each fixed-point pass
        # removes collisions instead of creating a self-match.
        for _ in range(MAX_KNOWN_SECRETS + 1):
            before = text
            text = self._replace_known_secrets(
                text,
                counts,
                protect_separator_replacement=None,
            )
            if text == before:
                break
        else:  # pragma: no cover - defensive bound for adversarial secret sets
            raise PrivacyError(
                "MH_PRIVACY_REDACT_INVARIANT",
                "known redaction values did not reach a stable output",
            )

        def replace_secret_collided_url(match: re.Match[str]) -> str:
            candidate, trailing = _split_contextual_candidate(match)
            if _SECRET_MARKER not in candidate:
                return match.group(0)
            return _URL_MARKER + trailing

        text = _URL.sub(replace_secret_collided_url, text)

        if len(text.encode("utf-8")) > MAX_REDACTED_TEXT_BYTES:
            raise PrivacyError(
                "MH_PRIVACY_REDACT_OUTPUT_LARGE",
                "redacted output exceeds the retained-text byte bound",
            )
        if not text and value:
            raise PrivacyError(
                "MH_PRIVACY_REDACT_EMPTY",
                "redaction removed all retained text",
            )
        if any(
            type(count) is not int or count <= 0 or not math.isfinite(count)
            for count in counts.values()
        ):
            raise PrivacyError(  # pragma: no cover - internal invariant
                "MH_PRIVACY_REDACT_INVARIANT",
                "redaction count invariant failed",
            )
        return RedactionResult(value=text, counts=counts)
