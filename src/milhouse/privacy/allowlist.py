"""Exact nested field allowlists applied before canonical record construction."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Literal

from milhouse.core.canonical import MAX_CANONICAL_INT, MIN_CANONICAL_INT
from milhouse.core.immutable import freeze_dict
from milhouse.privacy.pseudonym import PrivacyError
from milhouse.privacy.redact import LayeredRedactor, RedactionResult

MAX_FIELD_RULES = 100
MAX_FIELD_DEPTH = 8
MAX_INPUT_FIELDS_PER_OBJECT = 1_000

FieldKind = Literal["scalar", "text", "url", "path"]

_FIELD_SEGMENT = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_QUERY_KEY = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,63}$")


def _is_field_kind(value: object) -> bool:
    return type(value) is str and value in {"scalar", "text", "url", "path"}


def _is_strict_bool(value: object) -> bool:
    return type(value) is bool


@dataclass(frozen=True, slots=True)
class FieldRule:
    """One exact allowlisted leaf path and its privacy transformation."""

    path: tuple[str, ...]
    kind: FieldKind
    required: bool = False
    allowed_query_keys: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        if (
            type(self.path) is not tuple
            or not 1 <= len(self.path) <= MAX_FIELD_DEPTH
            or any(
                type(segment) is not str or _FIELD_SEGMENT.fullmatch(segment) is None
                for segment in self.path
            )
        ):
            raise PrivacyError("MH_PRIVACY_FIELD_PATH", "field rule path is invalid")
        if not _is_field_kind(self.kind):
            raise PrivacyError("MH_PRIVACY_FIELD_KIND", "field rule kind is invalid")
        if not _is_strict_bool(self.required):
            raise PrivacyError("MH_PRIVACY_FIELD_REQUIRED", "field required flag is invalid")
        if type(self.allowed_query_keys) is not frozenset:
            raise PrivacyError(
                "MH_PRIVACY_FIELD_QUERY_ALLOWLIST",
                "field query allowlist is invalid",
            )
        if len(self.allowed_query_keys) > MAX_FIELD_RULES or any(
            type(key) is not str or _QUERY_KEY.fullmatch(key) is None
            for key in self.allowed_query_keys
        ):
            raise PrivacyError(
                "MH_PRIVACY_FIELD_QUERY_ALLOWLIST",
                "field query allowlist is invalid",
            )
        if self.kind != "url" and self.allowed_query_keys:
            raise PrivacyError(
                "MH_PRIVACY_FIELD_QUERY_ALLOWLIST",
                "query keys are valid only for URL fields",
            )


class _RuleNode:
    __slots__ = ("children", "rule")

    def __init__(self) -> None:
        self.children: dict[str, _RuleNode] = {}
        self.rule: FieldRule | None = None


class FieldAllowlist:
    """Compiled exact field policy that never retains unlisted siblings."""

    __slots__ = ("__root", "__rules")

    def __init__(self, rules: tuple[FieldRule, ...]) -> None:
        if type(rules) is not tuple or not 1 <= len(rules) <= MAX_FIELD_RULES:
            raise PrivacyError(
                "MH_PRIVACY_FIELD_RULES",
                "field allowlist is empty, invalid, or too large",
            )
        if any(type(rule) is not FieldRule for rule in rules):
            raise PrivacyError(
                "MH_PRIVACY_FIELD_RULES",
                "field allowlist contains an invalid rule",
            )
        root = _RuleNode()
        seen: set[tuple[str, ...]] = set()
        for rule in rules:
            if rule.path in seen:
                raise PrivacyError(
                    "MH_PRIVACY_FIELD_DUPLICATE",
                    "field allowlist contains a duplicate path",
                )
            seen.add(rule.path)
            node = root
            for segment in rule.path:
                if node.rule is not None:
                    raise PrivacyError(
                        "MH_PRIVACY_FIELD_OVERLAP",
                        "field allowlist paths overlap",
                    )
                node = node.children.setdefault(segment, _RuleNode())
            if node.children:
                raise PrivacyError(
                    "MH_PRIVACY_FIELD_OVERLAP",
                    "field allowlist paths overlap",
                )
            node.rule = rule
        self.__root = root
        self.__rules = tuple(sorted(rules, key=lambda rule: rule.path))

    def __repr__(self) -> str:
        return f"FieldAllowlist(rule_count={len(self.__rules)})"

    @property
    def rules(self) -> tuple[FieldRule, ...]:
        return self.__rules

    def _root(self) -> _RuleNode:
        return self.__root


@dataclass(frozen=True, slots=True)
class AllowedFields:
    """Privacy-safe allowlist output and non-sensitive transformation counts."""

    value: dict[str, object]
    discarded_fields: int
    redactions: dict[str, int]

    def __post_init__(self) -> None:
        object.__setattr__(self, "value", _freeze_nested(self.value))
        object.__setattr__(self, "redactions", freeze_dict(dict(self.redactions)))


def _freeze_nested(value: dict[str, object]) -> dict[str, object]:
    frozen: dict[str, object] = {}
    for key, item in value.items():
        frozen[key] = _freeze_nested(item) if type(item) is dict else item
    return freeze_dict(frozen)


def _merge_counts(target: dict[str, int], result: RedactionResult) -> None:
    for category, count in result.counts.items():
        target[category] = target.get(category, 0) + count


def _transform_scalar(
    value: object, redactor: LayeredRedactor
) -> tuple[object, RedactionResult | None]:
    if type(value) is bool:
        return value, None
    if type(value) is int:
        if not MIN_CANONICAL_INT <= value <= MAX_CANONICAL_INT:
            raise PrivacyError(
                "MH_PRIVACY_FIELD_VALUE",
                "allowlisted integer is outside the canonical domain",
            )
        return value, None
    if type(value) is float:
        if not math.isfinite(value):
            raise PrivacyError(
                "MH_PRIVACY_FIELD_VALUE",
                "allowlisted number must be finite",
            )
        return value, None
    if type(value) is str:
        result = redactor.redact(value)
        return result.value, result
    raise PrivacyError(
        "MH_PRIVACY_FIELD_VALUE",
        "allowlisted scalar has an unsupported type",
    )


def _transform_leaf(
    value: object,
    rule: FieldRule,
    redactor: LayeredRedactor,
    counts: dict[str, int],
) -> object:
    if rule.kind == "scalar":
        transformed, redaction_result = _transform_scalar(value, redactor)
        if redaction_result is not None:
            _merge_counts(counts, redaction_result)
        return transformed
    if type(value) is not str:
        raise PrivacyError(
            "MH_PRIVACY_FIELD_VALUE",
            "allowlisted privacy field must contain text",
        )
    if rule.kind == "text":
        result = redactor.redact(value)
        _merge_counts(counts, result)
        return result.value
    if rule.kind == "path":
        result = redactor.redact_path(value)
        _merge_counts(counts, result)
        return result.value
    result = redactor.redact_url(value, allowed_query_keys=rule.allowed_query_keys)
    _merge_counts(counts, result)
    return result.value


def _has_required(node: _RuleNode) -> bool:
    if node.rule is not None:
        return node.rule.required
    return any(_has_required(child) for child in node.children.values())


def _filter_node(
    value: object,
    node: _RuleNode,
    redactor: LayeredRedactor,
    counts: dict[str, int],
) -> tuple[object | None, int, bool]:
    if node.rule is not None:
        return _transform_leaf(value, node.rule, redactor, counts), 0, True
    if type(value) is not dict:
        raise PrivacyError(
            "MH_PRIVACY_FIELD_OBJECT",
            "allowlisted nested field must contain an object",
        )
    if len(value) > MAX_INPUT_FIELDS_PER_OBJECT:
        raise PrivacyError(
            "MH_PRIVACY_FIELD_OBJECT_LARGE",
            "input object exceeds the field-count bound",
        )
    output: dict[str, object] = {}
    discarded = sum(1 for key in value if key not in node.children)
    for key in sorted(node.children):
        child = node.children[key]
        if key not in value:
            if _has_required(child):
                raise PrivacyError(
                    "MH_PRIVACY_FIELD_MISSING",
                    "required allowlisted field is missing",
                )
            continue
        transformed, child_discarded, present = _filter_node(value[key], child, redactor, counts)
        discarded += child_discarded
        if present:
            output[key] = transformed
    return output, discarded, bool(output)


def apply_field_allowlist(
    value: dict[str, object],
    *,
    allowlist: FieldAllowlist,
    redactor: LayeredRedactor,
) -> AllowedFields:
    """Retain exact policy leaves and privacy-transform every retained string."""

    if type(value) is not dict:
        raise PrivacyError("MH_PRIVACY_FIELD_INPUT", "field input must be an object")
    if type(allowlist) is not FieldAllowlist or type(redactor) is not LayeredRedactor:
        raise PrivacyError(
            "MH_PRIVACY_FIELD_POLICY",
            "field privacy policy is invalid",
        )
    counts: dict[str, int] = {}
    transformed, discarded, _ = _filter_node(value, allowlist._root(), redactor, counts)
    if type(transformed) is not dict:  # pragma: no cover - root is never a leaf
        raise PrivacyError(
            "MH_PRIVACY_FIELD_INVARIANT",
            "field allowlist invariant failed",
        )
    return AllowedFields(
        value=transformed,
        discarded_fields=discarded,
        redactions=counts,
    )
