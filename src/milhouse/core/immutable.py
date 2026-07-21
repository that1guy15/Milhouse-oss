"""Serialization-compatible immutable collection views for frozen domain models."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Generic, NoReturn, SupportsIndex, TypeVar

_Key = TypeVar("_Key")
_Value = TypeVar("_Value")


def _immutable() -> NoReturn:
    raise TypeError("canonical domain collections are immutable")


class FrozenDict(dict[_Key, _Value], Generic[_Key, _Value]):
    """A dict subclass that Pydantic serializes normally but callers cannot mutate."""

    def __setitem__(self, key: _Key, value: _Value) -> None:
        _immutable()

    def __delitem__(self, key: _Key) -> None:
        _immutable()

    def clear(self) -> None:
        _immutable()

    def pop(self, key: _Key, default: object = None) -> NoReturn:
        _immutable()

    def popitem(self) -> NoReturn:
        _immutable()

    def setdefault(self, key: _Key, default: _Value | None = None) -> NoReturn:
        _immutable()

    def update(  # type: ignore[override]
        self,
        other: Mapping[_Key, _Value] | Iterable[tuple[_Key, _Value]] = (),
        **kwargs: _Value,
    ) -> NoReturn:
        _immutable()

    def __ior__(self, other: Mapping[_Key, _Value]) -> NoReturn:  # type: ignore[override,misc]
        _immutable()

    def __copy__(self) -> FrozenDict[_Key, _Value]:
        return self

    def __deepcopy__(self, memo: dict[int, object]) -> FrozenDict[_Key, _Value]:
        return self


class FrozenList(list[_Value], Generic[_Value]):
    """A list subclass that preserves JSON arrays while preventing in-place mutation."""

    def __setitem__(self, key: object, value: object) -> None:
        _immutable()

    def __delitem__(self, key: object) -> None:
        _immutable()

    def append(self, value: _Value) -> None:
        _immutable()

    def clear(self) -> None:
        _immutable()

    def extend(self, values: Iterable[_Value]) -> None:
        _immutable()

    def insert(self, index: SupportsIndex, value: _Value) -> None:
        _immutable()

    def pop(self, index: SupportsIndex = -1) -> NoReturn:
        _immutable()

    def remove(self, value: _Value) -> None:
        _immutable()

    def reverse(self) -> None:
        _immutable()

    def sort(self, *, key: object = None, reverse: bool = False) -> None:
        _immutable()

    def __iadd__(self, values: Iterable[_Value]) -> NoReturn:  # type: ignore[override,misc]
        _immutable()

    def __imul__(self, count: SupportsIndex) -> NoReturn:
        _immutable()

    def __copy__(self) -> FrozenList[_Value]:
        return self

    def __deepcopy__(self, memo: dict[int, object]) -> FrozenList[_Value]:
        return self


def freeze_dict(value: dict[_Key, _Value]) -> dict[_Key, _Value]:
    """Return a serialization-compatible immutable copy of one dictionary."""

    return FrozenDict(value)


def freeze_list(value: list[_Value]) -> list[_Value]:
    """Return a serialization-compatible immutable copy of one list."""

    return FrozenList(value)
