import copy
import operator
from collections.abc import Callable

import pytest

from milhouse.core.immutable import freeze_dict, freeze_list


def _dict_setitem(value: dict[str, int]) -> object:
    value["other"] = 2
    return value


def _dict_delitem(value: dict[str, int]) -> object:
    del value["item"]
    return value


@pytest.mark.parametrize(
    "mutation",
    [
        _dict_setitem,
        _dict_delitem,
        lambda value: value.clear(),
        lambda value: value.pop("item"),
        lambda value: value.popitem(),
        lambda value: value.setdefault("other", 2),
        lambda value: value.update({"other": 2}),
        lambda value: operator.ior(value, {"other": 2}),
    ],
)
def test_frozen_dict_blocks_every_normal_in_place_mutation(
    mutation: Callable[[dict[str, int]], object],
) -> None:
    value = freeze_dict({"item": 1})

    with pytest.raises(TypeError, match="immutable"):
        mutation(value)

    assert value == {"item": 1}
    assert copy.copy(value) is value
    assert copy.deepcopy(value) is value


def _list_setitem(value: list[int]) -> object:
    value[0] = 2
    return value


def _list_delitem(value: list[int]) -> object:
    del value[0]
    return value


@pytest.mark.parametrize(
    "mutation",
    [
        _list_setitem,
        _list_delitem,
        lambda value: value.append(2),
        lambda value: value.clear(),
        lambda value: value.extend([2]),
        lambda value: value.insert(0, 2),
        lambda value: value.pop(),
        lambda value: value.remove(1),
        lambda value: value.reverse(),
        lambda value: value.sort(),
        lambda value: operator.iadd(value, [2]),
        lambda value: operator.imul(value, 2),
    ],
)
def test_frozen_list_blocks_every_normal_in_place_mutation(
    mutation: Callable[[list[int]], object],
) -> None:
    value = freeze_list([1])

    with pytest.raises(TypeError, match="immutable"):
        mutation(value)

    assert value == [1]
    assert copy.copy(value) is value
    assert copy.deepcopy(value) is value
