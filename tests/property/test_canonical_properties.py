import json
import unicodedata

import pytest
from hypothesis import given
from hypothesis import strategies as st

from milhouse.core.canonical import canonical_json_bytes

JSON_SCALAR = st.none() | st.booleans() | st.integers(min_value=-(2**63), max_value=2**63 - 1)
CANONICAL_KEY = st.text(
    alphabet=st.characters(
        blacklist_categories=("Cs",),
        blacklist_characters="\r",
    ),
    max_size=16,
).map(lambda value: unicodedata.normalize("NFC", value))
JSON_VALUE = st.recursive(
    JSON_SCALAR,
    lambda children: (
        st.lists(children, max_size=8)
        | st.dictionaries(
            CANONICAL_KEY,
            children,
            max_size=8,
        )
    ),
    max_leaves=40,
)


@pytest.mark.property
@given(JSON_VALUE)
def test_canonical_json_round_trips_supported_structures(value: object) -> None:
    encoded = canonical_json_bytes(value)

    assert canonical_json_bytes(json.loads(encoded)) == encoded


@pytest.mark.property
@given(st.dictionaries(CANONICAL_KEY.filter(bool), JSON_SCALAR, max_size=16))
def test_canonical_json_is_independent_of_mapping_insertion_order(value: dict[str, object]) -> None:
    reversed_value = dict(reversed(list(value.items())))

    assert canonical_json_bytes(value) == canonical_json_bytes(reversed_value)
