from urllib.parse import quote

import pytest
from hypothesis import given
from hypothesis import strategies as st

from milhouse.privacy import Pseudonymizer, render_untrusted_evidence, sanitize_url

KEY = bytes(range(32))
SAFE_TEXT = st.text(
    alphabet=st.characters(blacklist_categories=("Cs", "Cc")),
    min_size=1,
    max_size=128,
)


@pytest.mark.property
@given(SAFE_TEXT)
def test_pseudonym_wire_never_contains_the_source_text(value: str) -> None:
    source = f"raw:{value}:/"
    token = Pseudonymizer(KEY).pseudonymize("value", source)

    assert source not in token
    assert token == Pseudonymizer(KEY).pseudonymize("value", source)


@pytest.mark.property
@given(SAFE_TEXT)
def test_default_url_sanitization_never_retains_query_data(value: str) -> None:
    source = f"https://example.test/path?private={quote(value, safe='')}#fragment"
    sanitized = sanitize_url(source)

    assert sanitized.value == "https://example.test/path"
    assert sanitized.removed == frozenset({"query", "fragment"})


@pytest.mark.property
@given(SAFE_TEXT)
def test_html_renderer_never_emits_source_text_as_markup(value: str) -> None:
    source = f"<{value}>"
    rendered = render_untrusted_evidence(source, format="html")

    assert f"<{value}>" not in rendered
    assert "&lt;" in rendered
    assert "&gt;" in rendered
