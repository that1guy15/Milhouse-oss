import json

import pytest

from scripts import required_ci
from scripts.required_ci import ResultError, evaluate, results_from_needs_json


def test_required_ci_accepts_only_a_complete_success_graph() -> None:
    assert evaluate(
        ["test", "quality", "package"],
        ["package=SUCCESS", "test=success", "quality= success "],
    ) == ("package", "quality", "test")


@pytest.mark.parametrize("result", ["failure", "cancelled", "skipped"])
def test_required_ci_rejects_every_known_unsuccessful_result(result: str) -> None:
    with pytest.raises(ResultError, match="did not succeed"):
        evaluate(["quality"], [f"quality={result}"])


@pytest.mark.parametrize(
    ("expected", "observed", "message"),
    [
        (["quality"], [], "missing result"),
        (["quality"], ["quality=success", "extra=success"], "unexpected result"),
        (["quality"], ["quality=neutral"], "missing or unknown"),
        (["quality"], ["quality"], "JOB=RESULT"),
        (["quality", "quality"], ["quality=success"], "duplicate expected"),
        (["quality"], ["quality=success", "quality=success"], "duplicate result"),
    ],
)
def test_required_ci_rejects_incomplete_or_ambiguous_graphs(
    expected: list[str],
    observed: list[str],
    message: str,
) -> None:
    with pytest.raises(ResultError, match=message):
        evaluate(expected, observed)


def test_needs_json_requires_a_string_result_for_every_job() -> None:
    raw = json.dumps({"quality": {"result": "success"}, "test": {"outputs": {}}})

    with pytest.raises(ResultError, match="no string result"):
        results_from_needs_json(raw)


@pytest.mark.parametrize(
    "raw",
    [
        "[]",
        "not JSON",
        json.dumps({"invalid job name": {"result": "success"}}),
        json.dumps({"quality": "success"}),
    ],
)
def test_needs_json_fails_closed_on_malformed_shapes(raw: str) -> None:
    with pytest.raises(ResultError):
        results_from_needs_json(raw)


def test_needs_json_converts_a_complete_result_mapping() -> None:
    raw = json.dumps(
        {
            "quality": {"result": "success", "outputs": {}},
            "test": {"result": "failure"},
        }
    )
    assert results_from_needs_json(raw) == ["quality=success", "test=failure"]


def test_needs_json_enforces_input_size_bound() -> None:
    raw = json.dumps({"quality": {"result": "success", "padding": "x" * (1024 * 1024)}})
    with pytest.raises(ResultError, match="exceeds the 1 MiB"):
        results_from_needs_json(raw)


def test_required_ci_rejects_empty_expected_and_invalid_result_job() -> None:
    with pytest.raises(ResultError, match="at least one expected"):
        evaluate([], [])
    with pytest.raises(ResultError, match="invalid result job name"):
        evaluate(["quality"], ["invalid job=success"])


def test_required_ci_main_supports_pair_and_needs_json_interfaces(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert required_ci.main(["--expected-job", "quality", "--result", "quality=success"]) == 0
    assert "1 required job" in capsys.readouterr().out

    raw = json.dumps({"quality": {"result": "success"}})
    assert required_ci.main(["--required", "quality", "--needs-json", raw]) == 0


@pytest.mark.parametrize(
    "arguments",
    [
        [],
        ["--expected-job", "quality", "--needs-json", "{}", "--required", "quality"],
        ["--required", "quality"],
        ["--expected-job", "quality", "--result", "quality=skipped"],
    ],
)
def test_required_ci_main_fails_closed_on_incomplete_or_unsuccessful_inputs(
    arguments: list[str],
) -> None:
    with pytest.raises(SystemExit) as caught:
        required_ci.main(arguments)
    assert caught.value.code == 1


def test_required_ci_argument_parser_rejects_invalid_job_name() -> None:
    with pytest.raises(SystemExit) as caught:
        required_ci.parse_args(["--expected-job", "invalid job"])
    assert caught.value.code == 2
