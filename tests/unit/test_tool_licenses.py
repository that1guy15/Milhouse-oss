from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

import scripts.check_licenses as licenses
from scripts.check_licenses import (
    ArtifactEvidence,
    InventoryCoverage,
    LicensePolicyError,
    Policy,
    load_inventory,
    load_lock,
    load_policy,
    validate_exception_graph,
    validate_inventory,
)

ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = ROOT / "config" / "license-policy.toml"


def _record(
    name: str,
    version: str,
    *,
    expression: str = "MIT",
    metadata: str = "UNKNOWN",
    classifier: str = "MIT License",
) -> dict[str, str]:
    return {
        "License-Classifier": classifier,
        "License-Expression": expression,
        "License-Metadata": metadata,
        "Name": name,
        "Version": version,
    }


def _valid_inventory() -> list[dict[str, str]]:
    return [
        _record(
            "milhouse-observability",
            "0.1.0a0",
            expression="Apache-2.0",
            classifier="UNKNOWN",
        ),
        _record("safe-runtime", "1.0"),
        _record(
            "chardet",
            "5.2.0",
            expression="UNKNOWN",
            metadata="LGPL",
            classifier="GNU Lesser General Public License v2 or later (LGPLv2+)",
        ),
        _record(
            "docutils",
            "0.23",
            expression="UNKNOWN",
            metadata="UNKNOWN",
            classifier="BSD License; GNU General Public License (GPL); Public Domain",
        ),
        _record("receiver-lib", "1.0"),
        _record("cyclonedx-bom", "7.3.0"),
        _record("twine", "6.2.0"),
        _record("readme-renderer", "45.0"),
    ]


def _wheel_url(name: str, version: str) -> str:
    filename = f"{name.replace('-', '_')}-{version}-py3-none-any.whl"
    return f"https://files.pythonhosted.org/packages/aa/bb/{filename}"


def _dependency_row(dependency: str | tuple[str, str]) -> str:
    if isinstance(dependency, str):
        return f'{{ name = "{dependency}" }}'
    name, marker = dependency
    return f'{{ name = "{name}", marker = "{marker}" }}'


def _package(
    name: str,
    version: str,
    dependencies: tuple[str | tuple[str, str], ...] = (),
) -> str:
    dependency_rows = ", ".join(_dependency_row(dependency) for dependency in dependencies)
    return (
        "[[package]]\n"
        f'name = "{name}"\n'
        f'version = "{version}"\n'
        f"dependencies = [{dependency_rows}]\n"
        "wheels = [{ "
        f'url = "{_wheel_url(name, version)}", '
        f'hash = "sha256:{"a" * 64}", size = 1, upload-time = "2026-01-01T00:00:00Z" '
        "}]\n\n"
    )


def _lock_text(
    *,
    chardet_version: str = "5.2.0",
    runtime_reaches_chardet: bool = False,
    cyclonedx_reaches_chardet: bool = True,
    alternative_chardet_path: bool = False,
    marker_dependency: tuple[str, str] | None = None,
) -> str:
    safe_dependencies = ("chardet",) if runtime_reaches_chardet else ()
    cyclonedx_dependencies = ("chardet",) if cyclonedx_reaches_chardet else ()
    dev_dependencies = ["cyclonedx-bom", "twine"]
    packages = [
        _package("safe-runtime", "1.0", safe_dependencies),
        _package("receiver-lib", "1.0"),
        _package("cyclonedx-bom", "7.3.0", cyclonedx_dependencies),
        _package("chardet", chardet_version),
        _package("twine", "6.2.0", ("readme-renderer",)),
        _package("readme-renderer", "45.0", ("docutils",)),
        _package("docutils", "0.23"),
    ]
    if alternative_chardet_path:
        dev_dependencies.append("other-tool")
        packages.append(_package("other-tool", "1.0", ("chardet",)))
    if marker_dependency is not None:
        name, marker = marker_dependency
        dev_dependencies.append((name, marker))
        packages.append(_package(name, "1.0"))
    dev_rows = ", ".join(_dependency_row(dependency) for dependency in dev_dependencies)
    return (
        "version = 1\n"
        "revision = 3\n"
        'requires-python = ">=3.11, <3.15"\n'
        "resolution-markers = [\"python_full_version >= '3.11'\"]\n\n"
        + "".join(packages)
        + "[[package]]\n"
        'name = "milhouse-observability"\n'
        'source = { editable = "." }\n'
        'dependencies = [{ name = "safe-runtime" }]\n\n'
        "[package.optional-dependencies]\n"
        'receiver = [{ name = "receiver-lib" }]\n\n'
        "[package.dev-dependencies]\n"
        f"dev = [{dev_rows}]\n"
    )


def _write_json(path: Path, value: object) -> Path:
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def _write_lock(path: Path, **changes: object) -> Path:
    path.write_text(_lock_text(**changes), encoding="utf-8")
    return path


def _synthetic_policy() -> Policy:
    return replace(load_policy(POLICY_PATH), artifact_evidence={})


def _synthetic_policy_text() -> str:
    source = POLICY_PATH.read_text(encoding="utf-8")
    start = source.index("# These packages are reachable")
    end = source.index("[[exceptions]]")
    without_evidence = source[:start] + source[end:]
    return without_evidence.replace(
        "\n[recognized]\n",
        "\nartifact_evidence = []\n\n[recognized]\n",
        1,
    )


def _validate(
    tmp_path: Path,
    inventory: list[dict[str, str]],
    *,
    policy: Policy | None = None,
    environment: dict[str, str] | None = None,
    **lock_changes: object,
) -> InventoryCoverage:
    policy = policy or _synthetic_policy()
    lock = load_lock(_write_lock(tmp_path / "uv.lock", **lock_changes))
    records = load_inventory(_write_json(tmp_path / "licenses.json", inventory))
    return validate_inventory(records, lock, policy, environment=environment)


def _environment(python_minor: str, platform: str) -> dict[str, str]:
    for environment in licenses.SUPPORTED_ENVIRONMENTS:
        if (
            environment["python_version"] == python_minor
            and environment["sys_platform"] == platform
        ):
            return dict(environment)
    raise AssertionError("test environment is absent from the support matrix")


def _artifact_evidence(
    name: str,
    *,
    artifact_hash: str | None = None,
    values: tuple[str, str, str] = ("MIT", "UNKNOWN", "UNKNOWN"),
) -> ArtifactEvidence:
    return ArtifactEvidence(
        name=name,
        version="1.0",
        artifact_url=_wheel_url(name, "1.0"),
        artifact_hash=artifact_hash or f"sha256:{'a' * 64}",
        metadata_path=f"{name.replace('-', '_')}-1.0.dist-info/METADATA",
        values=values,
    )


def _duplicate_first_artifact(text: str) -> str:
    start = text.index("[[artifact_evidence]]")
    end = text.index("[[artifact_evidence]]", start + 1)
    return text[:end] + text[start:end] + text[end:]


def _replace_exceptions(text: str, replacement: str) -> str:
    start = text.index("[[exceptions]]")
    return text[:start] + replacement


def _drop_first_wheels(text: str) -> str:
    start = text.index("wheels = [")
    end = text.index("\n", start) + 1
    return text[:start] + text[end:]


def _add_orphan_package(text: str) -> str:
    return text.replace(
        '[[package]]\nname = "milhouse-observability"',
        _package("orphan", "1.0") + '[[package]]\nname = "milhouse-observability"',
    )


def test_exact_reviewed_exceptions_pass() -> None:
    policy = load_policy(POLICY_PATH)

    assert set(policy.exceptions) == {"chardet", "docutils"}
    assert policy.exceptions["chardet"].path == (
        "milhouse-observability",
        "cyclonedx-bom",
        "chardet",
    )
    assert policy.exceptions["docutils"].path == (
        "milhouse-observability",
        "twine",
        "readme-renderer",
        "docutils",
    )
    assert set(policy.artifact_evidence) == {
        "backports-tarfile",
        "importlib-metadata",
        "jeepney",
        "secretstorage",
        "zipp",
    }


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda text: "unexpected = true\n" + text, "top-level keys"),
        (lambda text: text.replace("policy_version = 1", "policy_version = true"), "version"),
        (
            lambda text: text.replace(
                'root_package = "milhouse-observability"',
                'root_package = "other-project"',
            ),
            "wrong root package",
        ),
        (
            lambda text: text.replace('"UNLICENSED"]', '"UNLICENSED", "MISSING"]'),
            "unknown markers differ",
        ),
        (lambda text: text.replace('  "GPL",\n', "", 1), "forbidden markers differ"),
        (
            lambda text: text.replace("license_expression = [", "expression = [", 1),
            "recognized fields",
        ),
        (
            lambda text: text.replace('  "MIT-0",\n', '  "GPL-only",\n', 1),
            "unknown or prohibited marker",
        ),
        (
            lambda _text: _synthetic_policy_text().replace(
                "artifact_evidence = []", 'artifact_evidence = "bad"'
            ),
            "artifact_evidence must be a list",
        ),
        (
            lambda text: text.replace(
                'metadata_path = "backports.tarfile-1.2.0.dist-info/METADATA"\n',
                "",
                1,
            ),
            "missing or unknown keys",
        ),
        (
            lambda text: text.replace('name = "backports-tarfile"', 'name = "bad/name"', 1),
            "artifact evidence name is invalid",
        ),
        (
            lambda text: text.replace('version = "1.2.0"', 'version = "bad version"', 1),
            "artifact evidence backports-tarfile identity is invalid",
        ),
        (
            lambda text: text.replace(
                "backports.tarfile-1.2.0.dist-info/METADATA",
                "other-1.2.0.dist-info/METADATA",
                1,
            ),
            "artifact evidence backports-tarfile identity is invalid",
        ),
        (_duplicate_first_artifact, "artifact evidence backports-tarfile is duplicated"),
        (
            lambda text: text.replace(
                'license_expression = "UNKNOWN"', 'expression = "UNKNOWN"', 1
            ),
            "inventory schema is invalid",
        ),
        (
            lambda _text: _replace_exceptions(_synthetic_policy_text(), "").replace(
                "\n[recognized]\n",
                '\nexceptions = "bad"\n\n[recognized]\n',
                1,
            ),
            "exceptions must be a list",
        ),
        (
            lambda text: text.replace(
                'reason = "Development-only SBOM generation dependency; absent from '
                'runtime and receiver closures."\n',
                "",
                1,
            ),
            "license exception has missing or unknown keys",
        ),
        (
            lambda text: text.replace('name = "chardet"', 'name = "bad/name"', 1),
            "license exception name is invalid",
        ),
        (
            lambda text: text.replace('version = "5.2.0"', 'version = "bad version"', 1),
            "license exception chardet version is invalid",
        ),
        (
            lambda text: text.replace('name = "docutils"', 'name = "chardet"', 1),
            "license exception chardet is duplicated",
        ),
        (
            lambda text: text[: text.rindex("[[exceptions]]")],
            "exactly the reviewed exceptions",
        ),
        (
            lambda text: text.replace(
                'path = ["milhouse-observability", "cyclonedx-bom", "chardet"]',
                'path = ["milhouse-observability", "other", "chardet"]',
            ),
            "differs from its reviewed contract",
        ),
        (
            lambda text: text.replace(
                'license_classifier = "MIT License"', 'license_classifier = "UNKNOWN"', 1
            ),
            "only unknown license data",
        ),
        (
            lambda text: text.replace(
                'license_classifier = "MIT License"', 'license_classifier = "Custom"', 1
            ),
            "unrecognized License-Classifier",
        ),
        (
            lambda text: text.replace(
                'license_classifier = "MIT License"', 'license_classifier = "GPL-3.0-only"', 1
            ),
            "unreviewed copyleft",
        ),
    ],
)
def test_policy_contract_mutations_fail_closed(
    tmp_path: Path,
    mutation,
    message: str,
) -> None:
    path = tmp_path / "policy.toml"
    path.write_text(mutation(POLICY_PATH.read_text(encoding="utf-8")), encoding="utf-8")

    with pytest.raises(LicensePolicyError, match=message):
        load_policy(path)


def test_policy_rejects_invalid_encoding(tmp_path: Path) -> None:
    path = tmp_path / "policy.toml"
    path.write_bytes(b"\xff")

    with pytest.raises(LicensePolicyError, match="valid UTF-8 TOML"):
        load_policy(path)


@pytest.mark.parametrize(
    ("call", "message"),
    [
        (lambda: licenses._mapping([], "fixture"), "object with string keys"),
        (lambda: licenses._bounded_text(1, "fixture"), "must be a string"),
        (lambda: licenses._bounded_text("", "fixture"), "empty, oversized"),
        (lambda: licenses._string_list([], "fixture"), "non-empty list"),
        (lambda: licenses._string_list(["same", "same"], "fixture"), "must be unique"),
        (lambda: licenses._inventory_values({}, "fixture"), "schema is invalid"),
    ],
)
def test_strict_shape_helpers_fail_closed(call, message: str) -> None:
    with pytest.raises(LicensePolicyError, match=message):
        call()


def test_bounded_reader_rejects_symlink_and_oversize(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "target"
    target.write_text("data", encoding="utf-8")
    linked = tmp_path / "linked"
    linked.symlink_to(target)
    with pytest.raises(LicensePolicyError, match="regular, non-symlink"):
        licenses._read_bytes(linked, "fixture")

    monkeypatch.setattr(licenses, "MAX_INPUT_BYTES", 1)
    with pytest.raises(LicensePolicyError, match="8 MiB safety bound"):
        licenses._read_bytes(target, "fixture")


def test_valid_inventory_and_lock_pass(tmp_path: Path) -> None:
    _validate(tmp_path, _valid_inventory())


def test_main_reports_success_and_bounded_failure(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    policy_path = tmp_path / "policy.toml"
    policy_path.write_text(_synthetic_policy_text(), encoding="utf-8")
    lock_path = _write_lock(tmp_path / "uv.lock")
    inventory_path = _write_json(tmp_path / "licenses.json", _valid_inventory())
    arguments = [
        "--inventory",
        str(inventory_path),
        "--lock",
        str(lock_path),
        "--policy",
        str(policy_path),
    ]

    assert licenses.main(arguments) == 0
    assert "8 package(s) passed" in capsys.readouterr().out

    inventory_path = _write_json(tmp_path / "licenses.json", _valid_inventory()[:-1])
    arguments[1] = str(inventory_path)
    with pytest.raises(SystemExit, match="1"):
        licenses.main(arguments)
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "license-policy: license inventory is incomplete" in captured.err


def test_identical_duplicate_inventory_rows_are_collapsed(tmp_path: Path) -> None:
    inventory = _valid_inventory()
    inventory.append(dict(inventory[0]))

    records = load_inventory(_write_json(tmp_path / "licenses.json", inventory))

    assert len(records) == len(inventory) - 1


def test_inventory_requires_from_all_schema(tmp_path: Path) -> None:
    invalid = [{"Name": "safe-runtime", "Version": "1.0", "License": "MIT"}]

    with pytest.raises(LicensePolicyError, match="--from=all"):
        load_inventory(_write_json(tmp_path / "licenses.json", invalid))


def test_inventory_parser_rejects_malformed_and_conflicting_records(tmp_path: Path) -> None:
    path = tmp_path / "licenses.json"
    path.write_bytes(b"\xff")
    with pytest.raises(LicensePolicyError, match="valid UTF-8 JSON"):
        load_inventory(path)

    for value, message in (
        ([], "non-empty bounded list"),
        ([_record("bad/name", "1.0")], "invalid package name"),
        ([_record("package", "bad version")], "invalid version"),
    ):
        with pytest.raises(LicensePolicyError, match=message):
            load_inventory(_write_json(path, value))

    conflicting = [_record("package", "1.0"), _record("package", "2.0")]
    with pytest.raises(LicensePolicyError, match="conflicting entries"):
        load_inventory(_write_json(path, conflicting))


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda text: "unknown = true\n" + text, "top-level fields"),
        (lambda text: text.replace("version = 1", "version = 2", 1), "schema version"),
        (lambda text: text.replace("revision = 3", "revision = 2", 1), "revision"),
        (
            lambda text: text.replace(
                "resolution-markers = [\"python_full_version >= '3.11'\"]",
                "resolution-markers = []",
            ),
            "resolution-markers",
        ),
        (
            lambda text: text.replace('name = "safe-runtime"', 'name = "bad/name"', 1),
            "invalid package name",
        ),
        (
            lambda text: text.replace('version = "1.0"', 'version = "bad version"', 1),
            "invalid version",
        ),
        (_drop_first_wheels, "wheels must be a non-empty list"),
        (
            lambda text: text.replace(f"sha256:{'a' * 64}", "sha256:bad", 1),
            "invalid artifact metadata",
        ),
        (
            lambda text: text.replace(
                'source = { editable = "." }', 'source = { editable = ".." }'
            ),
            "unversioned editable",
        ),
        (
            lambda text: text.replace(
                "[package.optional-dependencies]\nreceiver =",
                "[package.optional-dependencies]\nother =",
            ),
            "receiver optional group",
        ),
        (
            lambda text: text.replace(
                "[package.dev-dependencies]\ndev =",
                "[package.dev-dependencies]\nother =",
            ),
            "dev dependency group",
        ),
        (
            lambda text: text.replace(
                'dependencies = [{ name = "safe-runtime" }]',
                'dependencies = [{ name = "missing-package" }]',
            ),
            "has no package entry",
        ),
        (
            lambda text: text.replace(
                'receiver = [{ name = "receiver-lib" }]',
                'receiver = [{ name = "receiver-lib", extra = ["missing"] }]',
            ),
            "unavailable extra",
        ),
        (
            lambda text: _lock_text(marker_dependency=("marker-tool", "not a valid marker ???")),
            "marker is invalid",
        ),
        (
            lambda text: text.replace(
                'receiver = [{ name = "receiver-lib" }]',
                'receiver = [{ name = "receiver-lib", extra = "receiver" }]',
            ),
            "extra must be a list",
        ),
        (
            lambda text: text.replace(
                'receiver = [{ name = "receiver-lib" }]',
                'receiver = [{ name = "receiver-lib", extra = ["receiver", "receiver"] }]',
            ),
            "extras must be unique",
        ),
        (
            lambda text: text.replace(
                'dependencies = [{ name = "safe-runtime" }]',
                'dependencies = [{ name = "safe-runtime" }, { name = "safe-runtime" }]',
            ),
            "duplicate dependencies",
        ),
    ],
)
def test_uv_lock_parser_rejects_structural_drift(
    tmp_path: Path,
    mutation,
    message: str,
) -> None:
    path = tmp_path / "uv.lock"
    path.write_text(mutation(_lock_text()), encoding="utf-8")

    with pytest.raises(LicensePolicyError, match=message):
        load_lock(path)


def test_uv_lock_rejects_invalid_toml(tmp_path: Path) -> None:
    path = tmp_path / "uv.lock"
    path.write_bytes(b"\xff")

    with pytest.raises(LicensePolicyError, match="valid UTF-8 TOML"):
        load_lock(path)


def test_unknown_only_and_unrecognized_license_data_fail(tmp_path: Path) -> None:
    unknown_inventory = _valid_inventory()
    unknown_inventory[1] = _record(
        "safe-runtime",
        "1.0",
        expression="UNKNOWN",
        metadata="UNKNOWN",
        classifier="UNKNOWN",
    )
    with pytest.raises(LicensePolicyError, match="only unknown"):
        _validate(tmp_path, unknown_inventory)

    unrecognized_inventory = _valid_inventory()
    unrecognized_inventory[1] = _record(
        "safe-runtime",
        "1.0",
        metadata="Custom license label",
    )
    with pytest.raises(LicensePolicyError, match="unrecognized"):
        _validate(tmp_path, unrecognized_inventory)


@pytest.mark.parametrize(
    "field",
    ("License-Expression", "License-Metadata", "License-Classifier"),
)
def test_unreviewed_copyleft_marker_in_every_inventory_source_fails(
    tmp_path: Path, field: str
) -> None:
    inventory = _valid_inventory()
    inventory[1][field] = "GPL-3.0-only"

    with pytest.raises(LicensePolicyError, match="unreviewed copyleft"):
        _validate(tmp_path, inventory)


def test_reviewed_exception_inventory_or_version_drift_fails(tmp_path: Path) -> None:
    inventory = _valid_inventory()
    inventory[2]["License-Metadata"] = "LGPL-2.1-or-later"
    with pytest.raises(LicensePolicyError, match="unreviewed copyleft"):
        _validate(tmp_path, inventory)

    with pytest.raises(LicensePolicyError, match="version drift"):
        _validate(tmp_path, _valid_inventory(), chardet_version="5.3.0")


def test_reviewed_exception_path_or_runtime_reachability_drift_fails(
    tmp_path: Path,
) -> None:
    with pytest.raises(LicensePolicyError, match="path drift"):
        _validate(tmp_path, _valid_inventory(), cyclonedx_reaches_chardet=False)

    with pytest.raises(LicensePolicyError, match="path drift"):
        _validate(tmp_path, _valid_inventory(), alternative_chardet_path=True)

    with pytest.raises(LicensePolicyError, match="runtime or receiver"):
        _validate(tmp_path, _valid_inventory(), runtime_reaches_chardet=True)


def test_missing_normal_inventory_row_requires_with_system(tmp_path: Path) -> None:
    inventory = [row for row in _valid_inventory() if row["Name"] != "receiver-lib"]

    with pytest.raises(LicensePolicyError, match="--with-system"):
        _validate(tmp_path, inventory)


def test_supported_marker_dependency_requires_hash_bound_evidence_and_host_inventory(
    tmp_path: Path,
) -> None:
    marker_dependency = ("marker-tool", "sys_platform == 'linux'")
    evidence = _artifact_evidence("marker-tool")
    policy = replace(_synthetic_policy(), artifact_evidence={"marker-tool": evidence})

    with pytest.raises(LicensePolicyError, match="artifact evidence must exactly cover"):
        _validate(
            tmp_path,
            _valid_inventory(),
            environment=_environment("3.14", "darwin"),
            marker_dependency=marker_dependency,
        )

    coverage = _validate(
        tmp_path,
        _valid_inventory(),
        policy=policy,
        environment=_environment("3.14", "darwin"),
        marker_dependency=marker_dependency,
    )
    assert coverage.artifact_names == {"marker-tool"}

    with pytest.raises(LicensePolicyError, match="--with-system"):
        _validate(
            tmp_path,
            _valid_inventory(),
            policy=policy,
            environment=_environment("3.11", "linux"),
            marker_dependency=marker_dependency,
        )

    inventory = [*_valid_inventory(), _record("marker-tool", "1.0")]
    _validate(
        tmp_path,
        inventory,
        policy=policy,
        environment=_environment("3.11", "linux"),
        marker_dependency=marker_dependency,
    )


def test_marker_only_forbidden_or_stale_artifact_evidence_fails(tmp_path: Path) -> None:
    marker_dependency = ("marker-tool", "python_full_version < '3.12'")
    base = _synthetic_policy()
    forbidden = _artifact_evidence(
        "marker-tool",
        values=("GPL-3.0-only", "UNKNOWN", "UNKNOWN"),
    )
    with pytest.raises(LicensePolicyError, match="unreviewed copyleft"):
        _validate(
            tmp_path,
            _valid_inventory(),
            policy=replace(base, artifact_evidence={"marker-tool": forbidden}),
            environment=_environment("3.14", "darwin"),
            marker_dependency=marker_dependency,
        )

    stale = _artifact_evidence("marker-tool", artifact_hash=f"sha256:{'b' * 64}")
    with pytest.raises(LicensePolicyError, match=r"differs from uv\.lock"):
        _validate(
            tmp_path,
            _valid_inventory(),
            policy=replace(base, artifact_evidence={"marker-tool": stale}),
            environment=_environment("3.14", "darwin"),
            marker_dependency=marker_dependency,
        )


def test_windows_only_lock_member_is_explicitly_excluded(tmp_path: Path) -> None:
    coverage = _validate(
        tmp_path,
        _valid_inventory(),
        environment=_environment("3.13", "darwin"),
        marker_dependency=("windows-tool", "sys_platform == 'win32'"),
    )

    assert coverage.excluded_windows_names == {"windows-tool"}
    assert "windows-tool" not in coverage.supported_names


def test_unsupported_non_windows_lock_member_fails_closed(tmp_path: Path) -> None:
    with pytest.raises(LicensePolicyError, match="not Windows-only"):
        _validate(
            tmp_path,
            _valid_inventory(),
            environment=_environment("3.13", "darwin"),
            marker_dependency=("other-platform-tool", "sys_platform == 'emscripten'"),
        )


def test_exception_path_search_has_a_strict_traversal_state_bound() -> None:
    edges: set[tuple[str, str]] = set()
    names = {licenses.ROOT_PACKAGE}
    for index in range(1, licenses.MAX_GRAPH_STATES + 2):
        child = f"node-{index}"
        parent = licenses.ROOT_PACKAGE if index == 1 else f"node-{index // 2}"
        edges.add((parent, child))
        names.add(child)
    closure = licenses.Closure(names=frozenset(names), edges=frozenset(edges))

    with pytest.raises(LicensePolicyError, match="traversal bound"):
        licenses._dependency_paths(closure, "unreachable-target")


def test_support_matrix_covers_all_python_macos_and_linux_pairs() -> None:
    pairs = {
        (environment["python_version"], environment["sys_platform"])
        for environment in licenses.SUPPORTED_ENVIRONMENTS
    }

    assert pairs == {
        (python_minor, platform)
        for python_minor in ("3.11", "3.12", "3.13", "3.14")
        for platform in ("darwin", "linux")
    }


def test_current_lock_preserves_reviewed_exception_graph() -> None:
    lock = load_lock(ROOT / "uv.lock")
    policy = load_policy(POLICY_PATH)
    validate_exception_graph(lock, policy)
    supported, always, conservative, windows = licenses._coverage_closures(lock)

    assert set(policy.artifact_evidence) == supported.names - always
    assert conservative.names - supported.names == {"pywin32", "pywin32-ctypes"}
    assert (conservative.names - supported.names).issubset(windows.names)
    for evidence in policy.artifact_evidence.values():
        assert lock.packages[evidence.name].version == evidence.version
        assert lock.packages[evidence.name].wheels[evidence.artifact_url] == evidence.artifact_hash
