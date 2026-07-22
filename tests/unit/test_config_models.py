import copy
import importlib.util
import json
import traceback
from datetime import UTC, datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from milhouse.config._models import MAX_PLUGIN_ALLOWLIST_ENTRIES, MilhouseConfig


def _base_config(**overrides: object) -> dict[str, object]:
    config: dict[str, object] = {
        "config_version": 1,
        "project": {"name": "team", "default_target": "app", "timezone": "UTC"},
        "paths": {
            "home": "../data",
            "spool": "spool",
            "reports": "reports",
            "logs": "logs",
            "backups": "backups",
        },
        "secrets": {"env_files": []},
        "identity": {"pseudonym_key_path": "control/pseudonym.key"},
        "plugins": {"allow_third_party": False, "allowed": []},
        "runtime": {
            "mode": "full",
            "log_level": "INFO",
            "max_batch_records": 500,
            "max_batch_bytes": 5242880,
        },
        "storage": {
            "clickhouse": {
                "enabled": True,
                "url_env": "MILHOUSE_CLICKHOUSE_URL",
                "username_env": "MILHOUSE_CLICKHOUSE_USER",
                "password_env": "MILHOUSE_CLICKHOUSE_PASSWORD",
                "database": "milhouse",
                "connect_timeout_seconds": 5,
            }
        },
        "privacy": {
            "strict": True,
            "agent_summaries_enabled": False,
            "agent_trace_events_enabled": False,
            "trace_excerpts_enabled": False,
            "hash_local_paths": True,
        },
        "retention": {
            "events_days": 30,
            "metrics_days": 90,
            "runs_days": 180,
            "alerts_days": 365,
            "feedback_days": 365,
            "agent_summaries_days": 30,
            "trace_events_days": 14,
            "reports_days": 90,
            "logs_days": 14,
        },
        "scheduler": {"enabled": True, "jitter_seconds": 5, "shutdown_timeout_seconds": 30},
        "reports": {"daily": {"enabled": True}, "weekly": {"enabled": True}},
        "jobs": [],
        "mcp": {
            "enabled": True,
            "transport": "stdio",
            "allow_writes": False,
            "default_limit": 100,
            "maximum_limit": 500,
            "maximum_window_days": 30,
        },
        "postmortem": {
            "auto_on_doh_marker": True,
            "default_window_hours": 24,
            "scan_project_docs": True,
        },
        "receiver": {
            "enabled": False,
            "bind": "127.0.0.1",
            "port": 8787,
            "allow_remote": False,
            "max_body_bytes": 262144,
            "requests_per_minute": 60,
            "clock_skew_seconds": 300,
            "sources": [],
        },
        "targets": [
            {"id": "app", "name": "App", "kind": "web_service", "environment": "production"}
        ],
        "collectors": [],
        "providers": [],
        "notifications": [],
        "alert_rules": [],
        "incident_rules": [],
        "feedback_rules": [],
    }
    config.update(overrides)
    return config


def _with_section(base: dict[str, object], section: str, **overrides: object) -> dict[str, object]:
    config = copy.deepcopy(base)
    section_value = dict(config[section])  # type: ignore[arg-type]
    section_value.update(overrides)
    config[section] = section_value
    return config


def _site_canary(*, collector_id: str = "canary", target: str = "app") -> dict[str, object]:
    return {
        "id": collector_id,
        "type": "site_canary",
        "target": target,
        "url": "https://example.com/health",
        "expected_statuses": [200],
    }


def _github_provider(*, provider_id: str = "github-primary") -> dict[str, object]:
    return {
        "id": provider_id,
        "type": "github",
        "read_token_env": "MILHOUSE_GITHUB_READ_TOKEN",
        "repository_allowlist": ["example/allowed"],
        "api_version": "2022-11-28",
    }


def _github_notification(
    *,
    provider: str = "github-primary",
    repository: str = "example/allowed",
) -> dict[str, object]:
    return {
        "id": "github-issues",
        "type": "github_issues",
        "enabled": True,
        "provider": provider,
        "repository": repository,
        "label_allowlist": ["milhouse"],
        "enabled_priorities": ["P1"],
        "enabled_actionabilities": ["needs_approval"],
        "allowed_classifications": ["internal"],
    }


def _errors(exc: ValidationError) -> str:
    return "; ".join(f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors())


def test_minimal_config_validates() -> None:
    config = MilhouseConfig.model_validate(_base_config())

    assert config.project.default_target == "app"
    assert config.targets[0].id == "app"


def test_unknown_top_level_key_is_rejected() -> None:
    document = _base_config(bogus_top_level_key=True)

    with pytest.raises(ValidationError, match="configuration contains an unknown field"):
        MilhouseConfig.model_validate(document)


def test_unknown_nested_key_is_rejected() -> None:
    document = _with_section(_base_config(), "project", bogus_field="oops")

    with pytest.raises(ValidationError, match="configuration contains an unknown field"):
        MilhouseConfig.model_validate(document)


def test_direct_model_validation_hides_runtime_input_values() -> None:
    runtime_canary = "runtime-secret-model-input-9c73d5"
    document = _with_section(
        _base_config(),
        "runtime",
        max_batch_records=runtime_canary,
    )

    with pytest.raises(ValidationError) as captured:
        MilhouseConfig.model_validate(document)

    rendered = (
        str(captured.value),
        repr(captured.value),
        "".join(traceback.format_exception(captured.value)),
    )
    assert all(runtime_canary not in surface for surface in rendered)
    assert all("input_value=" not in surface for surface in rendered)
    assert all("input_type=" not in surface for surface in rendered)


@pytest.mark.parametrize("use_json", [False, True])
@pytest.mark.parametrize(
    "case",
    ["unknown", "nested_unknown", "collector_discriminator", "receiver_discriminator"],
)
def test_direct_model_validation_hides_untrusted_keys_and_discriminators(
    use_json: bool,
    case: str,
) -> None:
    runtime_canary = "runtime-private-config-canary-76f20d"
    if case == "unknown":
        document = _base_config(**{runtime_canary: True})
        expected = "configuration contains an unknown field"
    elif case == "nested_unknown":
        document = _with_section(_base_config(), "project", **{runtime_canary: True})
        expected = "configuration contains an unknown field"
    elif case == "collector_discriminator":
        document = _base_config(
            collectors=[{"id": "collector", "target": "app", "type": runtime_canary}]
        )
        expected = "configuration contains an invalid discriminator"
    else:
        receiver = {
            **_base_config()["receiver"],  # type: ignore[dict-item]
            "sources": [{"id": "source", "target": "app", "type": runtime_canary}],
        }
        document = _base_config(receiver=receiver)
        expected = "configuration contains an invalid discriminator"

    with pytest.raises(ValidationError) as captured:
        if use_json:
            MilhouseConfig.model_validate_json(json.dumps(document))
        else:
            MilhouseConfig.model_validate(document)

    rendered = (
        str(captured.value),
        repr(captured.value),
        "".join(traceback.format_exception(captured.value)),
    )
    assert all(runtime_canary not in surface for surface in rendered)
    assert all(expected in surface for surface in rendered)
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None


def test_concrete_pydantic_model_is_only_in_private_module() -> None:
    import milhouse.config as public_config
    import milhouse.config._models as concrete_models

    assert "MilhouseConfig" not in public_config.__all__
    assert not hasattr(public_config, "MilhouseConfig")
    assert importlib.util.find_spec("milhouse.config.models") is None
    assert "MilhouseConfig" not in concrete_models.__all__
    assert concrete_models.MilhouseConfig is MilhouseConfig


@pytest.mark.parametrize(
    ("section", "field", "value"),
    [
        ("runtime", "max_batch_records", "500"),
        ("runtime", "max_batch_bytes", 5242880.0),
        ("privacy", "strict", 1),
        ("scheduler", "enabled", "true"),
    ],
)
def test_native_toml_types_are_not_coerced(section: str, field: str, value: object) -> None:
    document = _with_section(_base_config(), section, **{field: value})

    with pytest.raises(ValidationError):
        MilhouseConfig.model_validate(document)


def test_trace_excerpts_enabled_true_is_rejected() -> None:
    document = _with_section(_base_config(), "privacy", trace_excerpts_enabled=True)

    with pytest.raises(ValidationError) as excinfo:
        MilhouseConfig.model_validate(document)
    assert "trace_excerpts_enabled" in _errors(excinfo.value)


@pytest.mark.parametrize("version", [0, 2, -1, 1.0, "1", True])
def test_unsupported_config_version_is_rejected(version: object) -> None:
    document = _base_config(config_version=version)

    with pytest.raises(ValidationError):
        MilhouseConfig.model_validate(document)


def test_duplicate_target_ids_are_rejected() -> None:
    document = _base_config(
        targets=[
            {"id": "app", "name": "App", "kind": "web_service", "environment": "production"},
            {"id": "app", "name": "App Two", "kind": "web_service", "environment": "staging"},
        ]
    )

    with pytest.raises(ValidationError, match="duplicate entry"):
        MilhouseConfig.model_validate(document)


def test_duplicate_job_ids_are_rejected() -> None:
    job = {
        "id": "replay",
        "type": "spool_replay",
        "enabled": True,
        "schedule": "interval",
        "interval_seconds": 60,
        "timeout_seconds": 30,
    }
    document = _base_config(jobs=[job, dict(job)])

    with pytest.raises(ValidationError, match="duplicate entry"):
        MilhouseConfig.model_validate(document)


def test_default_target_must_reference_a_declared_target() -> None:
    document = _with_section(_base_config(), "project", default_target="missing-app")

    with pytest.raises(ValidationError, match="not a declared target id"):
        MilhouseConfig.model_validate(document)


def test_collector_target_must_reference_a_declared_target() -> None:
    document = _base_config(
        collectors=[
            {
                "id": "canary",
                "type": "site_canary",
                "target": "missing-app",
                "url": "https://example.com/health",
                "expected_statuses": [200],
            }
        ]
    )

    with pytest.raises(ValidationError, match="not a declared target id"):
        MilhouseConfig.model_validate(document)


def test_alert_rule_collector_must_be_a_site_canary_collector() -> None:
    document = _base_config(
        collectors=[
            {
                "id": "outbox",
                "type": "file_outbox",
                "target": "app",
                "path": "feedback-outbox.jsonl",
            }
        ],
        alert_rules=[
            {
                "id": "outbox-state",
                "type": "canary_state",
                "collector": "outbox",
                "consecutive_failures": 2,
                "consecutive_successes": 2,
                "cooldown_seconds": 300,
            }
        ],
    )

    with pytest.raises(ValidationError, match="must reference a site_canary collector"):
        MilhouseConfig.model_validate(document)


def test_incident_rule_target_must_match_referenced_alert_rule_target() -> None:
    document = _base_config(
        targets=[
            {"id": "app", "name": "App", "kind": "web_service", "environment": "production"},
            {"id": "other", "name": "Other", "kind": "web_service", "environment": "production"},
        ],
        collectors=[
            {
                "id": "canary",
                "type": "site_canary",
                "target": "app",
                "url": "https://example.com/health",
                "expected_statuses": [200],
            }
        ],
        alert_rules=[
            {
                "id": "canary-state",
                "type": "canary_state",
                "collector": "canary",
                "consecutive_failures": 2,
                "consecutive_successes": 2,
                "cooldown_seconds": 300,
            }
        ],
        incident_rules=[
            {
                "id": "mismatch",
                "target": "other",
                "alert_rule_ids": ["canary-state"],
                "group_dimensions": [],
                "correlation_horizon_seconds": 900,
                "quiet_window_seconds": 300,
            }
        ],
    )

    with pytest.raises(ValidationError, match="bound to another target"):
        MilhouseConfig.model_validate(document)


def test_collector_job_must_reference_a_declared_collector() -> None:
    document = _base_config(
        jobs=[
            {
                "id": "collect",
                "type": "collector",
                "collector": "missing-collector",
                "enabled": True,
                "schedule": "interval",
                "interval_seconds": 60,
                "timeout_seconds": 15,
            }
        ]
    )

    with pytest.raises(ValidationError, match="not bound to a declared collector id"):
        MilhouseConfig.model_validate(document)


@pytest.mark.parametrize(
    "identifier",
    ["Bad-ID", "bad id", "bad\nid", "bad_ïd", "", "-leading-dash", "a" * 65],
)
def test_invalid_identifier_patterns_are_rejected(identifier: str) -> None:
    document = _with_section(_base_config(), "project", default_target=identifier)

    with pytest.raises(ValidationError):
        MilhouseConfig.model_validate(document)


@pytest.mark.parametrize(
    "env_name",
    ["milhouse_url", "MILHOUSE URL", "MILHOUSE\nURL", "1LEADING_DIGIT", "MÜLHOUSE_URL", ""],
)
def test_invalid_env_var_patterns_are_rejected(env_name: str) -> None:
    base = _base_config()
    clickhouse = dict(base["storage"]["clickhouse"])  # type: ignore[index]
    clickhouse["url_env"] = env_name
    document = _with_section(base, "storage", clickhouse=clickhouse)

    with pytest.raises(ValidationError):
        MilhouseConfig.model_validate(document)


@pytest.mark.parametrize(
    "job",
    [
        {
            "id": "interval-missing-seconds",
            "type": "spool_replay",
            "enabled": True,
            "schedule": "interval",
            "timeout_seconds": 30,
        },
        {
            "id": "daily-missing-local-time",
            "type": "spool_replay",
            "enabled": True,
            "schedule": "daily",
            "timeout_seconds": 30,
        },
        {
            "id": "weekly-missing-weekday",
            "type": "spool_replay",
            "enabled": True,
            "schedule": "weekly",
            "local_time": "08:00",
            "timeout_seconds": 30,
        },
        {
            "id": "interval-with-weekday",
            "type": "spool_replay",
            "enabled": True,
            "schedule": "interval",
            "interval_seconds": 60,
            "weekday": "monday",
            "timeout_seconds": 30,
        },
        {
            "id": "daily-with-interval",
            "type": "spool_replay",
            "enabled": True,
            "schedule": "daily",
            "interval_seconds": 60,
            "local_time": "08:00",
            "timeout_seconds": 30,
        },
        {
            "id": "weekly-with-interval",
            "type": "spool_replay",
            "enabled": True,
            "schedule": "weekly",
            "interval_seconds": 60,
            "weekday": "monday",
            "local_time": "08:00",
            "timeout_seconds": 30,
        },
    ],
)
def test_job_schedule_requires_matching_fields(job: dict[str, object]) -> None:
    document = _base_config(jobs=[job])

    with pytest.raises(ValidationError):
        MilhouseConfig.model_validate(document)


def test_job_schedule_accepts_valid_weekly_shape() -> None:
    document = _base_config(
        jobs=[
            {
                "id": "weekly-report",
                "type": "weekly_report",
                "enabled": True,
                "schedule": "weekly",
                "weekday": "monday",
                "local_time": "08:00",
                "timeout_seconds": 120,
            }
        ]
    )

    config = MilhouseConfig.model_validate(document)
    assert config.jobs[0].weekday == "monday"


def test_job_schedule_accepts_valid_daily_shape() -> None:
    document = _base_config(
        jobs=[
            {
                "id": "daily-report",
                "type": "daily_report",
                "enabled": True,
                "schedule": "daily",
                "local_time": "08:00",
                "timeout_seconds": 120,
            }
        ]
    )

    config = MilhouseConfig.model_validate(document)
    assert config.jobs[0].local_time == "08:00"


def test_receiver_source_requires_both_or_neither_previous_secret_fields() -> None:
    document = _base_config(
        targets=[{"id": "app", "name": "App", "kind": "web_service", "environment": "production"}],
        receiver={
            "enabled": True,
            "bind": "127.0.0.1",
            "port": 8787,
            "allow_remote": False,
            "max_body_bytes": 262144,
            "requests_per_minute": 60,
            "clock_skew_seconds": 300,
            "sources": [
                {
                    "id": "backend",
                    "type": "hmac_v1",
                    "target": "app",
                    "secret_env": "MILHOUSE_INGEST_SECRET",
                    "allowed_paths": ["/v1/ingest/events"],
                    "previous_secret_env": "MILHOUSE_INGEST_SECRET_OLD",
                }
            ],
        },
    )

    with pytest.raises(ValidationError, match="must both be set or both absent"):
        MilhouseConfig.model_validate(document)


def test_plugins_allowlist_rejects_duplicate_entries() -> None:
    entry = {
        "distribution": "example-plugin",
        "version": "1.0.0",
        "group": "milhouse.collectors",
        "entry_point": "example_plugin.module:Collector",
    }
    document = _with_section(
        _base_config(), "plugins", allow_third_party=True, allowed=[entry, dict(entry)]
    )

    with pytest.raises(ValidationError, match="duplicate entry"):
        MilhouseConfig.model_validate(document)


def test_plugins_allowlist_requires_third_party_enablement() -> None:
    entry = {
        "distribution": "example-plugin",
        "version": "1.0.0",
        "group": "milhouse.collectors",
        "entry_point": "example_plugin.module:Collector",
    }
    document = _with_section(_base_config(), "plugins", allowed=[entry])

    with pytest.raises(ValidationError, match="allow_third_party=true"):
        MilhouseConfig.model_validate(document)


def test_plugins_allowlist_has_a_bounded_metadata_work_budget() -> None:
    entries = [
        {
            "distribution": f"example-plugin-{index}",
            "version": "1.0.0",
            "group": "milhouse.collectors",
            "entry_point": f"example_plugin_{index}.module:Collector",
        }
        for index in range(MAX_PLUGIN_ALLOWLIST_ENTRIES + 1)
    ]
    document = _with_section(
        _base_config(),
        "plugins",
        allow_third_party=True,
        allowed=entries,
    )

    with pytest.raises(ValidationError, match="at most 128 items"):
        MilhouseConfig.model_validate(document)


def test_agent_collector_mapping_must_reference_a_declared_target() -> None:
    document = _base_config(
        collectors=[
            {
                "id": "codex-sessions",
                "type": "codex_session",
                "target": "app",
                "sessions_root": "/absolute/path/to/codex/sessions",
                "target_repo_mapping": {"example-repo": "missing-target"},
            }
        ]
    )

    with pytest.raises(ValidationError, match="undeclared mapped target id"):
        MilhouseConfig.model_validate(document)


def test_github_issue_repository_must_be_provider_allowlisted() -> None:
    document = _base_config(
        providers=[
            {
                "id": "github-primary",
                "type": "github",
                "read_token_env": "MILHOUSE_GITHUB_READ_TOKEN",
                "repository_allowlist": ["example/allowed"],
                "api_version": "2022-11-28",
            }
        ],
        notifications=[
            {
                "id": "github-issues",
                "type": "github_issues",
                "enabled": True,
                "provider": "github-primary",
                "repository": "example/not-allowed",
                "label_allowlist": ["milhouse"],
                "enabled_priorities": ["P1"],
                "enabled_actionabilities": ["needs_approval"],
                "allowed_classifications": ["internal"],
            }
        ],
    )

    with pytest.raises(ValidationError, match="repository is not allowlisted"):
        MilhouseConfig.model_validate(document)


def test_path_fields_reject_control_characters() -> None:
    document = _with_section(_base_config(), "paths", spool="bad\tpath")

    with pytest.raises(ValidationError):
        MilhouseConfig.model_validate(document)


def test_timezone_validation_returns_a_value_free_error() -> None:
    document = _with_section(_base_config(), "project", timezone="/not/a/zone")

    with pytest.raises(ValidationError) as excinfo:
        MilhouseConfig.model_validate(document)

    assert "known IANA zone name" in _errors(excinfo.value)
    assert "/not/a/zone" not in _errors(excinfo.value)


def test_standalone_file_sources_allow_config_directory_relative_paths() -> None:
    document = _base_config(
        collectors=[
            {
                "id": "errors",
                "type": "error_report_file",
                "target": "app",
                "path": "../inputs/errors.jsonl",
                "input_schema_version": 1,
            }
        ]
    )

    config = MilhouseConfig.model_validate(document)
    assert config.collectors[0].path == "../inputs/errors.jsonl"


@pytest.mark.parametrize(
    "record_names",
    [["Canary.State"], ["canary..state"], ["canary state"], ["<script>alert(1)</script>"]],
)
def test_feedback_rule_record_names_reject_unsafe_or_malformed_values(
    record_names: list[str],
) -> None:
    document = _base_config(
        feedback_rules=[
            {
                "id": "recurrence",
                "type": "recurrence",
                "target": "app",
                "record_names": record_names,
                "minimum_occurrences": 2,
                "window_seconds": 86400,
                "priority": "P1",
                "actionability": "needs_approval",
            }
        ]
    )

    with pytest.raises(ValidationError):
        MilhouseConfig.model_validate(document)


def test_root_model_rejects_non_mapping_input_without_rendering_it() -> None:
    runtime_canary = "runtime-private-nonmapping-833a"

    with pytest.raises(ValidationError) as captured:
        MilhouseConfig.model_validate(runtime_canary)

    assert runtime_canary not in str(captured.value)


def test_relative_path_rejects_absolute_input() -> None:
    document = _base_config(
        collectors=[
            {
                "id": "outbox",
                "type": "file_outbox",
                "target": "app",
                "path": "/absolute/outbox.jsonl",
            }
        ]
    )

    with pytest.raises(ValidationError, match="path must be relative"):
        MilhouseConfig.model_validate(document)


def test_paths_reject_dot_segments() -> None:
    document = _with_section(_base_config(), "paths", spool="spool/../private")

    with pytest.raises(ValidationError, match="must not contain"):
        MilhouseConfig.model_validate(document)


def test_absolute_path_requires_a_leading_slash() -> None:
    targets = list(_base_config()["targets"])  # type: ignore[arg-type]
    targets[0] = {**targets[0], "repo_path": "relative/repository"}

    with pytest.raises(ValidationError, match="absolute canonical path"):
        MilhouseConfig.model_validate(_base_config(targets=targets))


@pytest.mark.parametrize(
    "deadline",
    [
        datetime.now(UTC).replace(tzinfo=None) + timedelta(days=1),
        datetime.now(timezone(timedelta(hours=1))) + timedelta(days=1),
        datetime.now(UTC) - timedelta(days=1),
    ],
)
def test_previous_receiver_secret_requires_a_future_utc_deadline(deadline: datetime) -> None:
    document = _base_config(
        receiver={
            **_base_config()["receiver"],  # type: ignore[dict-item]
            "sources": [
                {
                    "id": "backend",
                    "type": "hmac_v1",
                    "target": "app",
                    "secret_env": "MILHOUSE_INGEST_SECRET",
                    "previous_secret_env": "MILHOUSE_INGEST_SECRET_OLD",
                    "previous_secret_expires_at": deadline,
                    "allowed_paths": ["/v1/ingest/events"],
                }
            ],
        }
    )

    with pytest.raises(ValidationError):
        MilhouseConfig.model_validate(document)


def test_previous_receiver_secret_must_differ_from_current_secret() -> None:
    deadline = datetime.now(UTC) + timedelta(days=1)
    document = _base_config(
        receiver={
            **_base_config()["receiver"],  # type: ignore[dict-item]
            "sources": [
                {
                    "id": "backend",
                    "type": "hmac_v1",
                    "target": "app",
                    "secret_env": "MILHOUSE_INGEST_SECRET",
                    "previous_secret_env": "MILHOUSE_INGEST_SECRET",
                    "previous_secret_expires_at": deadline,
                    "allowed_paths": ["/v1/ingest/events"],
                }
            ],
        }
    )

    with pytest.raises(ValidationError, match="must differ"):
        MilhouseConfig.model_validate(document)


def test_previous_receiver_secret_accepts_a_future_utc_deadline() -> None:
    deadline = datetime.now(UTC) + timedelta(days=1)
    document = _base_config(
        receiver={
            **_base_config()["receiver"],  # type: ignore[dict-item]
            "sources": [
                {
                    "id": "backend",
                    "type": "hmac_v1",
                    "target": "app",
                    "secret_env": "MILHOUSE_INGEST_SECRET",
                    "previous_secret_env": "MILHOUSE_INGEST_SECRET_OLD",
                    "previous_secret_expires_at": deadline,
                    "allowed_paths": ["/v1/ingest/events"],
                }
            ],
        }
    )

    config = MilhouseConfig.model_validate(document)
    assert config.receiver.sources[0].previous_secret_expires_at == deadline


def test_mcp_default_limit_must_not_exceed_maximum() -> None:
    document = _with_section(_base_config(), "mcp", default_limit=501, maximum_limit=500)

    with pytest.raises(ValidationError, match="must not exceed"):
        MilhouseConfig.model_validate(document)


def test_site_canary_rejects_invalid_http_status() -> None:
    document = _base_config(
        collectors=[
            {
                "id": "canary",
                "type": "site_canary",
                "target": "app",
                "url": "https://example.com/health",
                "expected_statuses": [99],
            }
        ]
    )

    with pytest.raises(ValidationError, match="valid HTTP status"):
        MilhouseConfig.model_validate(document)


def test_generic_http_header_auth_requires_a_header_name() -> None:
    document = _base_config(
        providers=[
            {
                "id": "admin-api",
                "type": "generic_http",
                "auth_mode": "header",
                "token_env": "MILHOUSE_ADMIN_TOKEN",
                "host_allowlist": ["admin.example.com"],
            }
        ]
    )

    with pytest.raises(ValidationError, match="header_name is required"):
        MilhouseConfig.model_validate(document)


def test_generic_http_bearer_auth_does_not_require_a_header_name() -> None:
    document = _base_config(
        providers=[
            {
                "id": "admin-api",
                "type": "generic_http",
                "auth_mode": "bearer",
                "token_env": "MILHOUSE_ADMIN_TOKEN",
                "host_allowlist": ["admin.example.com"],
            }
        ]
    )

    config = MilhouseConfig.model_validate(document)
    assert config.providers[0].type == "generic_http"


def test_clickhouse_hosted_provider_rejects_duplicate_egress_classes() -> None:
    provider = {
        "id": "hosted",
        "type": "clickhouse_hosted",
        "url_env": "MILHOUSE_HOSTED_URL",
        "username_env": "MILHOUSE_HOSTED_USER",
        "password_env": "MILHOUSE_HOSTED_PASSWORD",
        "database": "milhouse",
        "egress_allowlist": ["public", "public"],
    }

    with pytest.raises(ValidationError, match="duplicate entry"):
        MilhouseConfig.model_validate(_base_config(providers=[provider]))


def test_clickhouse_hosted_provider_accepts_unique_egress_classes() -> None:
    provider = {
        "id": "hosted",
        "type": "clickhouse_hosted",
        "url_env": "MILHOUSE_HOSTED_URL",
        "username_env": "MILHOUSE_HOSTED_USER",
        "password_env": "MILHOUSE_HOSTED_PASSWORD",
        "database": "milhouse",
        "egress_allowlist": ["public", "internal"],
    }

    config = MilhouseConfig.model_validate(_base_config(providers=[provider]))
    assert config.providers[0].type == "clickhouse_hosted"


def test_discriminated_collection_rejects_a_non_list_value() -> None:
    runtime_canary = "runtime-private-collection-3a4f"
    document = _base_config(collectors={runtime_canary: True})

    with pytest.raises(ValidationError) as captured:
        MilhouseConfig.model_validate(document)

    assert runtime_canary not in str(captured.value)


def test_collector_provider_must_be_declared() -> None:
    collector = {
        "id": "cloudflare",
        "type": "cloudflare",
        "target": "app",
        "provider": "missing-provider",
        "zone_account_mapping": {"zone": "account"},
        "metric_families": ["requests"],
    }

    with pytest.raises(ValidationError, match="not a declared provider"):
        MilhouseConfig.model_validate(_base_config(collectors=[collector]))


def test_collector_provider_must_have_a_compatible_type() -> None:
    collector = {
        "id": "cloudflare",
        "type": "cloudflare",
        "target": "app",
        "provider": "github-primary",
        "zone_account_mapping": {"zone": "account"},
        "metric_families": ["requests"],
    }

    with pytest.raises(ValidationError, match="incompatible provider type"):
        MilhouseConfig.model_validate(
            _base_config(providers=[_github_provider()], collectors=[collector])
        )


def test_collector_accepts_a_compatible_provider() -> None:
    provider = {
        "id": "cloudflare-primary",
        "type": "cloudflare",
        "account_id_env": "MILHOUSE_CLOUDFLARE_ACCOUNT",
        "token_env": "MILHOUSE_CLOUDFLARE_TOKEN",
    }
    collector = {
        "id": "cloudflare",
        "type": "cloudflare",
        "target": "app",
        "provider": "cloudflare-primary",
        "zone_account_mapping": {"zone": "account"},
        "metric_families": ["requests"],
    }

    config = MilhouseConfig.model_validate(
        _base_config(providers=[provider], collectors=[collector])
    )
    assert config.collectors[0].type == "cloudflare"


def test_agent_summary_mapping_accepts_a_declared_target() -> None:
    collector = {
        "id": "agent-summaries",
        "type": "agent_summary",
        "target": "app",
        "path": "inputs/agent-summaries.jsonl",
        "input_schema_version": 1,
        "target_alias_mapping": {"application": "app"},
    }

    config = MilhouseConfig.model_validate(_base_config(collectors=[collector]))
    assert config.collectors[0].type == "agent_summary"


def test_receiver_source_target_must_be_declared() -> None:
    receiver = {
        **_base_config()["receiver"],  # type: ignore[dict-item]
        "sources": [
            {
                "id": "backend",
                "type": "hmac_v1",
                "target": "missing-target",
                "secret_env": "MILHOUSE_INGEST_SECRET",
                "allowed_paths": ["/v1/ingest/events"],
            }
        ],
    }

    with pytest.raises(ValidationError, match="source target is not a declared target"):
        MilhouseConfig.model_validate(_base_config(receiver=receiver))


def test_alert_rule_collector_must_be_declared() -> None:
    alert_rule = {
        "id": "canary-state",
        "type": "canary_state",
        "collector": "missing-canary",
        "consecutive_failures": 2,
        "consecutive_successes": 2,
        "cooldown_seconds": 300,
    }

    with pytest.raises(ValidationError, match="collector is not a declared collector"):
        MilhouseConfig.model_validate(_base_config(alert_rules=[alert_rule]))


def test_incident_rule_target_must_be_declared() -> None:
    incident_rule = {
        "id": "incident",
        "target": "missing-target",
        "alert_rule_ids": ["missing-alert"],
        "group_dimensions": [],
        "correlation_horizon_seconds": 900,
        "quiet_window_seconds": 300,
    }

    with pytest.raises(ValidationError, match="incident rule target is not a declared target"):
        MilhouseConfig.model_validate(_base_config(incident_rules=[incident_rule]))


def test_incident_rule_alert_must_be_declared() -> None:
    incident_rule = {
        "id": "incident",
        "target": "app",
        "alert_rule_ids": ["missing-alert"],
        "group_dimensions": [],
        "correlation_horizon_seconds": 900,
        "quiet_window_seconds": 300,
    }

    with pytest.raises(ValidationError, match="undeclared alert rule"):
        MilhouseConfig.model_validate(_base_config(incident_rules=[incident_rule]))


def test_incident_rule_accepts_an_alert_for_the_same_target() -> None:
    alert_rule = {
        "id": "canary-state",
        "type": "canary_state",
        "collector": "canary",
        "consecutive_failures": 2,
        "consecutive_successes": 2,
        "cooldown_seconds": 300,
    }
    incident_rule = {
        "id": "incident",
        "target": "app",
        "alert_rule_ids": ["canary-state"],
        "group_dimensions": [],
        "correlation_horizon_seconds": 900,
        "quiet_window_seconds": 300,
    }

    config = MilhouseConfig.model_validate(
        _base_config(
            collectors=[_site_canary()],
            alert_rules=[alert_rule],
            incident_rules=[incident_rule],
        )
    )
    assert config.incident_rules[0].id == "incident"


def test_feedback_rule_target_must_be_declared() -> None:
    feedback_rule = {
        "id": "recurrence",
        "type": "recurrence",
        "target": "missing-target",
        "record_names": ["canary.state"],
        "minimum_occurrences": 2,
        "window_seconds": 86400,
        "priority": "P1",
        "actionability": "needs_approval",
    }

    with pytest.raises(ValidationError, match="feedback rule target is not a declared target"):
        MilhouseConfig.model_validate(_base_config(feedback_rules=[feedback_rule]))


def test_feedback_rule_accepts_a_declared_target() -> None:
    feedback_rule = {
        "id": "recurrence",
        "type": "recurrence",
        "target": "app",
        "record_names": ["canary.state"],
        "minimum_occurrences": 2,
        "window_seconds": 86400,
        "priority": "P1",
        "actionability": "needs_approval",
    }

    config = MilhouseConfig.model_validate(_base_config(feedback_rules=[feedback_rule]))
    assert config.feedback_rules[0].target == "app"


def test_github_notification_provider_must_be_declared() -> None:
    with pytest.raises(ValidationError, match="notification provider is not a declared provider"):
        MilhouseConfig.model_validate(
            _base_config(notifications=[_github_notification(provider="missing-provider")])
        )


def test_github_notification_provider_must_be_github() -> None:
    provider = {
        "id": "admin-api",
        "type": "generic_http",
        "auth_mode": "bearer",
        "token_env": "MILHOUSE_ADMIN_TOKEN",
        "host_allowlist": ["admin.example.com"],
    }

    with pytest.raises(ValidationError, match="requires a github provider"):
        MilhouseConfig.model_validate(
            _base_config(
                providers=[provider],
                notifications=[_github_notification(provider="admin-api")],
            )
        )


def test_github_notification_accepts_an_allowlisted_repository() -> None:
    config = MilhouseConfig.model_validate(
        _base_config(
            providers=[_github_provider()],
            notifications=[_github_notification()],
        )
    )
    assert config.notifications[0].repository == "example/allowed"


def test_telegram_notification_uses_safe_public_classification_default() -> None:
    notification = {
        "id": "telegram",
        "type": "telegram",
        "enabled": False,
        "bot_token_env": "MILHOUSE_TELEGRAM_TOKEN",
        "chat_id_env": "MILHOUSE_TELEGRAM_CHAT",
    }

    config = MilhouseConfig.model_validate(_base_config(notifications=[notification]))
    assert config.notifications[0].allowed_classifications == ["public"]
