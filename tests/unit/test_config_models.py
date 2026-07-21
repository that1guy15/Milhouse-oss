import copy

import pytest
from pydantic import ValidationError

from milhouse.config.models import MilhouseConfig


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


def _errors(exc: ValidationError) -> str:
    return "; ".join(f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors())


def test_minimal_config_validates() -> None:
    config = MilhouseConfig.model_validate(_base_config())

    assert config.project.default_target == "app"
    assert config.targets[0].id == "app"


def test_unknown_top_level_key_is_rejected() -> None:
    document = _base_config(bogus_top_level_key=True)

    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        MilhouseConfig.model_validate(document)


def test_unknown_nested_key_is_rejected() -> None:
    document = _with_section(_base_config(), "project", bogus_field="oops")

    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        MilhouseConfig.model_validate(document)


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
