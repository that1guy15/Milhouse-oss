"""Strict Pydantic v2 domain models for Milhouse configuration v1."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal, Protocol
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    HttpUrl,
    IPvAnyAddress,
    StringConstraints,
    UrlConstraints,
    model_validator,
)
from pydantic_core import Url

CONFIG_VERSION = 1

_ID_PATTERN = r"^[a-z][a-z0-9_-]{0,63}$"
_ENV_VAR_PATTERN = r"^[A-Z][A-Z0-9_]{0,127}$"
_DIMENSION_KEY_PATTERN = r"^[a-z][a-z0-9_]{0,63}$"
_MACHINE_NAME_PATTERN = r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$"
_LOCAL_TIME_PATTERN = r"^([01][0-9]|2[0-3]):[0-5][0-9]$"
_REPOSITORY_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}/[A-Za-z0-9][A-Za-z0-9._-]{0,99}$"
_DISTRIBUTION_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"
_PLUGIN_VERSION_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9.+_-]{0,63}$"
_ENTRY_POINT_PATTERN = r"^[A-Za-z_][A-Za-z0-9_.]{0,127}:[A-Za-z_][A-Za-z0-9_.]{0,127}$"
_CLICKHOUSE_IDENTIFIER_PATTERN = _ID_PATTERN
_ADMIN_API_PATH_PATTERN = r"^/[A-Za-z0-9/_-]{0,255}$"
_TIMEZONE_PATTERN = r"^[A-Za-z0-9_+\-/]{1,64}$"
_NO_CONTROL_CHARS_PATTERN = r"^[^\x00-\x1f\x7f]{1,4096}$"
_GITHUB_API_VERSION_PATTERN = r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$"

_SECONDS_MAX = 86400
_DAYS_MAX = 3650
_BYTES_MAX = 1_073_741_824
_COUNT_MAX = 1_000_000


def _validate_timezone(value: str) -> str:
    try:
        ZoneInfo(value)
    except (ValueError, ZoneInfoNotFoundError) as exc:
        raise ValueError("timezone must be a known IANA zone name") from exc
    return value


def _reject_dotdot_segments(value: str, *, allow_leading_slash: bool) -> list[str]:
    if value.startswith("/"):
        if not allow_leading_slash:
            raise ValueError("path must be relative, not absolute")
        segments = value[1:].split("/")
    else:
        segments = value.split("/")
    if any(segment in ("", ".", "..") for segment in segments):
        raise ValueError("path must not contain empty, '.', or '..' segments")
    return segments


def _validate_relative_path(value: str) -> str:
    _reject_dotdot_segments(value, allow_leading_slash=False)
    return value


def _validate_absolute_path(value: str) -> str:
    if not value.startswith("/"):
        raise ValueError("path must be an absolute canonical path")
    _reject_dotdot_segments(value, allow_leading_slash=True)
    return value


def _validate_class_specific_path(value: str) -> str:
    _reject_dotdot_segments(value, allow_leading_slash=True)
    return value


def _validate_future_utc_datetime(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError("timestamp must be RFC3339 with a zero UTC offset")
    if value <= datetime.now(UTC):
        raise ValueError("timestamp must be in the future")
    return value


def _require_unique(values: Sequence[str], *, label: str) -> list[str]:
    seen: set[str] = set()
    for value in values:
        if value in seen:
            raise ValueError(f"{label} contains a duplicate entry")
        seen.add(value)
    return list(values)


Identifier = Annotated[str, StringConstraints(pattern=_ID_PATTERN)]
EnvVarRef = Annotated[str, StringConstraints(pattern=_ENV_VAR_PATTERN)]
DimensionKey = Annotated[str, StringConstraints(pattern=_DIMENSION_KEY_PATTERN)]
MachineName = Annotated[str, StringConstraints(pattern=_MACHINE_NAME_PATTERN, max_length=128)]
LocalTime = Annotated[str, StringConstraints(pattern=_LOCAL_TIME_PATTERN)]
RepositorySlug = Annotated[str, StringConstraints(pattern=_REPOSITORY_PATTERN)]
PluginDistribution = Annotated[str, StringConstraints(pattern=_DISTRIBUTION_PATTERN)]
PluginVersion = Annotated[str, StringConstraints(pattern=_PLUGIN_VERSION_PATTERN)]
PluginEntryPoint = Annotated[str, StringConstraints(pattern=_ENTRY_POINT_PATTERN)]
ClickHouseIdentifier = Annotated[str, StringConstraints(pattern=_CLICKHOUSE_IDENTIFIER_PATTERN)]
AdminApiPath = Annotated[str, StringConstraints(pattern=_ADMIN_API_PATH_PATTERN)]
GithubApiVersion = Annotated[str, StringConstraints(pattern=_GITHUB_API_VERSION_PATTERN)]
BoundedText64 = Annotated[str, StringConstraints(pattern=_NO_CONTROL_CHARS_PATTERN, max_length=64)]
BoundedText128 = Annotated[
    str, StringConstraints(pattern=_NO_CONTROL_CHARS_PATTERN, max_length=128)
]
BoundedText255 = Annotated[
    str, StringConstraints(pattern=_NO_CONTROL_CHARS_PATTERN, max_length=255)
]
BoundedText512 = Annotated[
    str, StringConstraints(pattern=_NO_CONTROL_CHARS_PATTERN, max_length=512)
]
IanaTimezone = Annotated[
    str, StringConstraints(pattern=_TIMEZONE_PATTERN), AfterValidator(_validate_timezone)
]
RelativePathStr = Annotated[
    str,
    StringConstraints(pattern=_NO_CONTROL_CHARS_PATTERN),
    AfterValidator(_validate_relative_path),
]
AbsolutePathStr = Annotated[
    str,
    StringConstraints(pattern=_NO_CONTROL_CHARS_PATTERN),
    AfterValidator(_validate_absolute_path),
]
ClassSpecificPathStr = Annotated[
    str,
    StringConstraints(pattern=_NO_CONTROL_CHARS_PATTERN),
    AfterValidator(_validate_class_specific_path),
]
ConfigDirRelativePathStr = Annotated[str, StringConstraints(pattern=_NO_CONTROL_CHARS_PATTERN)]
FutureUtcDatetime = Annotated[datetime, AfterValidator(_validate_future_utc_datetime)]
HttpsUrl = Annotated[Url, UrlConstraints(allowed_schemes=["https"])]


class _HasId(Protocol):
    id: str


class StrictModel(BaseModel):
    """Base model shared by every Milhouse configuration node."""

    model_config = ConfigDict(extra="forbid", strict=True)


def require_unique_ids(items: Sequence[_HasId], *, label: str) -> frozenset[str]:
    ids = [item.id for item in items]
    _require_unique(ids, label=label)
    return frozenset(ids)


# --- 4.1 project, paths, secrets, identity, plugins, runtime -------------


class ProjectConfig(StrictModel):
    name: Identifier
    default_target: Identifier
    timezone: IanaTimezone


class PathsConfig(StrictModel):
    home: ConfigDirRelativePathStr
    spool: ClassSpecificPathStr
    reports: ClassSpecificPathStr
    logs: ClassSpecificPathStr
    backups: ClassSpecificPathStr


class SecretsConfig(StrictModel):
    env_files: list[ConfigDirRelativePathStr] = Field(default_factory=list)


class IdentityConfig(StrictModel):
    pseudonym_key_path: ClassSpecificPathStr


class PluginAllowlistEntry(StrictModel):
    distribution: PluginDistribution
    version: PluginVersion
    group: Literal["milhouse.collectors", "milhouse.notifications", "milhouse.exporters"]
    entry_point: PluginEntryPoint


class PluginsConfig(StrictModel):
    allow_third_party: bool = False
    allowed: list[PluginAllowlistEntry] = Field(default_factory=list)

    @model_validator(mode="after")
    def _check_unique_allowlist(self) -> PluginsConfig:
        keys = [(entry.distribution, entry.group, entry.entry_point) for entry in self.allowed]
        _require_unique([str(key) for key in keys], label="plugins.allowed")
        if not self.allow_third_party and self.allowed:
            raise ValueError("plugins.allowed requires allow_third_party=true")
        return self


class RuntimeConfig(StrictModel):
    mode: Literal["full", "spool_only"]
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
    max_batch_records: int = Field(ge=1, le=_COUNT_MAX)
    max_batch_bytes: int = Field(ge=1, le=_BYTES_MAX)


class StorageClickHouseConfig(StrictModel):
    enabled: bool
    url_env: EnvVarRef
    username_env: EnvVarRef
    password_env: EnvVarRef
    database: ClickHouseIdentifier
    connect_timeout_seconds: int = Field(ge=1, le=_SECONDS_MAX)


class StorageConfig(StrictModel):
    clickhouse: StorageClickHouseConfig


class PrivacyConfig(StrictModel):
    strict: bool
    agent_summaries_enabled: bool = False
    agent_trace_events_enabled: bool = False
    trace_excerpts_enabled: Literal[False] = False
    hash_local_paths: bool = True


class RetentionConfig(StrictModel):
    events_days: int = Field(ge=1, le=_DAYS_MAX)
    metrics_days: int = Field(ge=1, le=_DAYS_MAX)
    runs_days: int = Field(ge=1, le=_DAYS_MAX)
    alerts_days: int = Field(ge=1, le=_DAYS_MAX)
    feedback_days: int = Field(ge=1, le=_DAYS_MAX)
    agent_summaries_days: int = Field(ge=1, le=_DAYS_MAX)
    trace_events_days: int = Field(ge=1, le=_DAYS_MAX)
    reports_days: int = Field(ge=1, le=_DAYS_MAX)
    logs_days: int = Field(ge=1, le=_DAYS_MAX)


class SchedulerConfig(StrictModel):
    enabled: bool
    jitter_seconds: int = Field(ge=0, le=_SECONDS_MAX)
    shutdown_timeout_seconds: int = Field(ge=1, le=_SECONDS_MAX)


class ReportScheduleConfig(StrictModel):
    enabled: bool


class ReportsConfig(StrictModel):
    daily: ReportScheduleConfig
    weekly: ReportScheduleConfig


class MCPConfig(StrictModel):
    enabled: bool
    transport: Literal["stdio"]
    allow_writes: bool = False
    default_limit: int = Field(ge=1, le=_COUNT_MAX)
    maximum_limit: int = Field(ge=1, le=_COUNT_MAX)
    maximum_window_days: int = Field(ge=1, le=_DAYS_MAX)

    @model_validator(mode="after")
    def _check_limit_order(self) -> MCPConfig:
        if self.default_limit > self.maximum_limit:
            raise ValueError("mcp.default_limit must not exceed mcp.maximum_limit")
        return self


class PostmortemConfig(StrictModel):
    auto_on_doh_marker: bool
    default_window_hours: int = Field(ge=1, le=720)
    scan_project_docs: bool


# --- 4.12 ingestion receiver ------------------------------------------------


class _ReceiverSourceBase(StrictModel):
    id: Identifier
    target: Identifier
    secret_env: EnvVarRef
    previous_secret_env: EnvVarRef | None = None
    previous_secret_expires_at: FutureUtcDatetime | None = None

    @model_validator(mode="after")
    def _check_previous_secret_pair(self) -> _ReceiverSourceBase:
        has_env = self.previous_secret_env is not None
        has_deadline = self.previous_secret_expires_at is not None
        if has_env != has_deadline:
            raise ValueError(
                "previous_secret_env and previous_secret_expires_at must both be set or both absent"
            )
        if has_env and self.previous_secret_env == self.secret_env:
            raise ValueError("previous_secret_env must differ from secret_env")
        return self


class HmacIngestSource(_ReceiverSourceBase):
    type: Literal["hmac_v1"]
    allowed_paths: list[
        Literal[
            "/v1/ingest/events",
            "/v1/ingest/backend-errors",
            "/v1/ingest/browser-errors",
        ]
    ] = Field(min_length=1)

    @model_validator(mode="after")
    def _check_unique_paths(self) -> HmacIngestSource:
        _require_unique(self.allowed_paths, label="allowed_paths")
        return self


class GithubWebhookSource(_ReceiverSourceBase):
    type: Literal["github_webhook"]
    repository: RepositorySlug


ReceiverSource = Annotated[HmacIngestSource | GithubWebhookSource, Field(discriminator="type")]


class ReceiverConfig(StrictModel):
    enabled: bool = False
    bind: IPvAnyAddress
    port: int = Field(ge=1, le=65535)
    allow_remote: bool = False
    max_body_bytes: int = Field(ge=1, le=_BYTES_MAX)
    requests_per_minute: int = Field(ge=1, le=_COUNT_MAX)
    clock_skew_seconds: int = Field(ge=1, le=_SECONDS_MAX)
    sources: list[ReceiverSource] = Field(default_factory=list)


# --- targets -----------------------------------------------------------------


class TargetConfig(StrictModel):
    id: Identifier
    name: Annotated[str, StringConstraints(pattern=_NO_CONTROL_CHARS_PATTERN, max_length=200)]
    kind: Identifier
    environment: Identifier
    base_url: HttpUrl | None = None
    repo_path: AbsolutePathStr | None = None


# --- 4.8 collectors ------------------------------------------------------------


class _CollectorBase(StrictModel):
    id: Identifier
    target: Identifier
    request_timeout_seconds: int = Field(ge=1, le=300, default=30)


class SiteCanaryCollector(_CollectorBase):
    type: Literal["site_canary"]
    url: HttpUrl
    expected_statuses: list[int] = Field(min_length=1)
    follow_redirects: bool = False
    verify_tls: bool = True

    @model_validator(mode="after")
    def _check_statuses(self) -> SiteCanaryCollector:
        for status in self.expected_statuses:
            if not 100 <= status <= 599:
                raise ValueError("expected_statuses entries must be valid HTTP status codes")
        _require_unique([str(s) for s in self.expected_statuses], label="expected_statuses")
        return self


class FileOutboxCollector(_CollectorBase):
    type: Literal["file_outbox"]
    path: RelativePathStr
    producer_allowlist: list[Identifier] = Field(default_factory=list)
    max_line_bytes: int = Field(ge=1, le=_BYTES_MAX, default=65536)
    max_file_bytes: int = Field(ge=1, le=_BYTES_MAX, default=104857600)
    ack_filename: BoundedText255 = "outbox-ack.json"
    rotation_glob: BoundedText255 | None = None


class ErrorReportFileCollector(_CollectorBase):
    type: Literal["error_report_file"]
    path: ConfigDirRelativePathStr
    input_schema_version: int = Field(ge=1, le=1000)
    mode: Literal["json", "jsonl"] = "jsonl"
    max_record_bytes: int = Field(ge=1, le=_BYTES_MAX, default=65536)


class WorkflowFileCollector(_CollectorBase):
    type: Literal["workflow_file"]
    path: ConfigDirRelativePathStr
    input_schema_version: int = Field(ge=1, le=1000)
    mode: Literal["json", "jsonl"] = "jsonl"
    workflow_run_type_mapping: dict[Identifier, Identifier] = Field(default_factory=dict)


class CloudflareCollector(_CollectorBase):
    type: Literal["cloudflare"]
    provider: Identifier
    zone_account_mapping: dict[Identifier, Identifier] = Field(min_length=1)
    metric_families: list[Identifier] = Field(min_length=1)
    late_arrival_overlap_seconds: int = Field(ge=0, le=_SECONDS_MAX, default=0)
    page_size: int = Field(ge=1, le=1000, default=100)
    window_seconds: int = Field(ge=1, le=_SECONDS_MAX, default=300)

    @model_validator(mode="after")
    def _check_unique_families(self) -> CloudflareCollector:
        _require_unique(self.metric_families, label="metric_families")
        return self


class GithubActionsCollector(_CollectorBase):
    type: Literal["github_actions"]
    provider: Identifier
    repository: RepositorySlug
    workflow_allowlist: list[BoundedText255] = Field(default_factory=list)
    environment_allowlist: list[Identifier] = Field(default_factory=list)
    polling_lookback_seconds: int = Field(ge=1, le=_SECONDS_MAX, default=3600)
    page_size: int = Field(ge=1, le=1000, default=100)
    include_deployments: bool = False


class GenericAdminApiFieldMapping(StrictModel):
    source_pointer: BoundedText512
    record_field: MachineName


class GenericAdminApiCollector(_CollectorBase):
    type: Literal["generic_admin_api"]
    provider: Identifier
    base_url: HttpsUrl
    path: AdminApiPath
    field_mappings: list[GenericAdminApiFieldMapping] = Field(min_length=1)
    pagination_pointer: BoundedText512 | None = None
    max_response_bytes: int = Field(ge=1, le=_BYTES_MAX, default=1048576)
    max_pages: int = Field(ge=1, le=10000, default=1)


class AgentSummaryCollector(_CollectorBase):
    type: Literal["agent_summary"]
    path: ConfigDirRelativePathStr
    input_schema_version: int = Field(ge=1, le=1000)
    mode: Literal["json", "jsonl"] = "jsonl"
    target_alias_mapping: dict[Identifier, Identifier] = Field(default_factory=dict)


class CodexSessionCollector(_CollectorBase):
    type: Literal["codex_session"]
    sessions_root: AbsolutePathStr
    target_repo_mapping: dict[Identifier, Identifier] = Field(min_length=1)
    trace_categories: list[Identifier] = Field(default_factory=list)


class ClaudeSessionCollector(_CollectorBase):
    type: Literal["claude_session"]
    projects_root: AbsolutePathStr
    target_repo_mapping: dict[Identifier, Identifier] = Field(min_length=1)
    trace_categories: list[Identifier] = Field(default_factory=list)


CollectorConfig = Annotated[
    SiteCanaryCollector
    | FileOutboxCollector
    | ErrorReportFileCollector
    | WorkflowFileCollector
    | CloudflareCollector
    | GithubActionsCollector
    | GenericAdminApiCollector
    | AgentSummaryCollector
    | CodexSessionCollector
    | ClaudeSessionCollector,
    Field(discriminator="type"),
]

_COLLECTOR_PROVIDER_TYPE: dict[str, str] = {
    "cloudflare": "cloudflare",
    "github_actions": "github",
    "generic_admin_api": "generic_http",
}


# --- 4.8 providers -------------------------------------------------------------


class _ProviderBase(StrictModel):
    id: Identifier


class CloudflareProvider(_ProviderBase):
    type: Literal["cloudflare"]
    account_id_env: EnvVarRef
    token_env: EnvVarRef
    workers_token_env: EnvVarRef | None = None
    api_base_url: HttpsUrl | None = None
    allowed_accounts: list[Identifier] = Field(default_factory=list)
    allowed_zones: list[Identifier] = Field(default_factory=list)


class GithubProvider(_ProviderBase):
    type: Literal["github"]
    api_url: HttpsUrl = Url("https://api.github.com")
    read_token_env: EnvVarRef
    repository_allowlist: list[RepositorySlug] = Field(min_length=1)
    api_version: GithubApiVersion
    issue_write_token_env: EnvVarRef | None = None

    @model_validator(mode="after")
    def _check_unique_repositories(self) -> GithubProvider:
        _require_unique(self.repository_allowlist, label="repository_allowlist")
        return self


class GenericHttpProvider(_ProviderBase):
    type: Literal["generic_http"]
    auth_mode: Literal["bearer", "header"]
    token_env: EnvVarRef
    header_name: BoundedText128 | None = None
    header_scheme: BoundedText64 | None = None
    tls_verify: bool = True
    host_allowlist: list[BoundedText255] = Field(min_length=1)
    max_retries: int = Field(ge=0, le=100, default=3)
    rate_limit_per_minute: int = Field(ge=1, le=_COUNT_MAX, default=60)
    max_response_bytes: int = Field(ge=1, le=_BYTES_MAX, default=1048576)

    @model_validator(mode="after")
    def _check_header_mode(self) -> GenericHttpProvider:
        if self.auth_mode == "header" and self.header_name is None:
            raise ValueError("header_name is required when auth_mode is 'header'")
        return self


class ClickHouseHostedProvider(_ProviderBase):
    type: Literal["clickhouse_hosted"]
    url_env: EnvVarRef
    username_env: EnvVarRef
    password_env: EnvVarRef
    database: ClickHouseIdentifier
    tls_required: bool = True
    egress_allowlist: list[Literal["public", "internal", "sensitive"]] = Field(min_length=1)

    @model_validator(mode="after")
    def _check_unique_egress(self) -> ClickHouseHostedProvider:
        _require_unique(self.egress_allowlist, label="egress_allowlist")
        return self


ProviderConfig = Annotated[
    CloudflareProvider | GithubProvider | GenericHttpProvider | ClickHouseHostedProvider,
    Field(discriminator="type"),
]


# --- 4.14 notifications --------------------------------------------------------


class _NotificationBase(StrictModel):
    id: Identifier
    enabled: bool = False


def _default_public_classifications() -> list[Literal["public", "internal"]]:
    return ["public"]


class TelegramNotification(_NotificationBase):
    type: Literal["telegram"]
    bot_token_env: EnvVarRef
    chat_id_env: EnvVarRef
    allowed_classifications: list[Literal["public", "internal"]] = Field(
        default_factory=_default_public_classifications
    )
    urgent_alerts: bool = False
    weekly_summary: bool = False
    message_limit: int = Field(ge=1, le=4096, default=4096)
    retry_max_attempts: int = Field(ge=0, le=100, default=5)
    retry_backoff_seconds: int = Field(ge=1, le=_SECONDS_MAX, default=30)

    @model_validator(mode="after")
    def _check_unique_classifications(self) -> TelegramNotification:
        _require_unique(self.allowed_classifications, label="allowed_classifications")
        return self


class GithubIssuesNotification(_NotificationBase):
    type: Literal["github_issues"]
    provider: Identifier
    repository: RepositorySlug
    label_allowlist: list[Identifier] = Field(min_length=1)
    enabled_priorities: list[Literal["P0", "P1", "P2", "P3"]] = Field(min_length=1)
    enabled_actionabilities: list[
        Literal["observe", "investigate", "agent_safe", "needs_approval"]
    ] = Field(min_length=1)
    allowed_classifications: list[Literal["public", "internal"]] = Field(min_length=1)
    require_preview: bool = True
    idempotent_marker_prefix: Annotated[
        str, StringConstraints(pattern=r"^[a-z][a-z0-9:_-]{0,63}$")
    ] = "milhouse:"

    @model_validator(mode="after")
    def _check_unique_lists(self) -> GithubIssuesNotification:
        _require_unique(self.label_allowlist, label="label_allowlist")
        _require_unique(self.enabled_priorities, label="enabled_priorities")
        _require_unique(self.enabled_actionabilities, label="enabled_actionabilities")
        _require_unique(self.allowed_classifications, label="allowed_classifications")
        return self


NotificationConfig = Annotated[
    TelegramNotification | GithubIssuesNotification, Field(discriminator="type")
]


# --- 4.6 alert, incident, feedback rules ---------------------------------------


class CanaryStateAlertRule(StrictModel):
    id: Identifier
    type: Literal["canary_state"]
    collector: Identifier
    consecutive_failures: int = Field(ge=1, le=100)
    consecutive_successes: int = Field(ge=1, le=100)
    cooldown_seconds: int = Field(ge=0, le=_SECONDS_MAX)


AlertRuleConfig = CanaryStateAlertRule


class IncidentRuleConfig(StrictModel):
    id: Identifier
    target: Identifier
    alert_rule_ids: list[Identifier] = Field(min_length=1)
    group_dimensions: list[DimensionKey] = Field(default_factory=list)
    correlation_horizon_seconds: int = Field(ge=1, le=_SECONDS_MAX)
    quiet_window_seconds: int = Field(ge=0, le=_SECONDS_MAX)

    @model_validator(mode="after")
    def _check_unique_lists(self) -> IncidentRuleConfig:
        _require_unique(self.alert_rule_ids, label="alert_rule_ids")
        _require_unique(self.group_dimensions, label="group_dimensions")
        return self


class FeedbackRuleConfig(StrictModel):
    id: Identifier
    type: Literal["recurrence"]
    target: Identifier
    record_names: list[MachineName] = Field(min_length=1)
    minimum_occurrences: int = Field(ge=1, le=10000)
    window_seconds: int = Field(ge=1, le=31536000)
    priority: Literal["P0", "P1", "P2", "P3"]
    actionability: Literal["observe", "investigate", "agent_safe", "needs_approval"]

    @model_validator(mode="after")
    def _check_unique_record_names(self) -> FeedbackRuleConfig:
        _require_unique(self.record_names, label="record_names")
        return self


# --- 4.13 jobs -------------------------------------------------------------------

_WEEKDAYS = (
    "monday",
    "tuesday",
    "wednesday",
    "thursday",
    "friday",
    "saturday",
    "sunday",
)


class _JobBase(StrictModel):
    id: Identifier
    enabled: bool
    schedule: Literal["interval", "daily", "weekly"]
    interval_seconds: int | None = Field(default=None, ge=1, le=_SECONDS_MAX)
    weekday: Literal[_WEEKDAYS] | None = None  # type: ignore[valid-type]
    local_time: LocalTime | None = None
    timeout_seconds: int = Field(ge=1, le=_SECONDS_MAX)
    missed_run_policy: Literal["skip", "run_once"] = "run_once"

    @model_validator(mode="after")
    def _check_schedule_fields(self) -> _JobBase:
        if self.schedule == "interval":
            if self.interval_seconds is None:
                raise ValueError("interval_seconds is required when schedule is 'interval'")
            if self.weekday is not None or self.local_time is not None:
                raise ValueError("weekday and local_time are invalid when schedule is 'interval'")
        elif self.schedule == "daily":
            if self.local_time is None:
                raise ValueError("local_time is required when schedule is 'daily'")
            if self.interval_seconds is not None or self.weekday is not None:
                raise ValueError(
                    "interval_seconds and weekday are invalid when schedule is 'daily'"
                )
        else:
            if self.local_time is None or self.weekday is None:
                raise ValueError("weekday and local_time are required when schedule is 'weekly'")
            if self.interval_seconds is not None:
                raise ValueError("interval_seconds is invalid when schedule is 'weekly'")
        return self


class SpoolReplayJob(_JobBase):
    type: Literal["spool_replay"]


class CollectorJob(_JobBase):
    type: Literal["collector"]
    collector: Identifier


class FeedbackCurationJob(_JobBase):
    type: Literal["feedback_curation"]


class FeedbackVerificationJob(_JobBase):
    type: Literal["feedback_verification"]


class NotificationRetryJob(_JobBase):
    type: Literal["notification_retry"]


class RetentionApplyJob(_JobBase):
    type: Literal["retention_apply"]


class DailyReportJob(_JobBase):
    type: Literal["daily_report"]


class WeeklyReportJob(_JobBase):
    type: Literal["weekly_report"]


class BackupVerificationJob(_JobBase):
    type: Literal["backup_verification"]


JobConfig = Annotated[
    SpoolReplayJob
    | CollectorJob
    | FeedbackCurationJob
    | FeedbackVerificationJob
    | NotificationRetryJob
    | RetentionApplyJob
    | DailyReportJob
    | WeeklyReportJob
    | BackupVerificationJob,
    Field(discriminator="type"),
]


# --- root configuration ----------------------------------------------------------


def _validate_config_version(value: int) -> int:
    if value != CONFIG_VERSION:
        raise ValueError(f"config_version must equal {CONFIG_VERSION}")
    return value


ConfigVersion = Annotated[int, AfterValidator(_validate_config_version)]


class MilhouseConfig(StrictModel):
    config_version: ConfigVersion
    project: ProjectConfig
    paths: PathsConfig
    secrets: SecretsConfig = Field(default_factory=SecretsConfig)
    identity: IdentityConfig
    plugins: PluginsConfig = Field(default_factory=PluginsConfig)
    runtime: RuntimeConfig
    storage: StorageConfig
    privacy: PrivacyConfig
    retention: RetentionConfig
    scheduler: SchedulerConfig
    reports: ReportsConfig
    jobs: list[JobConfig] = Field(default_factory=list)
    mcp: MCPConfig
    postmortem: PostmortemConfig
    receiver: ReceiverConfig
    targets: list[TargetConfig] = Field(default_factory=list)
    collectors: list[CollectorConfig] = Field(default_factory=list)
    providers: list[ProviderConfig] = Field(default_factory=list)
    notifications: list[NotificationConfig] = Field(default_factory=list)
    alert_rules: list[AlertRuleConfig] = Field(default_factory=list)
    incident_rules: list[IncidentRuleConfig] = Field(default_factory=list)
    feedback_rules: list[FeedbackRuleConfig] = Field(default_factory=list)

    @model_validator(mode="after")
    def _check_cross_references(self) -> MilhouseConfig:
        target_ids = require_unique_ids(self.targets, label="targets")
        collector_ids = require_unique_ids(self.collectors, label="collectors")
        require_unique_ids(self.providers, label="providers")
        require_unique_ids(self.notifications, label="notifications")
        alert_rule_ids = require_unique_ids(self.alert_rules, label="alert_rules")
        require_unique_ids(self.incident_rules, label="incident_rules")
        require_unique_ids(self.feedback_rules, label="feedback_rules")
        require_unique_ids(self.jobs, label="jobs")
        require_unique_ids(self.receiver.sources, label="receiver.sources")

        if self.project.default_target not in target_ids:
            raise ValueError("project.default_target is not a declared target id")

        provider_by_id = {provider.id: provider for provider in self.providers}
        collector_by_id = {collector.id: collector for collector in self.collectors}

        for collector in self.collectors:
            if collector.target not in target_ids:
                raise ValueError("collector target is not a declared target id")
            provider_id = getattr(collector, "provider", None)
            if provider_id is not None:
                provider = provider_by_id.get(provider_id)
                if provider is None:
                    raise ValueError("collector provider is not a declared provider id")
                required_type = _COLLECTOR_PROVIDER_TYPE[collector.type]
                if provider.type != required_type:
                    raise ValueError("collector provider has an incompatible provider type")
            mapped_targets: Iterable[str]
            if isinstance(collector, AgentSummaryCollector):
                mapped_targets = collector.target_alias_mapping.values()
            elif isinstance(collector, (CodexSessionCollector, ClaudeSessionCollector)):
                mapped_targets = collector.target_repo_mapping.values()
            else:
                mapped_targets = ()
            if any(target_id not in target_ids for target_id in mapped_targets):
                raise ValueError("collector contains an undeclared mapped target id")

        for source in self.receiver.sources:
            if source.target not in target_ids:
                raise ValueError("receiver source target is not a declared target id")

        alert_rule_target: dict[str, str] = {}
        for rule in self.alert_rules:
            rule_collector = collector_by_id.get(rule.collector)
            if rule_collector is None:
                raise ValueError("alert rule collector is not a declared collector id")
            if rule_collector.type != "site_canary":
                raise ValueError("alert rule must reference a site_canary collector")
            alert_rule_target[rule.id] = rule_collector.target

        for incident_rule in self.incident_rules:
            if incident_rule.target not in target_ids:
                raise ValueError("incident rule target is not a declared target id")
            for alert_rule_id in incident_rule.alert_rule_ids:
                if alert_rule_id not in alert_rule_ids:
                    raise ValueError("incident rule references an undeclared alert rule id")
                if alert_rule_target[alert_rule_id] != incident_rule.target:
                    raise ValueError(
                        "incident rule references an alert rule bound to another target"
                    )

        for feedback_rule in self.feedback_rules:
            if feedback_rule.target not in target_ids:
                raise ValueError("feedback rule target is not a declared target id")

        for job in self.jobs:
            if job.type == "collector" and job.collector not in collector_ids:
                raise ValueError("collector job is not bound to a declared collector id")

        for notification in self.notifications:
            if notification.type == "github_issues":
                provider = provider_by_id.get(notification.provider)
                if provider is None:
                    raise ValueError("notification provider is not a declared provider id")
                if provider.type != "github":
                    raise ValueError("github issues notification requires a github provider")
                if notification.repository not in provider.repository_allowlist:
                    raise ValueError(
                        "notification repository is not allowlisted by its github provider"
                    )

        return self


__all__ = [
    "CONFIG_VERSION",
    "AbsolutePathStr",
    "AgentSummaryCollector",
    "AlertRuleConfig",
    "BackupVerificationJob",
    "CanaryStateAlertRule",
    "ClaudeSessionCollector",
    "ClickHouseHostedProvider",
    "ClickHouseIdentifier",
    "CloudflareCollector",
    "CloudflareProvider",
    "CodexSessionCollector",
    "CollectorConfig",
    "CollectorJob",
    "DailyReportJob",
    "DimensionKey",
    "ErrorReportFileCollector",
    "FeedbackCurationJob",
    "FeedbackRuleConfig",
    "FeedbackVerificationJob",
    "FileOutboxCollector",
    "GenericAdminApiCollector",
    "GenericAdminApiFieldMapping",
    "GenericHttpProvider",
    "GithubActionsCollector",
    "GithubIssuesNotification",
    "GithubProvider",
    "GithubWebhookSource",
    "HmacIngestSource",
    "Identifier",
    "IdentityConfig",
    "IncidentRuleConfig",
    "JobConfig",
    "MCPConfig",
    "MachineName",
    "MilhouseConfig",
    "NotificationConfig",
    "NotificationRetryJob",
    "PathsConfig",
    "PluginAllowlistEntry",
    "PluginsConfig",
    "PostmortemConfig",
    "PrivacyConfig",
    "ProjectConfig",
    "ProviderConfig",
    "ReceiverConfig",
    "ReceiverSource",
    "RelativePathStr",
    "ReportScheduleConfig",
    "ReportsConfig",
    "RetentionApplyJob",
    "RetentionConfig",
    "RuntimeConfig",
    "SchedulerConfig",
    "SecretsConfig",
    "SiteCanaryCollector",
    "SpoolReplayJob",
    "StorageClickHouseConfig",
    "StorageConfig",
    "StrictModel",
    "TargetConfig",
    "TelegramNotification",
    "WeeklyReportJob",
    "WorkflowFileCollector",
    "require_unique_ids",
]
