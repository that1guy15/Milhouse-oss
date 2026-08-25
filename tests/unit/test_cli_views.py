"""Tests for the read-only local inspect surface: spool/events/doctor."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from click.testing import CliRunner

from milhouse.cli import bootstrap, demo, views
from milhouse.cli.root import main
from milhouse.config import RuntimePaths, load_config, resolve_runtime_paths

_NOW = datetime(2026, 8, 3, 12, 0, 0, tzinfo=UTC)
_REPO_ROOT = Path(__file__).resolve().parents[2]
_EXAMPLE_CONFIG = (_REPO_ROOT / "config" / "example.toml").read_text(encoding="utf-8")


def _config_file(tmp_path: Path) -> Path:
    config_dir = tmp_path / "cfg"
    config_dir.mkdir()
    config_file = config_dir / "config.toml"
    config_file.write_text(_EXAMPLE_CONFIG, encoding="utf-8")
    return config_file


def _paths(tmp_path: Path) -> RuntimePaths:
    config_file = _config_file(tmp_path)
    config, config_path = load_config(config_file, platform_default=config_file)
    return resolve_runtime_paths(
        config, config_path=config_path, platform_data_root=tmp_path / "platform"
    )


def _init_with_key(tmp_path: Path) -> RuntimePaths:
    """Initialize an install WITH the pseudonym key so ``health``/``doctor`` report it healthy."""

    config_file = _config_file(tmp_path)
    config, config_path = load_config(config_file, platform_default=config_file)
    paths = resolve_runtime_paths(
        config, config_path=config_path, platform_data_root=tmp_path / "platform"
    )
    bootstrap.initialize(paths, now=_NOW, config=config)
    return paths


def test_list_segments_reports_spooled_segments(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    first = demo.run_demo(paths, now=_NOW)
    demo.run_demo(paths, now=_NOW)

    segments = views.list_segments(paths)

    assert len(segments) == 2
    batch_ids = {segment.batch_id for segment in segments}
    assert first.batch_id in batch_ids
    one = next(segment for segment in segments if segment.batch_id == first.batch_id)
    assert one.record_count == 1
    assert one.privacy_class == "internal"
    assert one.origin == "committed"
    assert one.byte_size > 0


def test_list_segments_is_empty_before_any_spooling(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    bootstrap.initialize(paths, now=_NOW)
    assert views.list_segments(paths) == ()


def test_read_events_returns_record_metadata(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    demo.run_demo(paths, now=_NOW)
    installation_id = bootstrap.read_installation_id(paths)
    assert installation_id is not None

    events = views.read_events(paths, installation_id)

    assert len(events) == 1
    event = events[0]
    assert event.record_id.startswith("mh_")
    assert event.record_type == "event"
    assert event.name == "source.event"
    assert event.target_id == "demo-target"
    assert event.privacy_class == "internal"
    assert event.occurred_at.endswith("Z")


def test_read_events_skips_an_unreadable_segment(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    report = demo.run_demo(paths, now=_NOW)
    installation_id = bootstrap.read_installation_id(paths)
    assert installation_id is not None
    # Corrupt the durable file: the trusted reader rejects it and the event is skipped, not raised.
    segment = paths.spool / "pending" / report.day / f"{report.batch_id}.jsonl"
    segment.write_bytes(b"not a valid segment")

    assert views.read_events(paths, installation_id) == ()


def test_show_segment_returns_detail_and_none_for_missing(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    report = demo.run_demo(paths, now=_NOW)
    installation_id = bootstrap.read_installation_id(paths)
    assert installation_id is not None

    detail = views.show_segment(paths, report.batch_id, installation_id)
    assert detail is not None
    assert detail.readable is True
    assert detail.summary.batch_id == report.batch_id
    assert len(detail.events) == 1

    assert views.show_segment(paths, "demo-does-not-exist", installation_id) is None


def test_show_segment_reports_an_unreadable_file(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    report = demo.run_demo(paths, now=_NOW)
    installation_id = bootstrap.read_installation_id(paths)
    assert installation_id is not None
    (paths.spool / "pending" / report.day / f"{report.batch_id}.jsonl").write_bytes(b"corrupt")

    detail = views.show_segment(paths, report.batch_id, installation_id)
    assert detail is not None
    assert detail.readable is False
    assert detail.events == ()


def test_doctor_reports_health_and_spool_totals(tmp_path: Path) -> None:
    # Provision the pseudonym key so the install is fully healthy; demo alone does not create it.
    paths = _init_with_key(tmp_path)
    demo.run_demo(paths, now=_NOW)
    demo.run_demo(paths, now=_NOW)

    report = views.doctor(paths, now=_NOW)

    assert report.ok is True
    assert report.segment_count == 2
    assert report.record_count == 2
    assert report.spool_readable is True


def test_doctor_is_unhealthy_before_init(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    report = views.doctor(paths, now=_NOW)
    assert report.ok is False
    assert report.segment_count == 0


# --- CLI surface ---------------------------------------------------------------------------------


def test_cli_spool_list_and_events_and_doctor(tmp_path: Path) -> None:
    config_file = _config_file(tmp_path)
    runner = CliRunner()
    # A full config-aware init provisions the pseudonym key so ``doctor`` reports the install ok.
    runner.invoke(main, ["--config", str(config_file), "init"])
    runner.invoke(main, ["--config", str(config_file), "demo"])

    listing = runner.invoke(main, ["--config", str(config_file), "spool", "list"])
    assert listing.exit_code == 0
    assert "records=1" in listing.output

    events = runner.invoke(main, ["--config", str(config_file), "events", "--json"])
    assert events.exit_code == 0
    assert '"record_type": "event"' in events.output

    doctor = runner.invoke(main, ["--config", str(config_file), "doctor"])
    assert doctor.exit_code == 0
    assert "status: ok" in doctor.output


def test_cli_spool_list_empty(tmp_path: Path) -> None:
    config_file = _config_file(tmp_path)
    runner = CliRunner()
    runner.invoke(main, ["--config", str(config_file), "init"])
    result = runner.invoke(main, ["--config", str(config_file), "spool", "list"])
    assert result.exit_code == 0
    assert "no committed segments" in result.output


def test_cli_events_requires_init(tmp_path: Path) -> None:
    config_file = _config_file(tmp_path)
    runner = CliRunner()
    result = runner.invoke(main, ["--config", str(config_file), "events"])
    assert result.exit_code == 1


def test_cli_spool_show_missing_exits_nonzero(tmp_path: Path) -> None:
    config_file = _config_file(tmp_path)
    runner = CliRunner()
    runner.invoke(main, ["--config", str(config_file), "init"])
    result = runner.invoke(main, ["--config", str(config_file), "spool", "show", "demo-nope"])
    assert result.exit_code == 1
    assert "no segment" in result.output
