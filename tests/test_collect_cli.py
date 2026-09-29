"""Collect command behavior with live endpoint collection replaced at its boundary."""
from pathlib import Path
from datetime import UTC, datetime
import logging
import sys

from typer.testing import CliRunner

from irsnapshot.cli import app
from irsnapshot.models import CollectionIssue, CollectionStatus
from irsnapshot.storage import load_snapshot


runner = CliRunner()
SAMPLE = Path(__file__).resolve().parents[1] / "samples" / "benign.snapshot.json"


def test_collect_publishes_valid_snapshot_and_prints_literal_coverage(tmp_path, monkeypatch):
    import irsnapshot.cli as cli
    source = load_snapshot(SAMPLE)
    source.system.collector_username = "[red]user\x1b[2J"
    monkeypatch.setattr(cli, "collect_snapshot", lambda: source)
    destination = tmp_path / "[red]snapshot[red].json"

    result = runner.invoke(app, ["collect", "--output", str(destination)])

    assert result.exit_code == 0, result.output
    assert load_snapshot(destination).snapshot_id == source.snapshot_id
    assert str(source.snapshot_id) in result.output
    assert "[red]snapshot[red].json" in result.output
    assert "system" in result.output and "persistence" in result.output
    assert "[red]user\\x1b[2J" in result.output
    assert "\x1b" not in result.output
    assert "S-1-5-21-100-200-300-1001" in result.output
    assert "elevated: no" in result.output


def test_collect_refuses_existing_destination_before_endpoint_calls(tmp_path, monkeypatch):
    import irsnapshot.cli as cli
    destination = tmp_path / "existing.json"
    destination.write_text("leave intact")
    calls = []
    monkeypatch.setattr(cli, "collect_snapshot", lambda: calls.append("collected"))

    result = runner.invoke(app, ["collect", "--output", str(destination)])

    assert result.exit_code == 1
    assert destination.read_text() == "leave intact"
    assert calls == []


def test_collect_overwrite_is_explicit(tmp_path, monkeypatch):
    import irsnapshot.cli as cli
    source = load_snapshot(SAMPLE)
    monkeypatch.setattr(cli, "collect_snapshot", lambda: source)
    destination = tmp_path / "existing.json"
    destination.write_text("old")

    result = runner.invoke(app, ["collect", "--output", str(destination), "--overwrite"])

    assert result.exit_code == 0, result.output
    assert load_snapshot(destination).snapshot_id == source.snapshot_id


def test_partial_collection_is_saved_and_exits_three(tmp_path, monkeypatch):
    import irsnapshot.cli as cli
    source = load_snapshot(SAMPLE)
    run = source.collector_runs[2]
    run.status = CollectionStatus.PARTIAL
    run.issues = [CollectionIssue(collector=run.collector, category="access_denied",
                                  message="Some connections unavailable",
                                  observed_at=run.finished_at)]
    monkeypatch.setattr(cli, "collect_snapshot", lambda: source)
    destination = tmp_path / "partial.json"

    result = runner.invoke(app, ["collect", "--output", str(destination)])

    assert result.exit_code == 3, result.output
    assert load_snapshot(destination).collector_runs[2].status == CollectionStatus.PARTIAL
    assert "partial" in result.output
    assert "1 issue" in result.output
    assert "Analyze saved snapshot to inspect issues" in result.output


def test_platform_failure_is_actionable_and_does_not_publish(tmp_path, monkeypatch):
    import irsnapshot.cli as cli
    from irsnapshot.collectors.windows import UnsupportedPlatformError
    monkeypatch.setattr(cli, "collect_snapshot", lambda: (_ for _ in ()).throw(
        UnsupportedPlatformError("Windows 10/11 x64 and 64-bit Python are required")))
    destination = tmp_path / "capture.json"

    result = runner.invoke(app, ["collect", "--output", str(destination)])

    assert result.exit_code == 1
    assert not destination.exists()
    assert "Windows" in result.output and "64-bit" in result.output


def test_fatal_and_interrupt_never_publish_partial_file(tmp_path, monkeypatch):
    import irsnapshot.cli as cli
    destination = tmp_path / "capture.json"
    for exception, exit_code in [(RuntimeError("raw secret"), 1),
                                 (KeyboardInterrupt(), 130)]:
        monkeypatch.setattr(cli, "collect_snapshot", lambda _exc=exception:
                            (_ for _ in ()).throw(_exc))
        result = runner.invoke(app, ["collect", "--output", str(destination)])
        assert result.exit_code == exit_code
        assert "raw secret" not in result.output
        assert not destination.exists()


def test_collect_usage_requires_output_and_overwrite_requires_output():
    assert runner.invoke(app, ["collect"]).exit_code == 2
    assert runner.invoke(app, ["collect", "--overwrite"]).exit_code == 2


def test_collector_traceback_renders_control_chars_literally_and_saves_partial(tmp_path, monkeypatch, capsys):
    """A source exception and its cause must not send terminal controls to stderr."""
    import irsnapshot.cli as cli
    import irsnapshot.pipeline as pipeline
    from irsnapshot.collectors.base import CollectionContext
    from irsnapshot.collectors.contracts import (
        RunResponse, StartupResponse, SystemReading, TasksResponse, UsersResponse,
        WindowsQuery,
    )
    from irsnapshot.models import CollectorName

    class Adapter:
        def ensure_supported(self): pass
        def system_reading(self):
            return SystemReading(
                hostname="fixture", windows_version="Windows 11", architecture="AMD64",
                boot_time=datetime(2020, 1, 1, tzinfo=UTC),
                collector_username="fixture-user", collector_sid="S-1-5-21-1",
                elevated=False)
        def net_connections(self): return []
        def service_iter(self): return iter(())
        def sessions(self): return []
        def run_query(self, query, inputs=None, timeout_seconds=30):
            if query == WindowsQuery.USERS:
                return UsersResponse()
            if query == WindowsQuery.TASKS:
                return TasksResponse()
            raise AssertionError("unexpected query")
        def read_run_values(self, owner_sid): return RunResponse()
        def startup_files(self, path_context): return StartupResponse()

    def broken_processes(context):
        try:
            raise ValueError("cause\rspoof")
        except ValueError as cause:
            raise RuntimeError("captured\x1b[2Jname") from cause

    monkeypatch.setattr(pipeline.processes, "collect", broken_processes)
    terminal_logger = logging.getLogger("irsnapshot.test.terminal")
    terminal_logger.handlers = [logging.StreamHandler(sys.stderr)]
    terminal_logger.setLevel(logging.ERROR)
    terminal_logger.propagate = False
    monkeypatch.setattr(pipeline, "logger", terminal_logger)
    context = CollectionContext(windows=Adapter())
    monkeypatch.setattr(cli, "collect_snapshot", lambda: pipeline.collect_snapshot(context))
    destination = tmp_path / "partial.json"

    result = runner.invoke(app, ["collect", "--output", str(destination)])
    logged = capsys.readouterr().err

    assert result.exit_code == 3, result.output
    assert destination.exists()
    snapshot = load_snapshot(destination)
    assert {r.collector: r.status for r in snapshot.collector_runs}[CollectorName.PROCESSES] == CollectionStatus.FAILED
    assert "Traceback (most recent call last)" in logged
    assert "ValueError: cause\\rspoof" in logged
    assert "RuntimeError: captured\\x1b[2Jname" in logged
    assert "\x1b" not in logged
    assert "\r" not in logged
