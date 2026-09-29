"""Collect command behavior with live endpoint collection replaced at its boundary."""
from pathlib import Path

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
