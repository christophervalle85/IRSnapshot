"""Collection orchestration contracts with endpoint access replaced at its boundary."""
from datetime import UTC, datetime, timedelta
import socket
from types import SimpleNamespace
from uuid import UUID

import pytest

from irsnapshot.collectors.base import CollectionContext, SystemInventory
from irsnapshot.models import (CollectionIssue, CollectionStatus, CollectorName,
                               CollectorResult, CollectorRun, KnownPath,
                               PathContext, PersistenceArtifact, ServiceArtifact,
                               SystemInfo)
from irsnapshot.pipeline import collect_snapshot


class Clock:
    def __init__(self):
        self.value = datetime(2026, 9, 17, 12, tzinfo=UTC)

    def __call__(self):
        self.value += timedelta(seconds=1)
        return self.value


class Adapter:
    def __init__(self, error=None):
        self.error = error
        self.checked = False

    def ensure_supported(self):
        self.checked = True
        if self.error:
            raise self.error


def _context(adapter=None):
    return CollectionContext(snapshot_id=UUID(int=1), clock=Clock(),
                             windows=adapter or Adapter())


def _result(context, name, items=(), status=CollectionStatus.OK):
    start = context.clock()
    end = context.clock()
    issues = [] if status == CollectionStatus.OK else [CollectionIssue(
        collector=name, category="unavailable", message="Source unavailable",
        observed_at=end)]
    return CollectorResult(items=list(items), run=CollectorRun(
        collector=name, status=status, started_at=start, finished_at=end,
        item_count=len(items), scope=["fixture scope"], issues=issues))


def _system(context):
    start = context.clock()
    observed = context.clock()
    system = SystemInfo(
        artifact_id=UUID(int=2), observed_at=observed, hostname="host",
        windows_version="Windows 11", architecture="AMD64", current_time=observed,
        boot_time=observed - timedelta(days=1), collector_username="DOMAIN\\alice",
        collector_sid="S-1-5-21-1", elevated=False)
    paths = PathContext(known_paths=[KnownPath(kind="profile", path="C:\\Users\\alice",
                                               owner_sid="S-1-5-21-1", source="fixture")])
    return CollectorResult(items=[SystemInventory(system=system, path_context=paths)],
                           run=CollectorRun(collector=CollectorName.SYSTEM,
                                            status=CollectionStatus.OK, started_at=start,
                                            finished_at=context.clock(), item_count=1,
                                            scope=["fixture system scope"]))


def _install_collectors(monkeypatch, overrides=None):
    import irsnapshot.pipeline as pipeline
    overrides = overrides or {}
    calls = []
    for name in CollectorName:
        module = getattr(pipeline, name.value)
        if name == CollectorName.SYSTEM:
            behavior = lambda context: _system(context)
        elif name == CollectorName.PERSISTENCE:
            behavior = lambda context, services, tasks: _result(context, name)
        else:
            behavior = lambda context, _name=name: _result(context, _name)
        behavior = overrides.get(name, behavior)
        def wrapped(*args, _name=name, _behavior=behavior):
            calls.append(_name)
            return _behavior(*args)
        monkeypatch.setattr(module, "collect", wrapped)
    return calls


def test_seven_runs_and_system_context_reach_later_collectors(monkeypatch):
    observed = {}
    def processes(context):
        observed["path"] = context.path_context.known_paths[0].path
        observed["sid"] = context.collector_sid
        return _result(context, CollectorName.PROCESSES)
    calls = _install_collectors(monkeypatch, {CollectorName.PROCESSES: processes})
    context = _context()

    snapshot = collect_snapshot(context)

    assert context.windows.checked
    assert calls == list(CollectorName)
    assert [run.status for run in snapshot.collector_runs] == [CollectionStatus.OK] * 7
    assert snapshot.system.hostname == "host"
    assert observed == {"path": "C:\\Users\\alice", "sid": "S-1-5-21-1"}
    assert snapshot.path_context.known_paths[0].owner_sid == "S-1-5-21-1"
    assert snapshot.started_at < snapshot.finished_at


def test_one_source_exception_preserves_other_evidence_and_safe_issue(monkeypatch, caplog):
    def broken(context):
        raise RuntimeError("secret raw command")
    _install_collectors(monkeypatch, {CollectorName.PROCESSES: broken})

    snapshot = collect_snapshot(_context())

    runs = {run.collector: run for run in snapshot.collector_runs}
    assert runs[CollectorName.PROCESSES].status == CollectionStatus.FAILED
    assert runs[CollectorName.PROCESSES].issues[0].exception_type == "RuntimeError"
    assert "secret raw command" not in runs[CollectorName.PROCESSES].issues[0].message
    assert snapshot.system.hostname == "host"
    assert runs[CollectorName.NETWORK].status == CollectionStatus.OK
    assert "Traceback" in caplog.text


def test_malformed_source_result_isolated_and_context_mutation_restored(monkeypatch):
    def broken(context):
        context.collector_sid = "S-1-wrong"
        context.path_context = PathContext()
        context.snapshot_id = UUID(int=999)
        context.clock = lambda: datetime(2100, 1, 1, tzinfo=UTC)
        return SimpleNamespace(items=[], run="wrong")
    seen = {}
    def users(context):
        seen["sid"] = context.collector_sid
        seen["paths"] = len(context.path_context.known_paths)
        return _result(context, CollectorName.USERS)
    _install_collectors(monkeypatch, {CollectorName.NETWORK: broken,
                                     CollectorName.USERS: users})

    snapshot = collect_snapshot(_context())

    assert {r.collector: r.status for r in snapshot.collector_runs}[CollectorName.NETWORK] == CollectionStatus.FAILED
    assert seen == {"sid": "S-1-5-21-1", "paths": 1}
    assert snapshot.path_context.known_paths[0].kind == "profile"
    assert snapshot.snapshot_id == UUID(int=1)


def test_system_failure_keeps_all_runs_without_inventing_identity(monkeypatch):
    def broken(context):
        raise RuntimeError("missing system")
    calls = _install_collectors(monkeypatch, {CollectorName.SYSTEM: broken})

    snapshot = collect_snapshot(_context())

    assert calls == list(CollectorName)
    assert snapshot.system is None
    assert snapshot.path_context == PathContext()
    assert {r.collector: r.status for r in snapshot.collector_runs}[CollectorName.SYSTEM] == CollectionStatus.FAILED


def test_missing_service_scope_marks_persistence_partial(monkeypatch):
    seen = {}
    def services(context):
        return _result(context, CollectorName.SERVICES, status=CollectionStatus.FAILED)
    def persistence(context, services, tasks):
        seen["services"] = services
        seen["tasks"] = tasks
        return _result(context, CollectorName.PERSISTENCE)
    _install_collectors(monkeypatch, {CollectorName.SERVICES: services,
                                     CollectorName.PERSISTENCE: persistence})

    snapshot = collect_snapshot(_context())

    run = {r.collector: r for r in snapshot.collector_runs}[CollectorName.PERSISTENCE]
    assert run.status == CollectionStatus.PARTIAL
    assert run.issues[0].category == "unavailable"
    assert "services" in run.issues[0].message
    assert seen == {"services": [], "tasks": []}


def test_invalid_persistence_reference_fails_only_persistence(monkeypatch):
    def services(context):
        start = context.clock()
        item = ServiceArtifact(artifact_id=UUID(int=40), observed_at=context.clock(),
                               name="svc", command="C:\\svc.exe")
        return CollectorResult(items=[item], run=CollectorRun(
            collector=CollectorName.SERVICES, status=CollectionStatus.OK,
            started_at=start, finished_at=context.clock(), item_count=1,
            scope=["fixture services"]))
    def persistence(context, services, tasks):
        start = context.clock()
        item = PersistenceArtifact(
            artifact_id=UUID(int=41), observed_at=context.clock(),
            kind="service", location="Services", entry_name="bad",
            source_artifact_id=UUID(int=999))
        return CollectorResult(items=[item], run=CollectorRun(
            collector=CollectorName.PERSISTENCE, status=CollectionStatus.OK,
            started_at=start, finished_at=context.clock(), item_count=1,
            scope=["fixture persistence"]))
    _install_collectors(monkeypatch, {CollectorName.SERVICES: services,
                                     CollectorName.PERSISTENCE: persistence})

    snapshot = collect_snapshot(_context())

    assert [item.name for item in snapshot.services] == ["svc"]
    assert snapshot.persistence == []
    assert {r.collector: r.status for r in snapshot.collector_runs}[CollectorName.PERSISTENCE] == CollectionStatus.FAILED


def test_persistence_cannot_mutate_accepted_service_evidence(monkeypatch):
    def services(context):
        start = context.clock()
        item = ServiceArtifact(artifact_id=UUID(int=50), observed_at=context.clock(),
                               name="original", command="C:\\trusted.exe")
        return CollectorResult(items=[item], run=CollectorRun(
            collector=CollectorName.SERVICES, status=CollectionStatus.OK,
            started_at=start, finished_at=context.clock(), item_count=1,
            scope=["fixture services"]))
    def persistence(context, services, tasks):
        services[0].command = "C:\\tampered.exe"
        return _result(context, CollectorName.PERSISTENCE)
    _install_collectors(monkeypatch, {CollectorName.SERVICES: services,
                                     CollectorName.PERSISTENCE: persistence})

    snapshot = collect_snapshot(_context())

    assert snapshot.services[0].command == "C:\\trusted.exe"


def test_future_collector_interval_fails_only_that_source(monkeypatch):
    def network(context):
        now = context.clock()
        return CollectorResult(items=[], run=CollectorRun(
            collector=CollectorName.NETWORK, status=CollectionStatus.OK,
            started_at=now, finished_at=now + timedelta(hours=1), item_count=0,
            scope=["fixture network"]))
    _install_collectors(monkeypatch, {CollectorName.NETWORK: network})

    snapshot = collect_snapshot(_context())

    assert {r.collector: r.status for r in snapshot.collector_runs}[CollectorName.NETWORK] == CollectionStatus.FAILED
    assert snapshot.system.hostname == "host"


def test_platform_guard_precedes_every_collector(monkeypatch):
    calls = _install_collectors(monkeypatch)
    context = _context(Adapter(error=RuntimeError("unsupported")))

    with pytest.raises(RuntimeError, match="unsupported"):
        collect_snapshot(context)

    assert context.windows.checked
    assert calls == []


def test_keyboard_interrupt_propagates_without_later_sources(monkeypatch):
    def interrupted(context):
        raise KeyboardInterrupt
    calls = _install_collectors(monkeypatch, {CollectorName.PROCESSES: interrupted})

    with pytest.raises(KeyboardInterrupt):
        collect_snapshot(_context())

    assert calls == [CollectorName.SYSTEM, CollectorName.PROCESSES]


def test_real_collectors_integrate_through_typed_adapter_and_round_trip(tmp_path, monkeypatch):
    """Catch broken interfaces between the seven real normalizers and snapshot model."""
    from irsnapshot.analyzers.engine import analyze_snapshot
    from irsnapshot.collectors.contracts import (
        RunResponse, RunValue, ShortcutRecord, ShortcutsResponse, StartupFile,
        StartupResponse, SystemReading, TaskRecord, TasksResponse, UserRecord,
        UsersResponse, WindowsQuery,
    )
    from irsnapshot.models import TaskAction
    from irsnapshot.storage import load_snapshot, write_snapshot

    class Process:
        pid = 45
        def ppid(self): return 0
        def name(self): return "example.exe"
        def exe(self): return "C:\\Program Files\\Example\\example.exe"
        def cmdline(self): return [self.exe(), "--ready"]
        def username(self): return "EXAMPLE\\alice"
        def create_time(self): return datetime(2026, 9, 16, tzinfo=UTC).timestamp()

    class Service:
        def name(self): return "ExampleSvc"
        def display_name(self): return "Example Service"
        def status(self): return "running"
        def binpath(self): return '"C:\\Program Files\\Example\\svc.exe"'
        def start_type(self): return "auto"
        def username(self): return "LocalSystem"
        def pid(self): return 45

    class TypedAdapter:
        def ensure_supported(self): pass
        def system_reading(self):
            return SystemReading(
                hostname="example-host", windows_version="Windows 11",
                architecture="AMD64", boot_time=datetime(2026, 9, 16, tzinfo=UTC),
                collector_username="EXAMPLE\\alice", collector_sid="S-1-5-21-1",
                elevated=False, path_context=PathContext(known_paths=[
                    KnownPath(kind="profile", path="C:\\Users\\alice", source="fixture",
                              owner_sid="S-1-5-21-1")]))
        def process_iter(self): return iter([Process()])
        def net_connections(self):
            return [SimpleNamespace(family=socket.AF_INET, type=socket.SOCK_STREAM,
                                    laddr=("127.0.0.1", 4444), raddr=(),
                                    status="LISTEN", pid=45)]
        def service_iter(self): return iter([Service()])
        def sessions(self): return []
        def read_run_values(self, owner_sid):
            assert owner_sid == "S-1-5-21-1"
            return RunResponse(items=[RunValue(
                location="HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                entry_name="Example", command='"C:\\Program Files\\Example\\example.exe"',
                owner_sid=owner_sid, registry_view="64", registry_value_type="REG_SZ")])
        def startup_files(self, path_context):
            assert path_context.known_paths[0].owner_sid == "S-1-5-21-1"
            return StartupResponse(items=[StartupFile(
                path="C:\\Users\\alice\\Startup\\Example.lnk", owner_sid="S-1-5-21-1")])
        def run_query(self, query, inputs=None, timeout_seconds=30):
            if query == WindowsQuery.USERS:
                return UsersResponse(items=[UserRecord(
                    name="alice", sid="S-1-5-21-1", source="current_token")])
            if query == WindowsQuery.TASKS:
                return TasksResponse(items=[TaskRecord(
                    name="ExampleTask", task_path="\\ExampleTask", enabled=True,
                    actions=[TaskAction(kind="exec", executable="C:\\Program Files\\Example\\task.exe")])])
            assert query == WindowsQuery.SHORTCUTS
            assert inputs.paths == ["C:\\Users\\alice\\Startup\\Example.lnk"]
            return ShortcutsResponse(items=[ShortcutRecord(
                path=inputs.paths[0], target_path="C:\\Program Files\\Example\\example.exe")])

    counter = iter(range(100, 120))
    context = CollectionContext(snapshot_id=UUID(int=1), clock=Clock(),
                                id_factory=lambda: UUID(int=next(counter)),
                                windows=TypedAdapter())
    snapshot = collect_snapshot(context)

    assert all(run.status == CollectionStatus.OK for run in snapshot.collector_runs)
    assert len(snapshot.collector_runs) == 7
    assert [entry.kind for entry in snapshot.persistence] == [
        "run_key", "startup_folder", "service", "scheduled_task"]
    service_projection = next(item for item in snapshot.persistence if item.kind == "service")
    task_projection = next(item for item in snapshot.persistence if item.kind == "scheduled_task")
    assert service_projection.source_artifact_id == snapshot.services[0].artifact_id
    assert task_projection.source_artifact_id == snapshot.scheduled_tasks[0].artifact_id
    assert task_projection.action_index == 0
    destination = tmp_path / "integrated.snapshot.json"
    write_snapshot(snapshot, destination)
    restored = load_snapshot(destination)
    assert restored.snapshot_id == snapshot.snapshot_id
    assert analyze_snapshot(restored).snapshot_id == snapshot.snapshot_id

    # Exercise the full workflow through the same seven actual normalizers.
    import irsnapshot.investigation as investigation
    from irsnapshot.models import InvestigationReport
    workflow_ids = iter(range(100, 120))
    workflow_context = CollectionContext(snapshot_id=UUID(int=2), clock=Clock(),
                                        id_factory=lambda: UUID(int=next(workflow_ids)),
                                        windows=TypedAdapter())
    monkeypatch.setattr(investigation, 'collect_snapshot', lambda: collect_snapshot(workflow_context))
    output = tmp_path / 'full-investigation'
    report = investigation.run_investigation(output)
    assert all(run.status == CollectionStatus.OK for run in report.snapshot.collector_runs)
    assert len(report.snapshot.collector_runs) == 7
    assert load_snapshot(output / 'snapshot.json') == report.snapshot
    assert InvestigationReport.model_validate_json((output / 'analysis.json').read_bytes()) == report
    assert 'example-host' in (output / 'report.html').read_text()
    assert report.analysis.network_links[0].process_id == report.snapshot.processes[0].artifact_id
