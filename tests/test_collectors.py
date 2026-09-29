"""Portable collector tests; Windows calls are replaced at the adapter boundary."""
from datetime import UTC, datetime
from types import SimpleNamespace

import psutil

from irsnapshot.collectors import processes
from irsnapshot.collectors.base import CollectionContext
from irsnapshot.models import CollectionStatus


NOW = datetime(2026, 9, 27, 12, tzinfo=UTC)


class Process:
    pid = 0

    def ppid(self):
        return 0

    def name(self):
        return 'System Idle Process'

    def exe(self):
        raise psutil.AccessDenied(0)

    def cmdline(self):
        return []

    def username(self):
        raise psutil.NoSuchProcess(0)

    def create_time(self):
        return NOW.timestamp() + 3600


def test_process_field_failures_retain_pid_zero_and_readable_fields():
    adapter = SimpleNamespace(process_iter=lambda: iter([Process()]))
    context = CollectionContext(windows=adapter, clock=lambda: NOW)
    result = processes.collect(context)
    assert result.run.status == CollectionStatus.PARTIAL
    assert result.run.item_count == 1
    assert result.items[0].pid == 0
    assert result.items[0].name == 'System Idle Process'
    assert result.items[0].executable is None
    assert result.items[0].created_at is None
    assert {issue.field for issue in result.run.issues} == {'executable', 'username', 'created_at'}
    assert all(issue.artifact_id == result.items[0].artifact_id for issue in result.run.issues)


def test_system_missing_fields_and_future_boot_are_explicit():
    from irsnapshot.collectors import system
    from irsnapshot.collectors.contracts import SystemReading
    reading = SystemReading(hostname='HOST', boot_time=NOW.replace(year=2027))
    context = CollectionContext(windows=SimpleNamespace(system_reading=lambda: reading), clock=lambda: NOW)
    result = system.collect(context)
    assert result.run.item_count == 1
    assert result.items[0].system.hostname == 'HOST'
    assert result.items[0].system.boot_time is None
    assert result.items[0].system.current_time == NOW
    assert 'boot_time' in {issue.field for issue in result.run.issues}
    assert all(issue.artifact_id == result.items[0].system.artifact_id for issue in result.run.issues)


def test_network_retains_valid_ipv6_udp_when_neighbor_invalid():
    import socket
    from irsnapshot.collectors import network
    valid = SimpleNamespace(family=socket.AF_INET6, type=socket.SOCK_DGRAM,
                            laddr=('::1', 53), raddr=(), status='NONE', pid=0)
    invalid = SimpleNamespace(family=socket.AF_INET, type=socket.SOCK_STREAM,
                              laddr=('not-an-ip', 80), raddr=(), status='LISTEN', pid=4)
    context = CollectionContext(windows=SimpleNamespace(net_connections=lambda: [valid, invalid]), clock=lambda: NOW)
    result = network.collect(context)
    assert len(result.items) == 1
    assert result.items[0].family == 'ipv6'
    assert result.items[0].protocol == 'udp'
    assert result.items[0].state is None
    assert result.items[0].owning_pid == 0
    assert result.run.status == CollectionStatus.PARTIAL


def test_users_retain_sessions_when_account_query_fails():
    from irsnapshot.collectors import users
    from irsnapshot.collectors.contracts import AdapterIssue, UsersResponse
    session = SimpleNamespace(name='alice', terminal='console', started=NOW.timestamp() - 30)
    adapter = SimpleNamespace(sessions=lambda: [session], run_query=lambda *args, **kwargs:
        UsersResponse(issues=[AdapterIssue(category='access_denied', message='accounts denied')]))
    result = users.collect(CollectionContext(windows=adapter, clock=lambda: NOW))
    assert len(result.items) == 1
    assert result.items[0].source == 'logged_in_session'
    assert result.items[0].session_name == 'console'
    assert result.run.status == CollectionStatus.PARTIAL


def test_service_field_denial_retains_other_fields():
    from irsnapshot.collectors import services
    class Service:
        def name(self): return 'Svc'
        def display_name(self): return 'Service'
        def status(self): return 'running'
        def binpath(self): raise psutil.AccessDenied(1)
        def start_type(self): return 'automatic'
        def username(self): return 'LocalSystem'
        def pid(self): return 4
    result = services.collect(CollectionContext(
        windows=SimpleNamespace(service_iter=lambda: [Service()]), clock=lambda: NOW))
    assert len(result.items) == 1
    assert result.items[0].name == 'Svc'
    assert result.items[0].command is None
    assert result.items[0].pid == 4
    assert result.run.issues[0].field == 'command'


def test_tasks_keep_multiple_actions_and_offsetless_trigger_raw():
    from irsnapshot.collectors import scheduled_tasks
    from irsnapshot.collectors.contracts import TaskRecord, TasksResponse
    from irsnapshot.models import TaskAction, TaskTrigger
    record = TaskRecord(name='Task', task_path='\\Task', actions=[
        TaskAction(kind='exec', executable='a.exe', arguments='-x'),
        TaskAction(kind='com_handler', class_id='{abc}'),
    ], triggers=[TaskTrigger(kind='time', start_boundary_raw='2026-09-27T12:00:00')])
    result = scheduled_tasks.collect(CollectionContext(
        windows=SimpleNamespace(run_query=lambda *args, **kwargs: TasksResponse(items=[record])),
        clock=lambda: NOW))
    assert len(result.items[0].actions) == 2
    assert result.items[0].triggers[0].start_at is None
    assert result.items[0].triggers[0].start_boundary_raw == '2026-09-27T12:00:00'


def test_persistence_keeps_run_views_unresolved_shortcut_and_all_projections():
    from irsnapshot.collectors import persistence
    from irsnapshot.collectors.contracts import (AdapterIssue, RunResponse, RunValue,
        StartupResponse, StartupFile, ShortcutsResponse)
    from irsnapshot.models import ServiceArtifact, ScheduledTaskArtifact, TaskAction
    from uuid import uuid4
    service = ServiceArtifact(artifact_id=uuid4(), observed_at=NOW, name='Svc', command='svc.exe')
    task = ScheduledTaskArtifact(artifact_id=uuid4(), observed_at=NOW, name='Task', task_path='\\Task',
                                 actions=[TaskAction(kind='exec', executable='one.exe'),
                                          TaskAction(kind='com_handler', class_id='{abc}')])
    run = RunResponse(items=[RunValue(location='HKLM\\Run', entry_name='X', command='x.exe',
        owner_sid=None, registry_view=view, registry_value_type='REG_SZ') for view in ('32', '64')])
    startup = StartupResponse(items=[StartupFile(path='C:\\Startup\\bad.lnk')])
    shortcuts = ShortcutsResponse(issues=[AdapterIssue(category='access_denied',
        message='shortcut denied', target='C:\\Startup\\bad.lnk')])
    adapter = SimpleNamespace(read_run_values=lambda sid: run, startup_files=lambda paths: startup,
                              run_query=lambda *args, **kwargs: shortcuts)
    result = persistence.collect(CollectionContext(windows=adapter, clock=lambda: NOW), [service], [task])
    assert len(result.items) == 6
    assert {x.registry_view for x in result.items if x.kind == 'run_key'} == {'32', '64'}
    assert next(x for x in result.items if x.kind == 'startup_folder').target_path is None
    assert {x.action_index for x in result.items if x.kind == 'scheduled_task'} == {0, 1}
    assert next(x for x in result.items if x.kind == 'service').source_artifact_id == service.artifact_id
    assert result.run.status == CollectionStatus.PARTIAL


def test_invalid_optional_process_value_is_nulled_without_losing_process():
    class InvalidProcess(Process):
        pid = 7
        def ppid(self): return -1
        def exe(self): return 'C:\\a.exe'
        def username(self): return 'alice'
        def create_time(self): return NOW.timestamp() - 1
    result = processes.collect(CollectionContext(
        windows=SimpleNamespace(process_iter=lambda: [InvalidProcess()]), clock=lambda: NOW))
    assert len(result.items) == 1
    assert result.items[0].ppid is None
    assert any(issue.field == 'ppid' and issue.artifact_id == result.items[0].artifact_id
               for issue in result.run.issues)


def test_process_iterator_failure_keeps_previous_process():
    def iterator():
        yield Process()
        raise psutil.AccessDenied(8)
    result = processes.collect(CollectionContext(
        windows=SimpleNamespace(process_iter=lambda: iterator()), clock=lambda: NOW))
    assert len(result.items) == 1
    assert result.run.status == CollectionStatus.PARTIAL
    assert any(issue.category == 'access_denied' for issue in result.run.issues)


def test_invalid_service_pid_is_nulled_without_losing_service():
    from irsnapshot.collectors import services
    class Service:
        def name(self): return 'Svc'
        def display_name(self): return None
        def status(self): return None
        def binpath(self): return None
        def start_type(self): return None
        def username(self): return None
        def pid(self): return -1
    result = services.collect(CollectionContext(
        windows=SimpleNamespace(service_iter=lambda: [Service()]), clock=lambda: NOW))
    assert len(result.items) == 1
    assert result.items[0].pid is None
    assert result.run.issues[0].field == 'pid'


def test_invalid_network_owner_pid_keeps_connection_without_owner():
    import socket
    from irsnapshot.collectors import network
    conn = SimpleNamespace(family=socket.AF_INET, type=socket.SOCK_STREAM,
                           laddr=('127.0.0.1', 80), raddr=(), status='LISTEN', pid=-1)
    result = network.collect(CollectionContext(
        windows=SimpleNamespace(net_connections=lambda: [conn]), clock=lambda: NOW))
    assert len(result.items) == 1
    assert result.items[0].owning_pid is None
    assert result.run.issues[0].field == 'owning_pid'


def test_missing_shortcut_response_is_visible_and_path_retained():
    from irsnapshot.collectors import persistence
    from irsnapshot.collectors.contracts import RunResponse, StartupResponse, StartupFile, ShortcutsResponse
    adapter = SimpleNamespace(read_run_values=lambda sid: RunResponse(),
        startup_files=lambda paths: StartupResponse(items=[StartupFile(path='C:\\Startup\\missing.lnk')]),
        run_query=lambda *args, **kwargs: ShortcutsResponse())
    result = persistence.collect(CollectionContext(windows=adapter, clock=lambda: NOW), [], [])
    assert len(result.items) == 1
    assert result.items[0].target_path is None
    assert any(issue.artifact_id == result.items[0].artifact_id and issue.field == 'target_path'
               for issue in result.run.issues)


def test_projected_commands_quote_path_and_preserve_arguments():
    from irsnapshot.collectors import persistence
    from irsnapshot.collectors.contracts import (RunResponse, StartupResponse, StartupFile,
        ShortcutsResponse, ShortcutRecord)
    from irsnapshot.models import ScheduledTaskArtifact, TaskAction
    from uuid import uuid4
    task = ScheduledTaskArtifact(artifact_id=uuid4(), observed_at=NOW, name='Task', task_path='\\Task',
        actions=[TaskAction(kind='exec', executable='C:\\Program Files\\task.exe', arguments='-x')])
    adapter = SimpleNamespace(read_run_values=lambda sid: RunResponse(),
        startup_files=lambda paths: StartupResponse(items=[StartupFile(path='C:\\Startup\\a.lnk')]),
        run_query=lambda *args, **kwargs: ShortcutsResponse(items=[ShortcutRecord(
            path='C:\\Startup\\a.lnk', target_path='C:\\Program Files\\app.exe', arguments='-y')]))
    result = persistence.collect(CollectionContext(windows=adapter, clock=lambda: NOW), [], [task])
    assert next(x for x in result.items if x.kind == 'startup_folder').command == '"C:\\Program Files\\app.exe" -y'
    assert next(x for x in result.items if x.kind == 'scheduled_task').command == '"C:\\Program Files\\task.exe" -x'


def test_wrong_query_response_kind_cannot_be_clean_empty_users_or_tasks():
    from irsnapshot.collectors import users, scheduled_tasks
    from irsnapshot.collectors.contracts import TasksResponse, UsersResponse
    user_result = users.collect(CollectionContext(windows=SimpleNamespace(
        run_query=lambda *args, **kwargs: TasksResponse(), sessions=lambda: []), clock=lambda: NOW))
    task_result = scheduled_tasks.collect(CollectionContext(windows=SimpleNamespace(
        run_query=lambda *args, **kwargs: UsersResponse()), clock=lambda: NOW))
    assert user_result.run.status != CollectionStatus.OK
    assert task_result.run.status != CollectionStatus.OK


def test_invalid_remote_endpoint_retains_valid_local_connection():
    import socket
    from irsnapshot.collectors import network
    conn = SimpleNamespace(family=socket.AF_INET, type=socket.SOCK_STREAM,
                           laddr=('127.0.0.1', 80), raddr=('invalid', 443),
                           status='ESTABLISHED', pid=4)
    result = network.collect(CollectionContext(
        windows=SimpleNamespace(net_connections=lambda: [conn]), clock=lambda: NOW))
    assert len(result.items) == 1
    assert result.items[0].remote is None
    assert any(issue.field == 'remote' and issue.artifact_id == result.items[0].artifact_id
               for issue in result.run.issues)
