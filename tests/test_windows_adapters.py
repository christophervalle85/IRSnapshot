"""Portable boundary tests: no Windows APIs or evidence commands are executed."""
import importlib.util


def test_typed_windows_contracts_exist():
    assert importlib.util.find_spec('irsnapshot.collectors.contracts') is not None

import json
import subprocess
from types import SimpleNamespace
import pytest
from pydantic import ValidationError
from irsnapshot.collectors.contracts import (
    NoInputs, ShortcutInputs, SystemReading, WindowsQuery,
)


def adapter(payload=None, **overrides):
    from irsnapshot.collectors.windows import WindowsAdapter
    captured = []
    def runner(args, **kwargs):
        captured.append((args, kwargs))
        return subprocess.CompletedProcess(args, 0, json.dumps(payload).encode('utf-8'), b'')
    native = SimpleNamespace(system_directory=lambda: r'C:\Windows\System32',
                             windows_directory=lambda: r'C:\Windows', architecture=lambda: 'AMD64', drive_type=lambda root: 3)
    options = dict(native=native, runner=runner, platform_name='Windows', pointer_bits=64, lstat=lambda path: SimpleNamespace(st_mode=0o100644, st_file_attributes=0))
    options.update(overrides)
    return WindowsAdapter(**options), captured


def test_unsupported_platform_rejected_before_native_or_runner():
    a, calls = adapter(platform_name='Darwin')
    from irsnapshot.collectors.windows import UnsupportedPlatformError
    with pytest.raises(UnsupportedPlatformError):
        a.ensure_supported()
    assert not calls
    a, _ = adapter(pointer_bits=32)
    with pytest.raises(UnsupportedPlatformError):
        a.ensure_supported()
    a, _ = adapter(native=SimpleNamespace(architecture=lambda: 'ARM64'))
    with pytest.raises(UnsupportedPlatformError):
        a.ensure_supported()


@pytest.mark.parametrize('items', [[], [{'name': 'Renée', 'source': 'local_account'}]])
def test_query_arrays_and_unicode(items):
    a, _ = adapter({'kind': 'users', 'items': items, 'issues': []})
    response = a.run_query(WindowsQuery.USERS)
    assert len(response.items) == len(items)
    assert not response.issues
    if items:
        assert response.items[0].name == 'Renée'


def test_bad_item_does_not_discard_valid_sibling():
    a, _ = adapter({'kind': 'users', 'items': [{'name': 'valid', 'source': 'local_account'},
                                            {'name': 9, 'source': 'local_account'}], 'issues': []})
    result = a.run_query(WindowsQuery.USERS)
    assert [u.name for u in result.items] == ['valid']
    assert result.issues[0].category == 'invalid_data'


@pytest.mark.parametrize('payload', [None, {}, [], {'kind': 'tasks', 'items': [], 'issues': []},
    {'kind': 'users', 'items': {}, 'issues': []},
    {'kind': 'users', 'items': [], 'issues': [], 'extra': True}])
def test_malformed_envelopes_are_not_empty_success(payload):
    a, _ = adapter(payload)
    result = a.run_query(WindowsQuery.USERS)
    assert not result.items
    assert result.issues


@pytest.mark.parametrize('outcome,category', [('timeout', 'timeout'), ('nonzero', 'unavailable'),
    ('malformed', 'parse_error'), ('empty', 'parse_error'), ('stderr', 'unavailable')])
def test_transport_failures_are_reported(outcome, category):
    def runner(args, **kwargs):
        if outcome == 'timeout':
            raise subprocess.TimeoutExpired(args, 1)
        return subprocess.CompletedProcess(args, 1 if outcome == 'nonzero' else 0,
            b'!' if outcome == 'malformed' else b'' if outcome == 'empty' else b'{"kind":"users","items":[],"issues":[]}',
            b'permission denied' if outcome == 'stderr' else b'')
    a, _ = adapter(runner=runner)
    result = a.run_query(WindowsQuery.USERS)
    assert result.issues[0].category == category


def test_shortcut_inputs_are_json_data_never_script_or_shell(monkeypatch):
    monkeypatch.setenv('SystemRoot', r'C:\attacker')
    monkeypatch.setenv('PSModulePath', r'C:\attacker')
    path = "C:\\Startup\\'; Invoke-Expression bad; #💾.lnk"
    a, calls = adapter({'kind': 'shortcuts', 'items': [{'path': path}], 'issues': []})
    result = a.run_query(WindowsQuery.SHORTCUTS, ShortcutInputs(paths=[path]), timeout_seconds=5)
    assert result.items[0].path == path
    args, kwargs = calls[0]
    assert args[0] == r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
    assert path not in ' '.join(args)
    assert json.loads(kwargs['input']) == {'paths': [path]}
    assert kwargs['shell'] is False and kwargs['timeout'] == 5
    assert 'attacker' not in str(kwargs['env'])
    assert '-NoProfile' in args and '-NonInteractive' in args
    assert '-ExecutionPolicy' not in args


def test_query_inputs_reject_wrong_variant_and_remote_paths_before_calls():
    a, calls = adapter()
    for query, inputs in [(WindowsQuery.USERS, ShortcutInputs()),
                          (WindowsQuery.SHORTCUTS, NoInputs()),
                          (WindowsQuery.SHORTCUTS, ShortcutInputs(paths=[r'\\server\share\a.lnk']))]:
        with pytest.raises(ValueError):
            a.run_query(query, inputs)
    assert not calls


def test_strict_independent_contract_defaults():
    first, second = SystemReading(), SystemReading()
    first.issues.append({'x': 1})
    assert second.issues == []
    with pytest.raises(ValidationError):
        SystemReading(elevated=1)


def test_bad_optional_and_nested_fields_preserve_readable_task():
    a, _ = adapter({'kind': 'tasks', 'items': [{'name': 'Job', 'task_path': '\\Folder\\Job',
        'enabled': 'no', 'actions': [{'kind': 'exec', 'executable': 'one.exe'},
                                  {'kind': 'exec', 'executable': 99}, {'kind': 'com_handler', 'class_id': '{clsid}'}],
        'triggers': [{'kind': 'daily', 'start_boundary_raw': '2026-01-01T10:00:00'}, {'kind': 5}]}], 'issues': []})
    result = a.run_query(WindowsQuery.TASKS)
    assert len(result.items) == 1
    task = result.items[0]
    assert task.task_path == '\\Folder\\Job' and task.enabled is None
    assert [a.kind for a in task.actions] == ['exec', 'exec', 'com_handler']
    assert task.actions[1].executable is None
    assert task.triggers[0].start_at is None
    assert task.triggers[0].start_boundary_raw == '2026-01-01T10:00:00'
    assert len(result.issues) >= 3


def test_system_field_and_path_failures_are_independent():
    def denied(*args):
        raise PermissionError('denied')
    native = SimpleNamespace(architecture=lambda: 'AMD64', hostname=lambda: 'endpoint',
        windows_version=denied, collector_username=lambda: 'user', collector_sid=denied,
        elevated=lambda: False, windows_directory=lambda: r'C:\Windows', known_folder=denied,
        environment_value=denied)
    a, _ = adapter(native=native, psutil_module=SimpleNamespace(boot_time=lambda: 0))
    result = a.system_reading()
    assert result.hostname == 'endpoint' and result.elevated is False
    assert result.boot_time.isoformat() == '1970-01-01T00:00:00+00:00'
    assert {i.field for i in result.issues} >= {'windows_version', 'collector_sid', 'path_context.known_paths', 'path_context.environment'}
    assert len(result.issues) == 17


class FakeRegistry:
    HKEY_CURRENT_USER = 'HKCU'
    HKEY_LOCAL_MACHINE = 'HKLM'
    KEY_READ = 1
    KEY_WOW64_32KEY = 32
    KEY_WOW64_64KEY = 64
    REG_SZ = 1
    REG_EXPAND_SZ = 2
    REG_DWORD = 4
    def __init__(self, values):
        self.values, self.opened, self.closed = values, [], []
    def OpenKey(self, hive, path, reserved, access):
        key = (hive, access & ~1)
        self.opened.append(key)
        value = self.values.get(key, FileNotFoundError())
        if isinstance(value, Exception):
            raise value
        return key
    def EnumValue(self, key, index):
        values = self.values[key]
        if index < len(values):
            value = values[index]
            if isinstance(value, Exception):
                raise value
            return value
        error = OSError('No more data'); error.winerror = 259
        raise error
    def CloseKey(self, key):
        self.closed.append(key)


def test_registry_views_exact_duplicate_and_nonstring_preservation():
    registry = FakeRegistry({('HKCU', 32): [('same', '%APPDATA%\\x.exe', 2), ('different', 'x.exe', 1), ('binary', 4, 4)],
                             ('HKCU', 64): [('same', '%APPDATA%\\x.exe', 2), ('different', 'y.exe', 1), ('binary', 5, 4)],
                             ('HKLM', 32): PermissionError('denied')})
    a, _ = adapter(native=SimpleNamespace(architecture=lambda: 'AMD64', registry=lambda: registry))
    result = a.read_run_values('S-1-5-21-owner')
    assert len(registry.opened) == 4 and len(registry.closed) == 2
    assert len(result.items) == 5
    shared = result.items[0]
    assert shared.registry_view == 'native' and shared.command == '%APPDATA%\\x.exe'
    assert shared.owner_sid == 'S-1-5-21-owner'
    assert [i.registry_view for i in result.items if i.entry_name == 'different'] == ['32', '64']
    assert all(i.command is None for i in result.items if i.entry_name == 'binary')
    assert [i.category for i in result.issues].count('access_denied') == 1
    assert [i.category for i in result.issues].count('invalid_data') == 2


def test_registry_partial_enumeration_preserves_values():
    registry = FakeRegistry({('HKLM', 64): [('first', 'one.exe', 1), PermissionError('denied')]})
    a, _ = adapter(native=SimpleNamespace(architecture=lambda: 'AMD64', registry=lambda: registry))
    result = a.read_run_values(None)
    assert [i.entry_name for i in result.items] == ['first']
    assert result.issues[0].category == 'access_denied'


def test_remote_and_reparse_startup_roots_are_not_enumerated():
    from irsnapshot.models import KnownPath, PathContext
    calls = []
    def scan(path):
        calls.append(path)
        raise AssertionError('unsafe enumeration')
    context = PathContext(known_paths=[KnownPath(kind='startup', path=r'\\server\share', source='fixture'),
        KnownPath(kind='common_startup', path=r'C:\junction\Startup', source='fixture')])
    a, _ = adapter(scandir=scan, lstat=lambda path: SimpleNamespace(st_mode=0o040755, st_file_attributes=0x400))
    result = a.startup_files(context)
    assert len(result.issues) == 2 and not calls


def test_shortcut_reparse_and_mapped_remote_drive_preserved_without_query():
    native = SimpleNamespace(architecture=lambda: 'AMD64', drive_type=lambda root: 4)
    a, calls = adapter(native=native)
    result = a.run_query(WindowsQuery.SHORTCUTS, ShortcutInputs(paths=[r'Z:\Startup\shortcut.lnk']))
    assert [i.path for i in result.items] == [r'Z:\Startup\shortcut.lnk']
    assert result.issues and not calls


def test_unknown_sid_does_not_promote_per_user_environment_to_global():
    def denied():
        raise PermissionError('token denied')
    native = SimpleNamespace(architecture=lambda: 'AMD64', hostname=lambda: 'endpoint',
        windows_version=lambda: 'Windows 11', collector_username=lambda: 'user', collector_sid=denied,
        elevated=lambda: False, windows_directory=lambda: r'C:\Windows',
        known_folder=lambda kind: r'C:\Users\user\AppData', environment_value=lambda name: r'C:\Users\user\AppData')
    a, _ = adapter(native=native, psutil_module=SimpleNamespace(boot_time=lambda: 0))
    result = a.system_reading()
    assert not ({e.name for e in result.path_context.environment} & {'USERPROFILE', 'APPDATA', 'LOCALAPPDATA', 'TEMP', 'TMP'})
    assert any(i.target == 'APPDATA' for i in result.issues)
    from irsnapshot.analyzers.paths import classify_path
    assert classify_path(r'%APPDATA%\bad.exe', result.path_context, None).confidence == 'unresolved'
