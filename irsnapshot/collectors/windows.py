"""Read-only Windows adapters with strict, failure-preserving local boundaries."""
import base64
from datetime import UTC, datetime
import json
import math
import ntpath
import os
import platform
import stat
import struct
import subprocess

import psutil
from pydantic import ValidationError
from irsnapshot.models import EnvironmentValue, KnownPath, PathContext, TaskAction, TaskTrigger
from irsnapshot.collectors.contracts import (
    AdapterIssue, NoInputs, QueryInputs, QueryResponse, RunResponse, RunValue,
    ShortcutInputs, ShortcutRecord, ShortcutsResponse, StartupFile, StartupResponse,
    SystemReading, TaskRecord, TasksResponse, UserRecord, UsersResponse, WindowsQuery,
)
from irsnapshot.collectors.windows_native import KNOWN_FOLDERS, NativeWindows
from irsnapshot.collectors.windows_queries import SCRIPTS


class UnsupportedPlatformError(RuntimeError):
    """Live collection requires Windows x64 and 64-bit Python."""


def _issue(error, *, target=None, field=None, category=None):
    if category is None:
        category = 'access_denied' if isinstance(error, (PermissionError, psutil.AccessDenied)) else 'unavailable'
    return AdapterIssue(category=category, message='Windows source could not be read',
                        target=target, field=field, exception_type=type(error).__name__)


def _local_path(path):
    drive, tail = ntpath.splitdrive(path)
    return (len(drive) == 2 and drive[0].isalpha() and drive[1] == ':'
            and tail.startswith(('\\', '/')) and '\x00' not in path
            and not any(part == '..' for part in path.replace('/', '\\').split('\\')))


_RESPONSE_TYPES = {
    WindowsQuery.USERS: (UsersResponse, UserRecord),
    WindowsQuery.TASKS: (TasksResponse, TaskRecord),
    WindowsQuery.SHORTCUTS: (ShortcutsResponse, ShortcutRecord),
}


def _partial_record(model, raw, issues, target):
    """Retain required identity and readable fields when optional fields fail.

    Unknown properties are still rejected by the strict models. A malformed
    action retains its position as an 'other' action if its kind is unavailable.
    """
    if not isinstance(raw, dict):
        return model.model_validate(raw)
    candidate = dict(raw)
    if model is TaskRecord:
        for field, nested in (('actions', TaskAction), ('triggers', TaskTrigger)):
            values = candidate.get(field)
            if not isinstance(values, list):
                continue
            cleaned = []
            for index, value in enumerate(values):
                nested_target = f'{target}.{field}[{index}]'
                try:
                    cleaned.append(_partial_record(nested, value, issues, nested_target))
                except ValidationError as error:
                    issues.append(_issue(error, target=nested_target, field=field, category='invalid_data'))
                    if field == 'actions':
                        cleaned.append(TaskAction(kind='other'))
            candidate[field] = cleaned
    try:
        return model.model_validate(candidate)
    except ValidationError as error:
        invalid_fields = {e['loc'][0] for e in error.errors() if e['loc']}
        # Required identifiers and unknown fields must not be invented or ignored.
        if any(field not in model.model_fields or model.model_fields[field].is_required()
               for field in invalid_fields):
            raise
        for field in invalid_fields:
            candidate.pop(field, None)
            issues.append(_issue(error, target=target, field=str(field), category='invalid_data'))
        return model.model_validate(candidate)


class WindowsAdapter:
    def __init__(self, *, native=None, runner=None, psutil_module=None,
                 platform_name=None, pointer_bits=None, scandir=None, lstat=None):
        self.native = native if native is not None else NativeWindows()
        self.runner = runner if runner is not None else subprocess.run
        self.psutil = psutil_module if psutil_module is not None else psutil
        self.platform_name = platform_name
        self.pointer_bits = pointer_bits
        self.scandir = scandir if scandir is not None else os.scandir
        self.lstat = lstat if lstat is not None else os.lstat

    def ensure_supported(self):
        name = self.platform_name if self.platform_name is not None else platform.system()
        bits = self.pointer_bits if self.pointer_bits is not None else struct.calcsize('P') * 8
        if name != 'Windows' or bits != 64:
            raise UnsupportedPlatformError('Collection requires Windows 10/11 x64 with 64-bit Python and Windows PowerShell 5.1.')
        if self.native.architecture() != 'AMD64':
            raise UnsupportedPlatformError('Collection requires native Windows x64; ARM and x86 are unsupported.')

    def process_iter(self):
        self.ensure_supported()
        return self.psutil.process_iter()

    def net_connections(self):
        self.ensure_supported()
        return self.psutil.net_connections(kind='inet')

    def service_iter(self):
        self.ensure_supported()
        return self.psutil.win_service_iter()

    def sessions(self):
        self.ensure_supported()
        return self.psutil.users()

    def run_query(self, query: WindowsQuery, inputs: QueryInputs = NoInputs(), timeout_seconds: float = 30) -> QueryResponse:
        if not isinstance(query, WindowsQuery):
            raise ValueError('Query must be a WindowsQuery value')
        if not isinstance(timeout_seconds, (float, int)) or isinstance(timeout_seconds, bool) or not math.isfinite(timeout_seconds) or not 0 < timeout_seconds <= 120:
            raise ValueError('Query timeout must be between 0 and 120 seconds')
        if query == WindowsQuery.SHORTCUTS:
            if not isinstance(inputs, ShortcutInputs):
                raise ValueError('Shortcut query requires ShortcutInputs')
            inputs = ShortcutInputs.model_validate(inputs)
            if len(inputs.paths) > 10000 or any(not _local_path(p) or not p.lower().endswith('.lnk') or len(p) > 32767 for p in inputs.paths):
                raise ValueError('Shortcut paths must be bounded absolute local .lnk paths')
        elif not isinstance(inputs, NoInputs):
            raise ValueError('This query takes NoInputs')
        self.ensure_supported()
        response_type, record_type = _RESPONSE_TYPES[query]
        response = response_type()
        if query == WindowsQuery.SHORTCUTS:
            safe_paths = []
            for path in inputs.paths:
                try:
                    self._safe_local_access(path)
                    safe_paths.append(path)
                except Exception as error:
                    response.items.append(ShortcutRecord(path=path))
                    response.issues.append(_issue(error, target=path, field='target_path'))
            inputs = ShortcutInputs(paths=safe_paths)
            if not safe_paths:
                return response
        try:
            system = self.native.system_directory()
            windows = self.native.windows_directory()
            if not _local_path(system) or not _local_path(windows):
                raise ValueError('System directory must be a local Windows path')
            ps_home = ntpath.join(system, 'WindowsPowerShell', 'v1.0')
            executable = ntpath.join(ps_home, 'powershell.exe')
            encoded = base64.b64encode(SCRIPTS[query].encode('utf-16-le')).decode('ascii')
            # Never inherit PATH, PSModulePath, profiles or a user-controlled working directory.
            env = {'SystemRoot': windows, 'WINDIR': windows, 'PATH': system,
                   'PSModulePath': ntpath.join(ps_home, 'Modules')}
            result = self.runner([executable, '-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', encoded],
                input=inputs.model_dump_json().encode('utf-8'), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                shell=False, timeout=timeout_seconds, check=False, cwd=system, env=env)
        except subprocess.TimeoutExpired as error:
            response.issues.append(_issue(error, target=query.value, category='timeout'))
            return response
        except Exception as error:
            response.issues.append(_issue(error, target=query.value))
            return response
        if result.returncode != 0:
            response.issues.append(AdapterIssue(category='unavailable', message=f'PowerShell query exited with status {result.returncode}', target=query.value))
        if result.stderr and result.stderr.strip():
            response.issues.append(AdapterIssue(category='unavailable', message='PowerShell emitted diagnostic output', target=query.value))
        try:
            if len(result.stdout) > 32 * 1024 * 1024:
                raise ValueError('PowerShell response exceeds supported size')
            text = result.stdout.decode('utf-8-sig') if isinstance(result.stdout, bytes) else result.stdout
            payload = json.loads(text)
            if (not isinstance(payload, dict) or set(payload) != {'kind', 'items', 'issues'}
                    or payload['kind'] != query.value or not isinstance(payload['items'], list)
                    or not isinstance(payload['issues'], list)):
                raise ValueError('Invalid query response envelope')
        except (UnicodeError, ValueError, TypeError) as error:
            response.issues.append(_issue(error, target=query.value, category='parse_error'))
            return response
        for index, raw in enumerate(payload['issues']):
            try:
                response.issues.append(AdapterIssue.model_validate(raw))
            except ValidationError as error:
                response.issues.append(_issue(error, target=f'{query.value}.issues[{index}]', category='invalid_data'))
        for index, raw in enumerate(payload['items']):
            try:
                record = _partial_record(record_type, raw, response.issues, f'{query.value}.items[{index}]')
                response.items.append(record)
            except ValidationError as error:
                response.issues.append(_issue(error, target=f'{query.value}.items[{index}]', category='invalid_data'))
        return response

    def _safe_local_access(self, path):
        """Check every existing component before touching children or shortcut bytes.

        This is a best-effort race check, not a filesystem sandbox. A concurrently
        replaced directory can still change after inspection.
        """
        if not _local_path(path):
            raise ValueError('Non-local path is outside collection scope')
        drive, tail = ntpath.splitdrive(path)
        if self.native.drive_type(drive + '\\') not in (2, 3, 5, 6):
            raise ValueError('Remote or unavailable drive is outside collection scope')
        current = drive + '\\'
        for component in tail.replace('/', '\\').strip('\\').split('\\'):
            if not component or component == '.':
                continue
            current = ntpath.join(current, component)
            metadata = self.lstat(current)
            if getattr(metadata, 'st_file_attributes', 0) & 0x400 or stat.S_ISLNK(metadata.st_mode):
                raise ValueError('Reparse traversal is outside collection scope')

    def system_reading(self):
        self.ensure_supported()
        result = SystemReading()
        for field in ('hostname', 'windows_version', 'architecture', 'collector_username', 'collector_sid', 'elevated', 'boot_time'):
            try:
                value = (datetime.fromtimestamp(self.psutil.boot_time(), UTC) if field == 'boot_time'
                         else getattr(self.native, field)())
                if value is None or value == '':
                    raise ValueError('System field unavailable')
                validated = SystemReading(**{field: value})
                setattr(result, field, getattr(validated, field))
            except Exception as error:
                result.issues.append(_issue(error, field=field))
        sid = result.collector_sid
        for kind in KNOWN_FOLDERS:
            try:
                path = self.native.known_folder(kind)
                result.path_context.known_paths.append(KnownPath(kind=kind, path=path,
                    owner_sid=None if kind == 'common_startup' else sid, source='SHGetKnownFolderPath'))
            except Exception as error:
                result.issues.append(_issue(error, target=kind, field='path_context.known_paths'))
        try:
            result.path_context.known_paths.append(KnownPath(kind='windows', path=self.native.windows_directory(), source='GetWindowsDirectoryW'))
        except Exception as error:
            result.issues.append(_issue(error, target='windows', field='path_context.known_paths'))
        for name in ('USERPROFILE', 'APPDATA', 'LOCALAPPDATA', 'TEMP', 'TMP', 'SystemRoot', 'WINDIR', 'ProgramData', 'ProgramFiles', 'ProgramFiles(x86)'):
            try:
                value = self.native.environment_value(name)
                if not value:
                    raise ValueError('Path environment value unavailable')
                owner_specific = name in ('USERPROFILE', 'APPDATA', 'LOCALAPPDATA', 'TEMP', 'TMP')
                if owner_specific and sid is None:
                    result.issues.append(AdapterIssue(category='unavailable',
                        message='Per-user environment value omitted because token SID is unavailable',
                        target=name, field='path_context.environment'))
                    continue
                owner = sid if owner_specific else None
                result.path_context.environment.append(EnvironmentValue(name=name, value=value, owner_sid=owner))
                if name in ('TEMP', 'TMP') and _local_path(value):
                    result.path_context.known_paths.append(KnownPath(kind='temp', path=value, owner_sid=sid, source=f'GetEnvironmentVariableW({name})'))
            except Exception as error:
                result.issues.append(_issue(error, target=name, field='path_context.environment'))
        return result

    def read_run_values(self, owner_sid):
        self.ensure_supported()
        result = RunResponse()
        try:
            registry = self.native.registry()
        except Exception as error:
            result.issues.append(_issue(error, target='Run keys'))
            return result
        subkey = r'Software\Microsoft\Windows\CurrentVersion\Run'
        # Native denotes byte-identical values observed in BOTH explicit views.
        seen = {}
        type_names = {getattr(registry, name): name for name in (
            'REG_NONE', 'REG_SZ', 'REG_EXPAND_SZ', 'REG_BINARY', 'REG_DWORD', 'REG_DWORD_BIG_ENDIAN',
            'REG_LINK', 'REG_MULTI_SZ', 'REG_RESOURCE_LIST', 'REG_FULL_RESOURCE_DESCRIPTOR',
            'REG_RESOURCE_REQUIREMENTS_LIST', 'REG_QWORD') if hasattr(registry, name)}
        for hive_name in ('HKEY_CURRENT_USER', 'HKEY_LOCAL_MACHINE'):
            for view, flag in (('32', registry.KEY_WOW64_32KEY), ('64', registry.KEY_WOW64_64KEY)):
                location = hive_name + '\\' + subkey
                target = location + f' [{view}-bit view]'
                try:
                    key = registry.OpenKey(getattr(registry, hive_name), subkey, 0, registry.KEY_READ | flag)
                except FileNotFoundError:
                    continue
                except Exception as error:
                    result.issues.append(_issue(error, target=target))
                    continue
                try:
                    index = 0
                    while True:
                        try:
                            name, value, value_type = registry.EnumValue(key, index)
                        except OSError as error:
                            if getattr(error, 'winerror', None) == 259:
                                break
                            result.issues.append(_issue(error, target=target))
                            break
                        index += 1
                        command = value if value_type in (registry.REG_SZ, registry.REG_EXPAND_SZ) and isinstance(value, str) else None
                        if command is None:
                            result.issues.append(AdapterIssue(category='invalid_data', message='Run value is not a string command', target=target + '\\' + name, field='command'))
                        record = RunValue(location=location, entry_name=name, command=command,
                            owner_sid=owner_sid if hive_name == 'HKEY_CURRENT_USER' else None,
                            registry_view=view, registry_value_type=type_names.get(value_type, f'REG_TYPE_{value_type}'))
                        # The raw non-string value participates too; null commands alone are not identical.
                        identity = (location, name, value_type, type(value).__name__, repr(value))
                        if identity in seen:
                            seen[identity].registry_view = 'native'
                        else:
                            result.items.append(record)
                            seen[identity] = record
                except Exception as error:
                    result.issues.append(_issue(error, target=target))
                finally:
                    registry.CloseKey(key)
        return result

    def startup_files(self, path_context: PathContext):
        self.ensure_supported()
        result = StartupResponse()
        for kind in ('startup', 'common_startup'):
            roots = [p for p in path_context.known_paths if p.kind == kind]
            if not roots:
                result.issues.append(AdapterIssue(category='unavailable', message='Startup directory could not be discovered', target=kind))
            for root in roots:
                if not _local_path(root.path):
                    result.issues.append(AdapterIssue(category='unavailable', message='Non-local Startup directory is outside collection scope', target=root.path))
                    continue
                try:
                    self._safe_local_access(root.path)
                    with self.scandir(root.path) as entries:
                        for entry in entries:
                            try:
                                # No target reads: lstat and directory metadata only.
                                metadata = entry.stat(follow_symlinks=False)
                                if stat.S_ISDIR(metadata.st_mode):
                                    continue
                                result.items.append(StartupFile(path=entry.path, owner_sid=root.owner_sid))
                                if getattr(metadata, 'st_file_attributes', 0) & 0x400 or stat.S_ISLNK(metadata.st_mode):
                                    result.issues.append(AdapterIssue(category='unavailable', message='Startup reparse target is not traversed', target=entry.path))
                            except Exception as error:
                                result.issues.append(_issue(error, target=entry.path))
                except FileNotFoundError:
                    continue
                except Exception as error:
                    result.issues.append(_issue(error, target=root.path))
        return result
