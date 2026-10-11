"""Temporary read-only CI probe; print only type names, counts and durations."""
import base64
from collections import Counter
import json
import os
import re
import subprocess
import time

from irsnapshot.collectors.contracts import WindowsQuery
from irsnapshot.collectors.windows import WindowsAdapter


def probe(query, additions, limit):
    def runner(arguments, **kwargs):
        arguments = list(arguments)
        script = base64.b64decode(arguments[-1]).decode('utf-16-le')
        # Preserve control flow; retain inner type names without error messages.
        script = script.replace(
            'exception_type=$err.Exception.GetType().FullName',
            "exception_type=(@($err.Exception.GetType().FullName; if ($err.Exception.InnerException) { $err.Exception.InnerException.GetType().FullName }) -join '>')",
        )
        arguments[-1] = base64.b64encode(script.encode('utf-16-le')).decode('ascii')
        kwargs['env'] = {**kwargs['env'], **additions}
        return subprocess.run(arguments, **kwargs)

    started = time.monotonic()
    response = WindowsAdapter(runner=runner).run_query(query, timeout_seconds=limit)
    issues = []
    for issue in response.issues:
        kind = issue.exception_type or 'none'
        # No messages, paths, identities or command evidence leave this probe.
        if not re.fullmatch(r'[A-Za-z0-9_.>+`]{1,250}', kind):
            kind = 'other'
        target = issue.target if issue.target in {
            'current_token', 'local_accounts', 'local_admin_members', 'users', 'tasks',
            'scheduled_tasks',
        } else 'other'
        issues.append({'target': target, 'category': issue.category, 'type': kind})
    return {'seconds': round(time.monotonic() - started, 2), 'items': len(response.items),
            'sources': dict(Counter(getattr(item, 'source', 'task') for item in response.items)),
            'issues': issues}


if __name__ == '__main__':
    native = WindowsAdapter().native
    variants = {
        'baseline': {},
        'native_computername': {'COMPUTERNAME': native.hostname()},
        'system_drive': {'SystemDrive': os.path.splitdrive(native.windows_directory())[0]},
        'profile_paths': {key: os.environ[key] for key in (
            'USERPROFILE', 'LOCALAPPDATA', 'APPDATA', 'TEMP', 'TMP') if key in os.environ},
    }
    for label, additions in variants.items():
        print(json.dumps({'variant': label, 'users': probe(WindowsQuery.USERS, additions, 30)}), flush=True)
    print(json.dumps({'tasks_120_seconds': probe(WindowsQuery.TASKS, {}, 120)}), flush=True)
