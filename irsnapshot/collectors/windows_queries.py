"""Fixed read-only Windows PowerShell 5.1 projections. Inputs are never script text."""
from irsnapshot.collectors.contracts import WindowsQuery

_PREFIX = r'''
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
[Console]::InputEncoding = New-Object System.Text.UTF8Encoding($false)
$items = New-Object 'System.Collections.Generic.List[object]'
$issues = New-Object 'System.Collections.Generic.List[object]'
function Issue($err, [string]$target, [string]$field) {
    $category = 'unavailable'
    if ($err.Exception -is [System.UnauthorizedAccessException] -or $err.CategoryInfo.Category -eq 'PermissionDenied') { $category = 'access_denied' }
    $issues.Add(@{category=$category; message='Windows source could not be read'; target=$target; field=$field; exception_type=$err.Exception.GetType().FullName})
}
function S($value) { if ($null -eq $value) { return $null }; return [string]$value }
'''
_USERS = r'''
try {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    try {
        $qualified = $identity.Name -split '\\', 2
        $name = $qualified[-1]; $domain = $null
        if ($qualified.Count -eq 2) { $domain = $qualified[0] }
        $items.Add(@{name=$name; domain=$domain; sid=$identity.User.Value; source='current_token'})
    } finally { $identity.Dispose() }
} catch { Issue $_ 'current_token' '' }
try {
    # The bundled module may store its manifest in a version subdirectory.
    # Resolve it under this trusted absolute directory, never a user module path.
    Import-Module ($PSHOME + '\Modules\Microsoft.PowerShell.LocalAccounts') -ErrorAction Stop
    Get-LocalUser -ErrorAction Stop | ForEach-Object {
        try { $items.Add(@{name=$_.Name; sid=$_.SID.Value; source='local_account'; enabled=$_.Enabled}) }
        catch { Issue $_ 'local_accounts' '' }
    }
} catch { Issue $_ 'local_accounts' '' }
try {
    Import-Module ($PSHOME + '\Modules\Microsoft.PowerShell.LocalAccounts') -ErrorAction Stop
    Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop | ForEach-Object {
        try {
            $qualified = $_.Name -split '\\', 2
            $name = $qualified[-1]; $domain = $null
            if ($qualified.Count -eq 2) { $domain = $qualified[0] }
            $items.Add(@{name=$name; domain=$domain; sid=$_.SID.Value; source='local_admin_member'; member_of_sid='S-1-5-32-544'})
        } catch { Issue $_ 'local_admin_members' '' }
    }
} catch { Issue $_ 'local_admin_members' '' }
@{kind='users'; items=@($items.ToArray()); issues=@($issues.ToArray())} | ConvertTo-Json -Depth 12 -Compress
'''
_TASKS = r'''
try {
    Import-Module ($PSHOME + '\Modules\ScheduledTasks\ScheduledTasks.psd1') -ErrorAction Stop
    Get-ScheduledTask -ErrorAction Stop | ForEach-Object {
        $task = $_
        $target = $task.TaskPath + $task.TaskName
        $actions = New-Object 'System.Collections.Generic.List[object]'
        $triggers = New-Object 'System.Collections.Generic.List[object]'
        foreach ($action in $task.Actions) {
            try {
                $class = $action.CimClass.CimClassName
                $kind = 'other'
                if ($class -eq 'MSFT_TaskExecAction') { $kind = 'exec' }
                if ($class -eq 'MSFT_TaskComHandlerAction') { $kind = 'com_handler' }
                $actions.Add(@{kind=$kind; executable=(S $action.Execute); arguments=(S $action.Arguments); working_directory=(S $action.WorkingDirectory); class_id=(S $action.ClassId)})
            } catch {
                $actions.Add(@{kind='other'})
                Issue $_ $target 'actions'
            }
        }
        foreach ($trigger in $task.Triggers) {
            try {
                $triggers.Add(@{kind=[string]$trigger.CimClass.CimClassName; enabled=$trigger.Enabled;
                    start_boundary_raw=(S $trigger.StartBoundary); end_boundary_raw=(S $trigger.EndBoundary);
                    user_id=(S $trigger.UserId); repetition_interval=(S $trigger.Repetition.Interval)})
            } catch { Issue $_ $target 'triggers' }
        }
        try {
            $principal = S $task.Principal.UserId
            if (-not $principal) { $principal = S $task.Principal.GroupId }
            $items.Add(@{name=$task.TaskName; task_path=$target; state=[string]$task.State;
                enabled=$task.Settings.Enabled; principal=$principal; actions=@($actions.ToArray()); triggers=@($triggers.ToArray())})
        } catch { Issue $_ $target '' }
    }
} catch { Issue $_ 'scheduled_tasks' '' }
@{kind='tasks'; items=@($items.ToArray()); issues=@($issues.ToArray())} | ConvertTo-Json -Depth 12 -Compress
'''
_SHORTCUTS = r'''
$inputData = [Console]::In.ReadToEnd() | ConvertFrom-Json
$shell = $null
try { $shell = New-Object -ComObject WScript.Shell }
catch { Issue $_ 'shortcuts' '' }
foreach ($path in $inputData.paths) {
    $record = @{path=[string]$path; target_path=$null; arguments=$null}
    $link = $null
    if ($null -ne $shell) {
        try {
            if (-not [System.IO.File]::Exists($path)) { throw 'Shortcut file is unavailable' }
            $link = $shell.CreateShortcut($path)
            $record.target_path = S $link.TargetPath
            $record.arguments = S $link.Arguments
            if (-not $record.target_path) { throw 'Shortcut target is unresolved' }
        } catch { Issue $_ ([string]$path) 'target_path' }
        finally { if ($null -ne $link) { [void][System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($link) } }
    }
    $items.Add($record)
}
if ($null -ne $shell) { [void][System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($shell) }
@{kind='shortcuts'; items=@($items.ToArray()); issues=@($issues.ToArray())} | ConvertTo-Json -Depth 12 -Compress
'''

SCRIPTS = {WindowsQuery.USERS: _PREFIX + _USERS, WindowsQuery.TASKS: _PREFIX + _TASKS,
           WindowsQuery.SHORTCUTS: _PREFIX + _SHORTCUTS}
