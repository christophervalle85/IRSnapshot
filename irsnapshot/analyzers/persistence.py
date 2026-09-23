"""Pure, conservative interpretation of captured Windows persistence targets.

The scanner intentionally implements only a small argument subset.  It never
uses the analyst host's shell, environment, filesystem, or process APIs.
"""

from dataclasses import dataclass
import ntpath
from typing import Literal

from irsnapshot.analyzers.commands import parse_command_target
from irsnapshot.models import TaskAction


TargetKind = Literal["executable", "script", "unresolved"]
TargetProvenance = Literal[
    "raw_command_executable",
    "powershell_file",
    "script_host_file",
    "task_action_executable",
    "unresolved",
]


@dataclass(frozen=True)
class PersistenceTarget:
    """One interpreted target plus the original values and parsing limitation."""

    path: str | None
    kind: TargetKind
    provenance: TargetProvenance
    raw_value: str | None
    executable: str | None
    arguments: str | None
    reason: str


_EXECUTABLE_SUFFIXES = (".exe", ".com")
_POWERSHELL_NAMES = {"powershell", "powershell.exe", "pwsh", "pwsh.exe"}
_SCRIPT_HOST_NAMES = {"wscript", "wscript.exe", "cscript", "cscript.exe"}
_SCRIPT_HOST_SUFFIXES = (".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh")
_POWERSHELL_FLAG_OPTIONS = {
    "nologo": "nologo", "nol": "nologo",
    "noprofile": "noprofile", "nop": "noprofile",
    "noninteractive": "noninteractive", "noni": "noninteractive",
    "noexit": "noexit", "noe": "noexit", "sta": "sta", "mta": "mta",
}
_POWERSHELL_VALUE_OPTIONS = {
    "executionpolicy": "executionpolicy", "ep": "executionpolicy",
    "inputformat": "inputformat", "inp": "inputformat", "if": "inputformat",
    "outputformat": "outputformat", "o": "outputformat", "of": "outputformat",
    "configurationname": "configurationname", "config": "configurationname",
    "workingdirectory": "workingdirectory", "wd": "workingdirectory",
}
_POWERSHELL_FILE_OPTIONS = {"file", "f"}
_SCRIPT_HOST_FLAGS = {
    "//b", "//d", "//i", "//logo", "//nologo", "//s", "//u", "//x",
}
_SCRIPT_HOST_VALUE_PREFIXES = ("//e:", "//h:", "//job:", "//t:")
_UNSUPPORTED_SYNTAX = "'&|<>^`"


class _ScanFailure(ValueError):
    pass


def _quote_is_backslash_escaped(raw: str, index: int) -> bool:
    backslashes = 0
    cursor = index - 1
    while cursor >= 0 and raw[cursor] == "\\":
        backslashes += 1
        cursor -= 1
    return backslashes % 2 == 1


def _basename(value: str) -> str:
    return ntpath.basename(value.replace("/", "\\")).casefold()


def _unresolved(
    reason: str,
    *,
    raw_value: str | None,
    executable: str | None = None,
    arguments: str | None = None,
) -> PersistenceTarget:
    return PersistenceTarget(
        path=None,
        kind="unresolved",
        provenance="unresolved",
        raw_value=raw_value,
        executable=executable,
        arguments=arguments,
        reason=reason,
    )


def _scan_windows_subset(raw: str) -> list[str]:
    """Split a deliberately bounded Windows command-line subset.

    Tokens are either wholly double quoted or contain no quotes. Backslash
    quote escaping, concatenated quoted/unquoted segments, single quotes, and
    shell metacharacters are rejected rather than approximated.
    """
    if any((ord(char) < 32 and char != "\t") or ord(char) == 127 for char in raw):
        raise _ScanFailure("The value contains a control character.")
    if any(char in raw for char in _UNSUPPORTED_SYNTAX):
        raise _ScanFailure("The value contains unsupported quoting or command syntax.")

    tokens: list[str] = []
    index = 0
    while index < len(raw):
        while index < len(raw) and raw[index] in " \t":
            index += 1
        if index >= len(raw):
            break
        if raw[index] == '"':
            end = raw.find('"', index + 1)
            if end < 0:
                raise _ScanFailure("A double-quoted token is unterminated.")
            if _quote_is_backslash_escaped(raw, end):
                raise _ScanFailure(
                    "Backslash-escaped quote boundaries are outside the supported subset."
                )
            token = raw[index + 1 : end]
            if end + 1 < len(raw) and raw[end + 1] not in " \t":
                raise _ScanFailure("Quoted and unquoted token segments are not supported.")
            index = end + 1
        else:
            end = index
            while end < len(raw) and raw[end] not in " \t":
                if raw[end] == '"':
                    raise _ScanFailure("Embedded quotes are outside the supported subset.")
                end += 1
            token = raw[index:end]
            index = end
        if not token:
            raise _ScanFailure("Empty quoted tokens are outside the supported subset.")
        tokens.append(token)
    if not tokens:
        raise _ScanFailure("The value is empty.")
    return tokens


def _powershell_switch(token: str, *, modern: bool) -> str | None:
    if modern and token.startswith("--") and len(token) > 2:
        return token[2:].casefold()
    if token.startswith(("-", "/")) and len(token) > 1:
        return token[1:].casefold()
    return None


def _powershell_target(
    tokens: list[str],
    *,
    raw_value: str | None,
    executable: str,
    arguments: str | None,
    modern: bool,
) -> PersistenceTarget:
    index = 0
    seen: set[str] = set()
    while index < len(tokens):
        switch = _powershell_switch(tokens[index], modern=modern)
        if switch in _POWERSHELL_FILE_OPTIONS:
            if "file" in seen:
                return _unresolved(
                    "A duplicate PowerShell -File option is ambiguous.",
                    raw_value=raw_value,
                    executable=executable,
                    arguments=arguments,
                )
            if index + 1 >= len(tokens):
                return _unresolved(
                    "PowerShell -File has no explicit script target.",
                    raw_value=raw_value,
                    executable=executable,
                    arguments=arguments,
                )
            target = tokens[index + 1]
            if not target.casefold().endswith(".ps1"):
                return _unresolved(
                    "PowerShell -File target does not have the supported .ps1 suffix.",
                    raw_value=raw_value,
                    executable=executable,
                    arguments=arguments,
                )
            return PersistenceTarget(
                path=target,
                kind="script",
                provenance="powershell_file",
                raw_value=raw_value,
                executable=executable,
                arguments=arguments,
                reason=(
                    "Explicit PowerShell -File script target; the script is not read "
                    "or executed."
                ),
            )
        if switch in _POWERSHELL_FLAG_OPTIONS:
            canonical = _POWERSHELL_FLAG_OPTIONS[switch]
            if canonical in seen:
                return _unresolved(
                    "A duplicate PowerShell host option is ambiguous.",
                    raw_value=raw_value,
                    executable=executable,
                    arguments=arguments,
                )
            seen.add(canonical)
            index += 1
            continue
        if switch in _POWERSHELL_VALUE_OPTIONS:
            if switch in {"workingdirectory", "wd"} and not modern:
                return _unresolved(
                    "PowerShell working-directory options are supported only for pwsh.",
                    raw_value=raw_value,
                    executable=executable,
                    arguments=arguments,
                )
            canonical = _POWERSHELL_VALUE_OPTIONS[switch]
            if (
                canonical in seen
                or index + 1 >= len(tokens)
                or _powershell_switch(tokens[index + 1], modern=modern) is not None
            ):
                return _unresolved(
                    "A PowerShell host option is duplicate or missing its value.",
                    raw_value=raw_value,
                    executable=executable,
                    arguments=arguments,
                )
            seen.add(canonical)
            index += 2
            continue
        return _unresolved(
            "Only recognized PowerShell host options before explicit -File are supported.",
            raw_value=raw_value,
            executable=executable,
            arguments=arguments,
        )
    return _unresolved(
        "PowerShell arguments do not contain an explicit supported -File target.",
        raw_value=raw_value,
        executable=executable,
        arguments=arguments,
    )


def _script_host_target(
    tokens: list[str],
    *,
    raw_value: str | None,
    executable: str,
    arguments: str | None,
) -> PersistenceTarget:
    index = 0
    while index < len(tokens):
        token = tokens[index]
        folded = token.casefold()
        if folded in _SCRIPT_HOST_FLAGS or any(
            folded.startswith(prefix) and len(folded) > len(prefix)
            for prefix in _SCRIPT_HOST_VALUE_PREFIXES
        ):
            index += 1
            continue
        if folded.startswith("//"):
            return _unresolved(
                "An unsupported Windows Script Host switch precedes the script target.",
                raw_value=raw_value,
                executable=executable,
                arguments=arguments,
            )
        if not folded.endswith(_SCRIPT_HOST_SUFFIXES):
            return _unresolved(
                "The first non-switch Windows Script Host argument is not a supported script file.",
                raw_value=raw_value,
                executable=executable,
                arguments=arguments,
            )
        return PersistenceTarget(
            path=token,
            kind="script",
            provenance="script_host_file",
            raw_value=raw_value,
            executable=executable,
            arguments=arguments,
            reason=(
                "Explicit first Windows Script Host file argument; the script is not "
                "read or executed."
            ),
        )
    return _unresolved(
        "Windows Script Host arguments do not contain an explicit script target.",
        raw_value=raw_value,
        executable=executable,
        arguments=arguments,
    )


def _interpret(
    executable: str,
    arguments_tokens: list[str],
    *,
    raw_value: str | None,
    arguments: str | None,
    direct_provenance: Literal["raw_command_executable", "task_action_executable"],
) -> PersistenceTarget:
    name = _basename(executable)
    if name in _POWERSHELL_NAMES:
        return _powershell_target(
            arguments_tokens,
            raw_value=raw_value,
            executable=executable,
            arguments=arguments,
            modern=name in {"pwsh", "pwsh.exe"},
        )
    if name in _SCRIPT_HOST_NAMES:
        return _script_host_target(
            arguments_tokens,
            raw_value=raw_value,
            executable=executable,
            arguments=arguments,
        )
    if name in {"cmd", "cmd.exe"}:
        return _unresolved(
            "Nested cmd shell interpretation is outside the supported subset.",
            raw_value=raw_value,
            executable=executable,
            arguments=arguments,
        )
    if executable.casefold().endswith(_EXECUTABLE_SUFFIXES):
        return PersistenceTarget(
            path=executable,
            kind="executable",
            provenance=direct_provenance,
            raw_value=raw_value,
            executable=executable,
            arguments=arguments,
            reason=(
                "Explicit executable field or first executable token; existence and "
                "execution are not established."
            ),
        )
    return _unresolved(
        "The target is not a supported direct .exe/.com or interpreter form.",
        raw_value=raw_value,
        executable=executable,
        arguments=arguments,
    )


def parse_persistence_command(command: str | None) -> PersistenceTarget:
    """Interpret one raw Run-key or service command without executing it."""
    if command is None:
        return _unresolved("The raw command is unavailable.", raw_value=None)
    try:
        tokens = _scan_windows_subset(command)
    except _ScanFailure as exc:
        reason = str(exc)
        executable = None
        if reason in {
            "A double-quoted token is unterminated.",
            "Backslash-escaped quote boundaries are outside the supported subset.",
            "Quoted and unquoted token segments are not supported.",
            "Embedded quotes are outside the supported subset.",
        }:
            direct = parse_command_target(command)
            if not direct.ambiguous:
                executable = direct.path
        return _unresolved(
            reason,
            raw_value=command,
            executable=executable,
            arguments=command,
        )
    return _interpret(
        tokens[0],
        tokens[1:],
        raw_value=command,
        arguments=command,
        direct_provenance="raw_command_executable",
    )


def parse_task_action(action: TaskAction) -> PersistenceTarget:
    """Interpret an already structured scheduled-task action."""
    action = TaskAction.model_validate(action)
    if action.kind != "exec":
        return _unresolved(
            f"Scheduled-task action kind {action.kind!r} has no supported executable target.",
            raw_value=action.executable or action.arguments,
            executable=action.executable,
            arguments=action.arguments,
        )
    if not action.executable:
        return _unresolved(
            "The scheduled-task executable field is unavailable.",
            raw_value=action.arguments,
            arguments=action.arguments,
        )
    executable = action.executable.strip()
    if (
        not executable
        or any(ord(char) < 32 or ord(char) == 127 for char in executable)
        or any(char in executable for char in _UNSUPPORTED_SYNTAX + '"')
    ):
        return _unresolved(
            "The scheduled-task executable field contains unsupported syntax.",
            raw_value=action.executable,
            executable=action.executable,
            arguments=action.arguments,
        )
    name = _basename(executable)
    if name not in _POWERSHELL_NAMES | _SCRIPT_HOST_NAMES | {"cmd", "cmd.exe"}:
        return _interpret(
            executable,
            [],
            raw_value=action.executable,
            arguments=action.arguments,
            direct_provenance="task_action_executable",
        )
    try:
        argument_tokens = _scan_windows_subset(action.arguments) if action.arguments else []
    except _ScanFailure as exc:
        return _unresolved(
            f"Scheduled-task arguments are unresolved: {exc}",
            raw_value=action.executable,
            executable=action.executable,
            arguments=action.arguments,
        )
    return _interpret(
        executable,
        argument_tokens,
        raw_value=action.executable,
        arguments=action.arguments,
        direct_provenance="task_action_executable",
    )
