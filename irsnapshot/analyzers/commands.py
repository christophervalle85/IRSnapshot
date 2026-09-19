"""Conservative Windows command facts, never shell evaluation or payload execution.

PowerShell argv is already tokenized by collection. Raw service/Run strings only
receive a first-executable interpretation; neither API consults PATH or the host.
"""
from dataclasses import dataclass, field
import ntpath

from irsnapshot.models import ProcessArtifact


@dataclass(frozen=True)
class HostOption:
    name: str
    value: str | None
    token_index: int


@dataclass(frozen=True)
class CommandFacts:
    executable_name: str | None
    host_options: list[HostOption] = field(default_factory=list)
    payload: list[str] = field(default_factory=list)
    parse_issues: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class CommandTarget:
    path: str | None
    ambiguous: bool
    reason: str


# Explicit recognition subset, not a replacement for the PowerShell parser.
# Ordered aliases/prefix minima follow documented host options and upstream's
# CommandLineParameterParser. No regex search across script text is performed.
_OPTIONS = (
    ('executionpolicy', 'ex', ('ep',), True),
    ('encodedcommand', 'e', ('ec',), True),
    ('encodedarguments', 'encodeda', ('ea',), True),
    ('windowstyle', 'w', (), True),
    ('noprofile', 'nop', (), False),
    ('noninteractive', 'noni', (), False),
    ('noexit', 'noe', (), False),
    ('nologo', 'nol', (), False),
    ('inputformat', 'inp', ('if',), True),
    ('outputformat', 'o', ('of',), True),
    ('configurationname', 'config', (), True),
    ('file', 'f', (), True),
    ('command', 'c', (), True),
    ('sta', 'sta', (), False),
    ('mta', 'mta', (), False),
    ('help', 'h', ('?',), False),
)
_DASHES = '-\u2013\u2014\u2015'


def _basename(value: str) -> str:
    return ntpath.basename(value.strip('"')).casefold()


def _same_executable(left: str, right: str) -> bool:
    return _basename(left).removesuffix('.exe') == _basename(right).removesuffix('.exe')


def parse_process_command(process: ProcessArtifact) -> CommandFacts:
    """Extract host options from a supported argv prefix, retaining uncertainty.

    Raw encoded values stay opaque. Command/File payload boundaries terminate
    scanning. A parse issue is a limitation, never evidence of maliciousness.
    """
    process = ProcessArtifact.model_validate(process)
    argv = process.command_line
    identity = process.executable or process.name or (argv[0] if argv else None)
    name = _basename(identity) if identity else None
    if not argv:
        return CommandFacts(name, parse_issues=['Command line is unavailable or empty'])
    if not argv[0] or (identity is not None and not _same_executable(identity, argv[0])):
        return CommandFacts(name, payload=list(argv), parse_issues=['Executable identity and argv[0] disagree'])
    if name not in ('powershell', 'powershell.exe', 'pwsh', 'pwsh.exe'):
        return CommandFacts(name, payload=list(argv[1:]))
    options, payload, issues = _powershell_options(argv, modern=name in ('pwsh', 'pwsh.exe'))
    return CommandFacts(name, options, payload, issues)


def _option(token: str, modern: bool) -> tuple[str, bool] | None:
    if not token or token[0] not in _DASHES + '/':
        return None
    key = token[1:].casefold()
    if modern and token[0] in _DASHES and key.startswith(token[0]):
        key = key[1:]
    if modern and key in ('commandwithargs', 'cwa'):
        return 'commandwithargs', True
    if modern and (key == 'wd' or (len(key) >= 2 and 'workingdirectory'.startswith(key))):
        return 'workingdirectory', True
    if key and 'version'.startswith(key):
        return 'version', not modern
    for name, minimum, aliases, takes_value in _OPTIONS:
        if key in aliases or (len(key) >= len(minimum) and name.startswith(key)):
            return name, takes_value
    return None


def _powershell_options(argv: list[str], modern: bool) -> tuple[list[HostOption], list[str], list[str]]:
    options: list[HostOption] = []
    index = 1
    while index < len(argv):
        token = argv[index].strip()
        if not token or token[0] not in _DASHES + '/':
            return options, list(argv[index:]), []
        match = _option(token, modern)
        if match is None:
            return options, list(argv[index:]), [f'Unsupported host option at token {index}']
        name, takes_value = match
        if any(option.name == name for option in options):
            return options, list(argv[index:]), [f'Duplicate host option at token {index}']
        value = argv[index + 1] if takes_value and index + 1 < len(argv) else None
        if takes_value and (not value or (value != '-' and value[0] in _DASHES + '/')):
            return options, list(argv[index:]), [f'Missing or ambiguous value for {name} at token {index}']
        if name == 'windowstyle' and value is not None and value.casefold() not in ('normal', 'hidden', 'minimized', 'maximized'):
            return options, list(argv[index:]), [f'Unrecognized window style at token {index + 1}']
        options.append(HostOption(name, value, index))
        if name in ('command', 'file', 'commandwithargs'):
            return options, list(argv[index + 1:]), []
        if name == 'help' or (name == 'version' and modern):
            return options, list(argv[index + 1:]), []
        index += 2 if takes_value else 1
    return options, [], []


def parse_command_target(command: str) -> CommandTarget:
    """Extract an explicit .exe/.com target without guessing unquoted spaced paths.

    This is syntax evidence only. Relative/variable-containing targets remain
    unresolved locations until classify_path evaluates captured path context.
    Script/interpreter payload extraction is intentionally a later concern.
    """
    if any(ord(char) < 32 and char != '\t' for char in command):
        return CommandTarget(None, True, 'Command contains control characters')
    text = command.strip()
    if not text:
        return CommandTarget(None, True, 'Command is empty')
    if text.startswith('"'):
        end = text.find('"', 1)
        if end < 0 or (len(text) > end + 1 and not text[end + 1].isspace()):
            return CommandTarget(None, True, 'First executable quote is unterminated or has an attached suffix')
        candidate = text[1:end]
    else:
        candidate = text.split(maxsplit=1)[0]
    if not candidate or any(char in candidate for char in '\"\'&|<>^`'):
        return CommandTarget(None, True, 'First token has ambiguous quoting or command syntax')
    if not candidate.casefold().endswith(('.exe', '.com')):
        return CommandTarget(None, True, 'No unambiguous explicit executable suffix; a spaced path or shell expression may be present')
    return CommandTarget(candidate, False, 'Explicit first executable; existence, expansion and execution are not established')
