"""Ten deterministic process rules over captured, inert evidence.

The command rules inspect already-tokenized argv only. They never decode a
PowerShell value, join and reparse tokens, resolve a program, or execute data.
Supported transfer/script forms are deliberately narrow:

* certutil requires exact ``-urlcache`` and ``-f`` tokens plus a later,
  standalone HTTP(S) URL; ``-split`` is optional.
* rundll32 requires the first argument to begin with the explicit
  ``javascript:\\..\\mshtml,RunHTMLApplication`` form (an optional quote after
  the colon is accepted).
* regsvr32 requires an inline ``/i:http(s)://...`` token and a separate token
  whose Windows basename is exactly ``scrobj.dll``.
"""

from collections.abc import Callable
import ntpath
import re
from urllib.parse import urlsplit

from irsnapshot.analyzers.commands import HostOption, parse_process_command
from irsnapshot.analyzers.paths import PathAssessment, classify_path
from irsnapshot.models import EvidenceItem, ProcessArtifact, ProcessNode
from irsnapshot.rules.base import AnalysisContext, Rule, make_finding
from irsnapshot.severity import Severity


_POWERSHELL = frozenset(("powershell", "pwsh"))
_OFFICE = frozenset(
    ("winword", "excel", "powerpnt", "outlook", "msaccess", "mspub", "onenote")
)
_RUNDLL32_SCRIPT = re.compile(
    r'''^javascript\s*:\s*["']?\\\.\.\\mshtml\s*,\s*runhtmlapplication(?=$|[\s"'`;])''',
    re.IGNORECASE,
)


def _basename(value: str) -> str:
    return ntpath.basename(value.strip().strip('"')).casefold().removesuffix(".exe")


def _identity(process: ProcessArtifact) -> str | None:
    """Return one consistent basename, or unknown for conflicting evidence."""

    raw = [value for value in (process.executable, process.name) if value]
    if process.command_line and process.command_line[0]:
        raw.append(process.command_line[0])
    names = {_basename(value) for value in raw}
    if len(names) != 1:
        return None
    return next(iter(names), None)


def _processes(context: AnalysisContext) -> list[ProcessArtifact]:
    return sorted(
        (ProcessArtifact.model_validate(item) for item in context.snapshot.processes),
        key=lambda item: (item.artifact_id.int, item.pid),
    )


def _raw_process_evidence(process: ProcessArtifact) -> list[EvidenceItem]:
    return [
        EvidenceItem(
            artifact_id=process.artifact_id,
            field="executable",
            value=process.executable,
            explanation="Captured executable path; it is not a publisher or signature assertion.",
        ),
        EvidenceItem(
            artifact_id=process.artifact_id,
            field="command_line",
            value=list(process.command_line) if process.command_line is not None else None,
            explanation="Captured argv tokens preserved as evidence; no token was executed.",
        ),
    ]


def _host_option_evidence(
    process: ProcessArtifact, option: HostOption
) -> EvidenceItem:
    assert process.command_line is not None
    raw = [process.command_line[option.token_index]]
    if option.value is not None:
        raw.append(option.value)
    return EvidenceItem(
        artifact_id=process.artifact_id,
        field="host_option",
        value=raw,
        explanation=(
            f"Parsed PowerShell host option {option.name!r} at argv index "
            f"{option.token_index}; its value remains opaque."
        ),
    )


def _powershell_option_findings(
    context: AnalysisContext,
    rule: Rule,
    predicate: Callable[[HostOption], bool],
    description: str,
):
    findings = []
    for process in _processes(context):
        if _identity(process) not in _POWERSHELL:
            continue
        facts = parse_process_command(process)
        option = next((item for item in facts.host_options if predicate(item)), None)
        if option is None:
            continue
        findings.append(
            make_finding(
                context,
                rule,
                artifact_ids=[process.artifact_id],
                pids=[process.pid],
                evidence=[*_raw_process_evidence(process), _host_option_evidence(process, option)],
                description=description,
            )
        )
    return findings


def _p001(context: AnalysisContext):
    return _powershell_option_findings(
        context,
        P001,
        lambda option: option.name == "encodedcommand" and option.value is not None,
        "A PowerShell host EncodedCommand option obscures casual inspection of the command. "
        "Legitimate automation can also use encoded commands, so review the surrounding workflow.",
    )


def _p002(context: AnalysisContext):
    return _powershell_option_findings(
        context,
        P002,
        lambda option: option.name == "windowstyle"
        and option.value is not None
        and option.value.casefold() == "hidden",
        "A PowerShell host explicitly requested a hidden window. Legitimate background "
        "automation also uses hidden windows, so this is a review hint rather than a verdict.",
    )


def _office_child_findings(
    context: AnalysisContext,
    rule: Rule,
    accepted_children: frozenset[str],
    description: str,
):
    processes = {item.artifact_id: item for item in _processes(context)}
    nodes = sorted(context.tree.nodes, key=lambda item: item.process_id.int)
    findings = []
    for raw_node in nodes:
        node = ProcessNode.model_validate(raw_node)
        if node.parent_status != "linked" or node.parent_id is None:
            continue
        child = processes.get(node.process_id)
        parent = processes.get(node.parent_id)
        if child is None or parent is None:
            continue
        if child.created_at is None or parent.created_at is None:
            continue
        if _identity(child) not in accepted_children or _identity(parent) not in _OFFICE:
            continue
        evidence = [
            EvidenceItem(
                artifact_id=parent.artifact_id,
                field="parent.executable",
                value=parent.executable or parent.name,
                explanation="Captured parent identity used for case-insensitive basename matching.",
            ),
            EvidenceItem(
                artifact_id=parent.artifact_id,
                field="parent.created_at",
                value=parent.created_at.isoformat(),
                explanation="Captured parent creation time required for a temporally consistent tree link.",
            ),
            EvidenceItem(
                artifact_id=child.artifact_id,
                field="child.executable",
                value=child.executable or child.name,
                explanation="Captured direct-child identity used for basename matching.",
            ),
            EvidenceItem(
                artifact_id=child.artifact_id,
                field="child.created_at",
                value=child.created_at.isoformat(),
                explanation="Captured child creation time required for a temporally consistent tree link.",
            ),
            EvidenceItem(
                artifact_id=child.artifact_id,
                field="relationship",
                value=f"direct child of PID {parent.pid}",
                explanation="The deterministic tree linked both collected records directly.",
            ),
        ]
        findings.append(
            make_finding(
                context,
                rule,
                artifact_ids=[parent.artifact_id, child.artifact_id],
                pids=[parent.pid, child.pid],
                evidence=evidence,
                description=description,
            )
        )
    return findings


def _p003(context: AnalysisContext):
    return _office_child_findings(
        context,
        P003,
        _POWERSHELL,
        "A recognized Office basename directly parented a PowerShell host with a temporally "
        "consistent link. Legitimate Office automation can do this; basename evidence does "
        "not verify the publisher or establish exploitation.",
    )


def _p004(context: AnalysisContext):
    return _office_child_findings(
        context,
        P004,
        frozenset(("cmd",)),
        "A recognized Office basename directly parented cmd.exe with a temporally consistent "
        "link. Legitimate Office automation can launch a shell; basename evidence does not "
        "verify the publisher or establish exploitation.",
    )


def _p005(context: AnalysisContext):
    return _office_child_findings(
        context,
        P005,
        frozenset(("wscript", "cscript")),
        "A recognized Office basename directly parented a Windows script host with a "
        "temporally consistent link. Legitimate scripted workflows exist; basename evidence "
        "does not verify the publisher or characterize script contents.",
    )


def _path_evidence(
    process: ProcessArtifact, assessment: PathAssessment
) -> list[EvidenceItem]:
    return [
        EvidenceItem(
            artifact_id=process.artifact_id,
            field="executable",
            value=process.executable,
            explanation="Captured executable path required by this location rule.",
        ),
        EvidenceItem(
            artifact_id=process.artifact_id,
            field="normalized_path",
            value=assessment.normalized_path,
            explanation="Lexically normalized Windows path derived only from captured context.",
        ),
        EvidenceItem(
            artifact_id=process.artifact_id,
            field="path_basis",
            value=assessment.basis,
            explanation="Classifier basis; this makes no ACL, trust, or existence claim.",
        ),
    ]


def _path_findings(
    context: AnalysisContext,
    rule: Rule,
    predicate: Callable[[PathAssessment], bool],
    description: str,
):
    findings = []
    for process in _processes(context):
        if process.executable is None:
            continue
        assessment = classify_path(process.executable, context.snapshot.path_context)
        if not predicate(assessment):
            continue
        findings.append(
            make_finding(
                context,
                rule,
                artifact_ids=[process.artifact_id],
                pids=[process.pid],
                evidence=_path_evidence(process, assessment),
                description=description,
            )
        )
    return findings


def _p006(context: AnalysisContext):
    return _path_findings(
        context,
        P006,
        lambda assessment: assessment.category == "temp",
        "The captured executable path is in an identified TEMP directory. Installers and "
        "updaters commonly execute there, so the location warrants review but is not a trust conclusion.",
    )


def _contains(root: str, path: str) -> bool:
    return path == root or path.startswith(root.rstrip("\\") + "\\")


def _programs_roots(context: AnalysisContext) -> tuple[str, ...]:
    """Return only conventional Local AppData ``Programs`` installation roots."""

    roots: set[str] = set()
    for known in context.snapshot.path_context.known_paths:
        if known.kind not in ("local_appdata", "profile"):
            continue
        root = classify_path(known.path, context.snapshot.path_context).normalized_path
        if root is None:
            continue
        if known.kind == "profile":
            root = ntpath.join(root, "appdata", "local")
        roots.add(ntpath.join(root, "programs"))
    return tuple(sorted(roots))


def _p007(context: AnalysisContext):
    program_roots = _programs_roots(context)

    def included(assessment: PathAssessment) -> bool:
        if assessment.category != "appdata" or assessment.normalized_path is None:
            return False
        return not any(
            _contains(root, assessment.normalized_path) for root in program_roots
        )

    return _path_findings(
        context,
        P007,
        included,
        "The captured executable is in AppData, outside the conventional Local AppData "
        "Programs subtree and any more-specific TEMP classification. Legitimate per-user "
        "applications commonly use AppData; this lexical heuristic does not measure trust or ACLs.",
    )


def _standalone_http_url(value: str) -> bool:
    if value != value.strip() or any(character.isspace() for character in value):
        return False
    parsed = urlsplit(value)
    return parsed.scheme.casefold() in ("http", "https") and bool(parsed.netloc)


def _command_finding(
    context: AnalysisContext,
    rule: Rule,
    process: ProcessArtifact,
    extra_evidence: list[EvidenceItem],
    description: str,
):
    return make_finding(
        context,
        rule,
        artifact_ids=[process.artifact_id],
        pids=[process.pid],
        evidence=[*_raw_process_evidence(process), *extra_evidence],
        description=description,
    )


def _p008(context: AnalysisContext):
    findings = []
    for process in _processes(context):
        argv = process.command_line
        if _identity(process) != "certutil" or not argv:
            continue
        folded = [token.casefold() for token in argv]
        if (
            "-urlcache" not in folded
            or "-f" not in folded
            or "delete" in folded[1:]
        ):
            continue
        boundary = folded.index("-urlcache")
        source = next(
            (token for token in argv[boundary + 1 :] if _standalone_http_url(token)),
            None,
        )
        if source is None:
            continue
        options = [
            token for token in argv[1:] if token.casefold() in ("-urlcache", "-split", "-f")
        ]
        findings.append(
            _command_finding(
                context,
                P008,
                process,
                [
                    EvidenceItem(
                        artifact_id=process.artifact_id,
                        field="download_options",
                        value=options,
                        explanation="Exact supported certutil option tokens found in captured argv.",
                    ),
                    EvidenceItem(
                        artifact_id=process.artifact_id,
                        field="remote_source",
                        value=source,
                        explanation="Standalone HTTP(S) source token following -urlcache.",
                    ),
                ],
                "Certutil combined -urlcache and forced retrieval with a standalone HTTP(S) "
                "source. Legitimate certificate administration can fetch remote material, so "
                "review the source and workflow.",
            )
        )
    return findings


def _p009(context: AnalysisContext):
    findings = []
    for process in _processes(context):
        argv = process.command_line
        if _identity(process) != "rundll32" or not argv or len(argv) < 2:
            continue
        pattern = argv[1]
        if _RUNDLL32_SCRIPT.match(pattern) is None:
            continue
        findings.append(
            _command_finding(
                context,
                P009,
                process,
                [
                    EvidenceItem(
                        artifact_id=process.artifact_id,
                        field="script_pattern",
                        value=pattern,
                        explanation="The explicit script-oriented pattern occupies argv index 1.",
                    )
                ],
                "Rundll32 used an explicit JavaScript/mshtml RunHTMLApplication form. This "
                "rule does not match a normal DLL/export invocation and does not interpret or "
                "execute the later script data.",
            )
        )
    return findings


def _p010(context: AnalysisContext):
    findings = []
    for process in _processes(context):
        argv = process.command_line
        if _identity(process) != "regsvr32" or not argv:
            continue
        install_argument = next(
            (
                token
                for token in argv[1:]
                if token.casefold().startswith("/i:")
                and _standalone_http_url(token[3:])
            ),
            None,
        )
        target = next(
            (token for token in argv[1:] if _basename(token) == "scrobj.dll"), None
        )
        if install_argument is None or target is None:
            continue
        findings.append(
            _command_finding(
                context,
                P010,
                process,
                [
                    EvidenceItem(
                        artifact_id=process.artifact_id,
                        field="remote_install_argument",
                        value=install_argument,
                        explanation="Inline /i: argument contains a standalone HTTP(S) value.",
                    ),
                    EvidenceItem(
                        artifact_id=process.artifact_id,
                        field="scriptlet_target",
                        value=target,
                        explanation="A separate target token has the exact Windows basename scrobj.dll.",
                    ),
                ],
                "Regsvr32 combined a remote /i: argument with scrobj.dll. Normal local component "
                "registration does not satisfy this form; the evidence still does not prove execution.",
            )
        )
    return findings


P001 = Rule("IRS-P001", "PowerShell encoded command", Severity.MEDIUM, _p001)
P002 = Rule("IRS-P002", "PowerShell hidden window", Severity.LOW, _p002)
P003 = Rule("IRS-P003", "Office spawned PowerShell", Severity.HIGH, _p003)
P004 = Rule("IRS-P004", "Office spawned command shell", Severity.MEDIUM, _p004)
P005 = Rule("IRS-P005", "Office spawned script host", Severity.HIGH, _p005)
P006 = Rule("IRS-P006", "Process executable in TEMP", Severity.MEDIUM, _p006)
P007 = Rule("IRS-P007", "Process executable in AppData", Severity.LOW, _p007)
P008 = Rule("IRS-P008", "Certutil remote forced retrieval", Severity.MEDIUM, _p008)
P009 = Rule("IRS-P009", "Rundll32 JavaScript/mshtml form", Severity.HIGH, _p009)
P010 = Rule("IRS-P010", "Regsvr32 remote scriptlet form", Severity.HIGH, _p010)


PROCESS_RULES: tuple[Rule, ...] = (
    P001,
    P002,
    P003,
    P004,
    P005,
    P006,
    P007,
    P008,
    P009,
    P010,
)
