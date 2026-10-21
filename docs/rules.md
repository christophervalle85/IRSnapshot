# Rule reference — ruleset 1.0.0

IRSnapshot applies thirteen explicit predicates to saved evidence. Each finding identifies its rule, fixed severity, matching artifact UUIDs, original evidence fields, and a plausible benign explanation. A match means the pattern warrants review; it does not establish malware, compromise, intent, or successful execution.

## Process rules

| ID | Severity | Matching evidence | Important exclusions and benign explanations |
|---|---|---|---|
| IRS-P001 | medium | Recognized PowerShell/pwsh host `EncodedCommand` option or supported alias | Script arguments and `EncodedArguments` do not match. Encoded values stay opaque. Legitimate automation uses encoding. |
| IRS-P002 | low | Recognized host `WindowStyle` option with value `Hidden` | Text inside a script is not a host option. Background automation commonly suppresses windows. |
| IRS-P003 | high | Direct Office child is PowerShell/pwsh, with a temporally consistent tree link | An ancestor several levels away, missing start times, or a newer parent does not match. Office automation can legitimately launch a shell. |
| IRS-P004 | medium | Same direct Office relationship, child is cmd | Same relationship safeguards. Approved document workflows may use command scripts. |
| IRS-P005 | high | Same direct Office relationship, child is wscript/cscript | Same relationship safeguards. Approved Office scripting can explain this pattern. |
| IRS-P006 | medium | Captured executable path classifies as TEMP | A command argument alone is insufficient. Installers and updaters often run from temporary directories. |
| IRS-P007 | low | Captured executable classifies as AppData, outside the conventional per-user Programs subtree | More-specific TEMP locations are handled by P006. Per-user applications are common; the exclusion reduces noise and establishes no trust. |
| IRS-P008 | medium | certutil arguments contain `-urlcache`, `-f`, and an HTTP(S) source in the supported argument form | Optional `-split` is supported. URL-free operations, cache inspection/deletion, certificate inspection, and URLs present only as unrelated data do not match. Administrative certificate workflows can fetch URLs. |
| IRS-P009 | high | rundll32's executable argument contains the supported JavaScript/mshtml `RunHTMLApplication` pattern | A normal DLL/export invocation or the pattern only in later data does not match. Specialized compatibility/testing workflows may explain it. |
| IRS-P010 | high | regsvr32 combines a remote HTTP(S) `/i:` value with scrobj.dll as the target | Ordinary local component registration and unrelated URL text do not match. Authorized administrative testing remains possible. |

Office recognition uses the fixed basename set `WINWORD.EXE`, `EXCEL.EXE`, `POWERPNT.EXE`, `OUTLOOK.EXE`, `MSACCESS.EXE`, `MSPUB.EXE`, and `ONENOTE.EXE`. Names are compared case-insensitively. Basenames are not signatures or publisher identity. Parent rules require both creation times and a `linked` direct parent; uncertain links remain in the tree for context.

P007's Programs exclusion applies to the conventional `Programs` child of a captured local AppData root, or the conventional `AppData\Local\Programs` subtree under a captured profile. Directory boundaries matter: `ProgramsElsewhere` is not `Programs`. A folder named Programs at an unrelated level is not exempt.

PowerShell process matching uses the [PowerShell host parser](interpretation.md). Its explicit prefix/alias table stops at command/file payload boundaries and retains parsing limitations. Findings describe recognized syntax, not whether the host accepted a command. Arbitrary inline code is never evaluated.

The certutil fetch requirement follows Microsoft's explanation that `-f` forces URL retrieval in the [certutil reference](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil). The narrow script-oriented binary patterns are informed by MITRE's [Rundll32 technique](https://attack.mitre.org/techniques/T1218/011/) and [Regsvr32 technique](https://attack.mitre.org/techniques/T1218/010/). These references explain review patterns, not attribution of any particular finding.

P008 accepts a prefix containing exactly one `-urlcache`, required `-f`, and optional `-split` in any order, followed by the HTTP(S) source and at most one output token. Unknown options, extra operands, and a `delete` output token are excluded; a URL supplied as an unrelated option's value is not treated as a source. P009 checks only the first argument for `javascript:..\mshtml,RunHTMLApplication`, allowing a quote after the colon and an optional leading backslash before `..`. Normal DLL/export forms and longer function-name prefixes do not match. Malformed bracketed URLs remain non-matches for P008/P010.

## Persistence rules

| ID | Severity | Matching evidence | Important exclusions and benign explanations |
|---|---|---|---|
| IRS-R001 | medium | Run-key command executable or supported explicit script target classifies as TEMP, AppData, or profile | Owner-scoped variables require the captured owner SID. Unresolved targets do not become guessed paths. Legitimate startup applications can live in these directories. |
| IRS-R002 | medium | Scheduled-task execution action targets TEMP/AppData directly or through a supported interpreter/file argument | COM/other actions stay inventory. All matching actions are retained in one finding per task. Disabled tasks remain evidence with state/principal shown. Approved maintenance tasks can use these paths. |
| IRS-R003 | high | Service command's executable classifies as TEMP, AppData, or profile | Only the service executable is matched, not a script mentioned later in its arguments. Stopped services remain configured evidence. Legitimate vendor software can use per-user locations. |

R002 evaluates collected task artifacts; R003 evaluates collected service artifacts. Their projections in `snapshot.persistence` do not produce duplicate findings. Run-key entries are evaluated directly from persistence records. Startup-folder entries remain inventory in this initial ruleset.

The supported persistence grammar deliberately covers direct `.exe`/`.com` targets, explicit PowerShell/pwsh `-File` `.ps1` targets, and wscript/cscript script-file targets. Wholly double-quoted paths can contain spaces. A scheduled action's executable field is already a separate value and may contain spaces without surrounding quotes. Raw Run/service commands have different quoting requirements.

Before `-File`/`-f`, the persistence parser accepts `NoLogo`/`nol`, `NoProfile`/`nop`, `NonInteractive`/`noni`, `NoExit`/`noe`, `Sta`, and `Mta`; value-taking options are `ExecutionPolicy`/`ep`, `InputFormat`/`inp`/`if`, `OutputFormat`/`o`/`of`, and `ConfigurationName`/`config`. `WorkingDirectory`/`wd` is supported only for pwsh. Matching is case-insensitive; `-` and `/` introduce options, with `--` additionally supported for pwsh. Unknown or duplicate options and missing values stop script interpretation. Script-host parsing accepts `//B`, `//D`, `//I`, `//Logo`, `//Nologo`, `//S`, `//U`, `//X`, and nonempty inline `//E:`, `//H:`, `//Job:`, `//T:` values before a `.vbs`, `.vbe`, `.js`, `.jse`, `.wsf`, or `.wsh` target.

Unsupported or malformed quoting, ambiguous unquoted executable paths, missing values, inline `-Command`/`-EncodedCommand`, nested shells, relative locations without captured context, and unresolved variables do not become script findings. This is a lexical subset, not a general Windows shell parser. The analyzer never launches an interpreter, reads a script, resolves a shortcut, or checks path permissions.

## Evidence, identity, and completeness

Finding IDs use UUIDv5 with the snapshot UUID as namespace and the rule ID plus sorted matched artifact UUIDs as the name. Reordering evidence does not create new finding identities. Findings sort by severity (highest first), rule ID, then finding ID. Several actions matching one task retain their distinct evidence in the same finding. Related findings never increase one another's severity.

A rule failure produces an `AnalysisIssue` and `complete=false`; successful rules retain their findings. Collection failures stay in `snapshot.collector_runs`. An analysis can be complete while its evidence collection is partial. Missing fields and unsupported syntax limit the rules' ability to match; the original evidence and coverage records remain in the JSON report.

No findings means no supported predicate matched the available evidence. It does not mean the host is clean, the inventory is complete, or a command was harmless. Initial rules do not assign critical severity. Optional ATT&CK metadata does not affect any predicate or severity.

## Fixture walkthrough and tests

`samples/review.snapshot.json` produces thirteen findings, one per rule. `samples/partial.snapshot.json` produces eleven because its PowerShell command line is unavailable; the corresponding two host-option rules cannot match. `samples/benign.snapshot.json` produces none. All fixtures are invented, and no fixture string is executed.

From the repository after installation:

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_process_rules.py tests/test_persistence_rules.py tests/test_engine.py tests/test_sample_analysis.py -q
.\.venv\Scripts\irsnapshot.exe analyze samples/review.snapshot.json --output analysis.json
```
