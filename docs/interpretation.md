# Evidence interpretation APIs

These APIs interpret already captured, validated evidence. They do not collect endpoint data, execute commands, resolve a live filesystem, assign findings, or change severity. Input models are revalidated; original evidence remains unchanged. Snapshot schema `1.0` is unchanged.

## API map

| Module | Function | Result |
|---|---|---|
| `analyzers.process_tree` | `build_process_tree(processes)` | `ProcessTree` |
| `reporting.process_tree` | `render_process_tree(tree, processes)` | Rich `Tree` |
| `analyzers.paths` | `classify_path(path, context, owner_sid=None)` | `PathAssessment` |
| `analyzers.commands` | `parse_process_command(process)` | `CommandFacts` |
| `analyzers.commands` | `parse_command_target(command)` | `CommandTarget` |
| `analyzers.network` | `correlate_network(snapshot)` | List of `NetworkProcessLink` |
| `correlation.relationships` | `correlate_findings(findings, tree, links)` | List of `FindingContext` |
| `correlation.timeline` | `build_timeline(snapshot)` | List of `TimelineEvent` |

Imports begin with `irsnapshot.`. Command/path facts are intermediate dataclasses; existing Pydantic contracts represent trees, links, contexts, and timeline events. These APIs remain usable independently of detection rules. The [offline example](../examples/interpret_snapshot.py) demonstrates interpretation without detections; the `analyze` command evaluates rules and applies finding correlation.

## Investigation analysis API

```python
from pathlib import Path
from rich.console import Console
from irsnapshot.storage import load_snapshot
from irsnapshot.analyzers.engine import analyze_snapshot
from irsnapshot.models import InvestigationReport
from irsnapshot.reporting.console import render_console
from irsnapshot.reporting.json_report import write_json_report

snapshot = load_snapshot(Path('samples/review.snapshot.json'))
analysis = analyze_snapshot(snapshot)
report = InvestigationReport(snapshot=snapshot, analysis=analysis)
render_console(report, Console())
write_json_report(report, Path('analysis.json'))
```

The report writer refuses an existing destination unless `overwrite=True` is explicit. `analyze_snapshot` uses the bundled `DEFAULT_RULES`; an optional `rules` sequence enables controlled library tests/custom evaluation, not a runtime plugin loader. Rules receive isolated copies of an `AnalysisContext` containing snapshot, process tree, and network links. Rule exceptions yield incomplete analysis with an issue; structural engine failures raise `AnalysisError`. The command-line wrapper maps these outcomes to the documented exit codes and protects the input path. Library callers choose separate output paths themselves.

Persistence-specific target extraction is implemented in `analyzers.persistence`; its conservative supported subset and limitations are documented in the [rule reference](rules.md). These helpers neither modify the original raw fields nor execute their contents.

## Process relationships and rendering

Process nodes and children are ordered by PID, then artifact UUID. Missing parents are not invented. PID 0, a missing PPID, and a self-referencing PPID produce roots. An absent parent is labelled `missing`. A parent created after its reported child is rejected as `newer_parent`. If either creation time is unknown, a present parent link remains `unverified`. Compatible known times produce `linked`, which is an association within this inventory, not proof of historical identity.

Cycles are broken at their lowest PID and labelled `cycle_broken`. Construction and rendering use iterative traversal; construction is tested with a 1,800-process chain. Duplicate PIDs or artifact IDs are rejected. Rendering requires the exact same artifact inventory as the tree. Names use Rich `Text`, so bracket markup remains literal; control and invisible formatting characters become visible escape text.

## Windows path facts

`PathAssessment` contains `category`, `normalized_path`, `confidence`, and `basis`. Categories are `temp`, `appdata`, `profile`, `other`, and `unknown`. Windows lexical normalization handles case, separators, paired quotes, and dot components on any development host. Containment respects directory boundaries: a captured `C:\Temp` does not match `C:\Tempest`.

Only captured `PathContext` values are used. A variable scoped to an owner SID requires that explicit SID; it overrides the same unscoped name. Without an owner SID, only unscoped values may expand. Usernames do not establish SIDs. Missing, conflicting, cyclic, or excessive expansions remain unresolved. Resource limits are 32 nested variables, 256 substitutions, and 32,768 characters per expanded value/path; these are interpreter budgets, not claims about Windows path limits. Relative and drive-relative paths, device namespaces, unsupported stream/colon syntax, malformed quoting, incomplete UNC paths, controls, and trailing component dots/spaces are unresolved.

The longest matching captured root wins. Temp has priority at an equal root. Incompatible equal-root categories remain unresolved; equivalent matches have stable selection independent of capture order. A captured root gives `known_root` confidence. Conventional AppData/Temp subdirectories beneath captured profile or Windows roots give `conventional_pattern` confidence. An otherwise valid absolute path receives `other / conventional_pattern`; here that confidence means a valid lexical path with no recognized captured category, not a positive assertion about a directory convention. The basis makes this distinction explicit.

These categories do not establish ACLs, trust, executable existence, or actual user writability. Junctions, symbolic links, 8.3 names, reserved device-name semantics, and other aliases are not resolved. The captured original path must be preserved alongside any normalized analysis value.

## Command facts and limits

Process command lines are already-tokenized lists. The parser compares executable basenames (case-insensitive, allowing a missing `.exe` suffix); it does not authenticate the executable or equate full paths. An identity mismatch halts interpretation with an issue. Non-PowerShell processes retain their argument payload without PowerShell host-option interpretation.

For `powershell` and `pwsh`, supported host options use an explicit case-insensitive alias/prefix table. It recognizes encoded-command and window-style options, common launch flags, format and execution-policy arguments, and command/file boundaries. `pwsh` additionally supports command-with-arguments, working-directory options, and double-dash switches. Version handling distinguishes the legacy value-taking option from modern version output. This is a conservative recognition subset, not validation of every legal invocation or option combination.

`-Command`, `-File`, and `-CommandWithArgs` stop scanning before their payload. An encoded-command argument stays opaque: it is never decoded or run. Unknown, duplicate, missing-value, or unsupported options stop parsing and retain the remaining tokens in `payload`; `parse_issues` explains uncertainty. An unavailable or empty command line remains unresolved. Recognized options are syntax observations and do not prove that the host accepted or executed them.

Host behavior was checked against Microsoft's [Windows PowerShell host documentation](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_powershell_exe?view=powershell-5.1), [pwsh documentation](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_pwsh?view=powershell-7.5), and the [upstream command-line parser](https://github.com/PowerShell/PowerShell/blob/master/src/Microsoft.PowerShell.ConsoleHost/host/msh/CommandLineParameterParser.cs). Supported dash characters include ASCII hyphen and U+2013/U+2014/U+2015; U+2212 is distinct, consistent with Microsoft's [dash explanation](https://devblogs.microsoft.com/powershell/em-dash-en-dash-dash-dash/). These checks do not replace execution tests on Windows.

Raw service/Run strings use a narrower helper: the first target must be a balanced double-quoted path or an unquoted whitespace-free token with an explicit `.exe`/`.com` suffix. Ambiguous spaced paths and shell expressions remain unresolved. This avoids guessing among the interpretations described in Microsoft's [CreateProcessW documentation](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw). A returned target can still contain variables or be relative; location classification is a separate step. PATH lookup, shell grammar, interpreter payload extraction, and persistence detection are outside this helper.

## Network and finding context

Network status distinguishes `owner_unavailable` (null PID), `process_missing`, `temporal_conflict` (process creation after connection observation), and `pid_match`. PID 0 is a real value. A match does not prove which historical process owned traffic, including when creation time is missing. Scoped IPv6 addresses remain part of the original network artifact; correlation uses its identity and owner PID without rewriting endpoints.

Finding context uses artifact UUIDs, not convenience PID hints. Direct process evidence and matched network evidence identify the associated process set. Context includes its ancestors, immediate children, and its own connections; relatives do not inherit findings, connections, or severity. An unowned directly referenced connection remains in the context. Unknown references may belong to service or persistence evidence and do not produce invented process links.

Duplicate finding/connection identities, process/connection ID collisions, and network endpoints outside the supplied tree are rejected. Ancestors can cross `unverified` links; consumers must keep the tree's status visible. Results use stable UUID ordering.

## Factual timeline

Only captured system boot times, process creation times, and logged-in-session logon times produce reported events. Null event times are omitted. Snapshot start/end are explicitly observed collection boundaries. Connection observation times and task schedule boundaries do not become execution events. Results sort by UTC timestamp, event kind, artifact IDs, then description. Descriptions retain evidence as data; each presentation layer must escape it, as the example and tree renderer do.
