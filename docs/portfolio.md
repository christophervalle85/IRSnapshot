# My IRSnapshot design decisions and walkthrough

I built IRSnapshot around a saved Windows triage snapshot so I could separate collection from analysis and reporting. The implementation includes four CLI commands, seven collection categories, thirteen behavioral rules, process and network correlation, and JSON/HTML reporting.

## Why I chose this design

| Decision | My reasoning |
|---|---|
| Typed evidence and explicit collection coverage | I wanted unavailable evidence to remain distinct from a successful empty result. |
| Deterministic rules and finding identifiers | I wanted each finding to be reproducible and traceable to its source artifacts. |
| Separate collection, analysis, correlation, and reporting | I kept these stages separate so saved snapshots can be analyzed offline and components can be tested independently. |
| Save the snapshot before generating reports | I save the snapshot first so a later failure leaves collected evidence available for recovery. |
| Fixed Windows queries and escaped report content | I keep captured evidence separate from executable code and presentation markup. |
| Atomic publication and explicit overwrite protection | I preserve existing files when publication fails or a destination is already occupied. |

## Example investigation

The [demo directory](../portfolio-demo/README.md) contains ready-to-open reports and their original synthetic snapshots. After downloading or cloning the repository:

1. Open `portfolio-demo/review.html`. Inspect a finding's rule, evidence, explanation, and process context. This sample produces 13 findings, one per rule.
2. Open `portfolio-demo/partial.html`. Review the 11 retained findings alongside failed collection sources. Partial coverage remains visible throughout the report.
3. Open `portfolio-demo/benign.html`. It produces no findings; that result applies only to the available evidence and implemented rules.

Each HTML report has a matching analysis JSON file. The JSON retains the original snapshot, derived findings, relationships, available timeline events, and collection issues. No captured command is executed. See the [rule reference](rules.md) for matching boundaries and benign explanations.

To regenerate a report from the checkout after installation:

```powershell
.\.venv\Scripts\irsnapshot.exe report samples/review.snapshot.json --output review.html
.\.venv\Scripts\irsnapshot.exe report samples/partial.snapshot.json --output partial.html
$LASTEXITCODE # Expected: 3 for the partial-coverage sample.
```

Use a new output path, or explicitly pass `--overwrite` to replace an existing report.

## Validation status

| Area | Recorded result |
|---|---|
| Portable behavior | 562 tests passed on the documented macOS and Windows Server environments. |
| Installed Windows commands | Clean-wheel installation and 3 live tests passed per Python version, including all four commands. |
| Native Windows environment | Elevated Windows Server 2025 x64; Python 3.12.10 and 3.15.0. |
| Synthetic reports | Benign/review/partial samples produce 0/13/11 findings. |
| Windows 10/11 x64 desktop sessions | Ordinary and elevated sessions remain unverified. |
| Printed reports | Visual print/PDF inspection remains pending. |

Native execution exposed a LocalAccounts module-import defect. A failing regression established the cause before correction; the final Windows matrix passed after the query switched to the trusted absolute module directory. In those reported CLI captures, system, network, users, services, scheduled tasks, and persistence succeeded. Four process-access denials remained explicitly partial.

The [verification record](testing.md) contains exact environments, source revisions, test results, and execution links. The [release checklist](release-validation.md) tracks the remaining desktop, print, and release checks. The application feature set is implemented; M6 and the final v1 release remain open.

## Interpretation limits

Findings identify behaviors that warrant review, with possible benign explanations. Synthetic expected results verify functionality rather than detection accuracy. A PID association does not prove historical ownership, a path category does not establish filesystem permissions, and a zero-finding report does not establish that an endpoint is clean. See [limitations](limitations.md) for collection and analysis boundaries.
