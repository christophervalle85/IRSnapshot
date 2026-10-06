# Portfolio value and completion assessment

Assessed on 2026-10-06 against the implemented project, accepted architecture, recorded tests, and an independent targeted review.

**IRSnapshot is a solid résumé project now. Its implementation has meaningful security-engineering depth and a working synthetic offline demonstration. Milestone 6 and the final Windows release are not complete yet.**

## What makes the project worth showing

- **Honest evidence coverage:** seven collector categories record successful, partial, failed, and skipped sources. Missing evidence is not treated as a clean result. Collection completeness is distinct from analysis success and finding count.
- **Explainable analysis:** thirteen deterministic heuristic rules retain source evidence and benign explanations. Rule failures are isolated, and identical evidence produces reproducible IDs and output ordering.
- **Recoverable investigations:** the snapshot is saved before analysis and reporting. Downstream failures preserve evidence, while explicit overwrite and no-clobber behavior protect existing outputs.
- **Careful input boundaries:** fixed Windows queries, conservative command interpretation, escaped report content, and literal captured strings keep evidence from becoming executable instructions.
- **Distributable output:** four CLI commands, validated JSON, standalone HTML, packaged templates, and clean-install checks demonstrate more than a source-only prototype.

The recorded suite has 562 passing portable cases on Python 3.12 and 3.14, with the live Windows test explicitly excluded. These include failure injection, real publication contention, partial coverage, reproducibility, and installed-package behavior. They do not substitute for native Windows tests. See [verification evidence](testing.md).

## Completion status

| Area | Assessment |
|---|---|
| Accepted application feature set | Implemented: four commands, seven collection categories, thirteen rules, correlation, JSON/HTML reports, and recovery |
| Portable behavior and installation | Verified on the documented macOS/Python environments |
| Synthetic offline demonstration | Ready; benign/review/partial samples produce 0/13/11 findings |
| Native Windows CI | Workflow prepared; no observed run yet |
| Windows 10/11 x64 ordinary and elevated sessions | Pending; an ARM64 VM cannot substitute for the declared x64 target |
| Printed report appearance and evidence visibility | Pending; inspect closed disclosure sections as well as tables and page breaks |
| Milestone 6 / final v1 release | Incomplete until those execution gates and final release checks are recorded |

No new source-code blocker was identified by the targeted assessment. That is not a comprehensive security certification or proof of Windows correctness. A green hosted smoke test would establish basic hosted Windows evidence and a round trip; it intentionally permits partial sources and would not by itself establish complete desktop coverage.

The necessary remaining work is validation, followed by repairs to any observed defects and coherent release finalization. More rules, a web dashboard, cloud storage, malware execution, or a background service are not required to finish the accepted scope. The [release checklist](release-validation.md) gives the exact commands and evidence to record.

## Suggested résumé wording

Use wording that matches the implementation and technical decisions you can explain. Keep the repository's Windows-validation status visible when linking the project.

- Developed IRSnapshot, a Python incident-response triage CLI with 13 evidence-linked heuristic rules, deterministic JSON/HTML reporting, and 562 automated test cases covering validation, partial collection, and failure recovery.
- Designed a typed evidence pipeline that isolates collection and rule failures and preserves snapshots when downstream analysis or reporting fails.

An optional project subtitle is **“Python incident-response triage project — native Windows validation in progress.”**

Do not describe the current release as a production-ready EDR, a validated Windows 10/11 deployment, or a malware detector with measured accuracy. Detection accuracy, time saved, adoption, and real-incident outcomes have not been measured. Synthetic expected findings are functional checks, not detection-performance metrics.

## A short interview demonstration

After installing the project as described in the README, use these PowerShell commands from the checkout. Choose a new demo directory each time:

```powershell
$demo = Join-Path ([IO.Path]::GetTempPath()) ("irsnapshot-demo-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $demo | Out-Null
.\.venv\Scripts\irsnapshot.exe analyze samples/benign.snapshot.json
.\.venv\Scripts\irsnapshot.exe report samples/review.snapshot.json --output "$demo\review.html"
.\.venv\Scripts\irsnapshot.exe report samples/partial.snapshot.json --output "$demo\partial.html"
$LASTEXITCODE # Expected: 3, because collection is incomplete in this synthetic sample.
```

Open the HTML files locally. Explain one finding's evidence and benign explanation, then show the partial report retaining useful findings while clearly identifying unavailable sources. Explain why a zero-finding report is not proof of a clean host, why a PID match is not historical identity, and why the snapshot is published before derived reports. This demonstration executes no captured command and makes no claim of live endpoint validation.

Before an interview, be able to trace one record from collector to model to rule to report, explain one failure-injection test, and modify a small behavior with its test. Those explanations make the project credible; a large test count alone does not.
