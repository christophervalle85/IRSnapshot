# Interpretation and operational limits

IRSnapshot 0.5.0 implements local Windows evidence collection, offline analysis, standalone HTML reports, and investigation orchestration. It is a portfolio triage project, not an EDR, antivirus, continuous monitor, remediation tool, or forensic acquisition system. Windows collectors have fixture tests and passing hosted Windows Server live validation; Windows 10/11 desktop validation remains open.

## Snapshot scope

A snapshot covers a collection interval rather than one atomic instant. It cannot reconstruct exited processes, historical network ownership, past connections, deleted persistence, or events that were never captured. A missing parent or owner is retained as unresolved. PID matches are associations, not verified historical identity.

All seven collector records describe declared scope and failures. Successful collection means that scope was queried; it cannot promise visibility into every endpoint behavior. Failed/skipped sources are distinct from successfully empty sources. A denied field stays null and carries its collection issue. An analysis can finish successfully using incomplete evidence; the CLI still returns 3 when collection was partial, failed, or skipped.

Live collection targets Windows 10/11 x64 with 64-bit Python and Windows PowerShell 5.1. Current-user registry and Startup scope follow the collecting identity. Other users' offline hives, recursive domain membership, historical events, and packet capture are outside this milestone. [Collection details](collection.md) describe the individual sources and their limitations.

## Matching limits

Rules are a transparent fixed set of heuristics with both false positives and false negatives. Legitimate installers, updaters, Office integrations, administrative scripts, and per-user applications can match. Conversely, an unsupported command form or absent field may hide a relevant behavior from these predicates. A zero-finding report is not a clean-host attestation.

Executable basenames do not prove file identity or publisher. Encoded command values remain opaque. The parser does not implement every PowerShell/Windows grammar variant, recursively inspect nested shells, deobfuscate scripts, evaluate inline code, or resolve commands through PATH. Persistence interpretation only supports the explicit forms documented in the [rule reference](rules.md).

Directory categories come from Windows lexical rules and captured path context. They do not measure ACLs, prove writability, establish trusted directories, authenticate binaries, or resolve aliases, links, junctions, or 8.3 names. Owner-specific environment values need an explicit SID; a username or task principal string does not establish one. Bounded variable expansion returns unresolved results when input exceeds its budgets.

The factual timeline uses captured boot, process-start, and session-logon times, plus labelled collection boundaries. Observation timestamps are not substitutes for missing event times. A scheduled trigger is a planned boundary, not proof that its action ran.

## Local files and output

Analysis and offline reporting perform no network requests or endpoint queries and never execute captured commands. Console evidence is rendered as literal text with control characters visible. HTML escapes source evidence, has no scripts or external assets, and never turns artifact strings into active links. JSON and HTML retain evidence including command lines, usernames, addresses, and collection errors; those fields may contain sensitive information in real snapshots. Review the actual content before sharing a report.

The JSON report is a separate envelope containing `snapshot` and `analysis`; it is not itself a snapshot input to `analyze`. The output destination cannot alias the input snapshot, even when overwrite is requested. Other existing reports are preserved unless `--overwrite` is supplied. Atomic publication requires filesystem support: new-file no-clobber publication uses a hard link, and replacement uses an atomic rename. This is not chain-of-custody tooling or a power-loss durability guarantee.

The investigation folder is not a transactional database. Each evidence/report file is published atomically, but the complete set is not a single atomic operation. A failed downstream stage can leave a saved snapshot and log without a complete report. Under explicit overwrite, old derived reports are removed after the new snapshot is published and before analysis. If that cleanup itself fails, the run stops; earlier reports may remain, so check snapshot IDs before using outputs from a failed folder. The local log is written incrementally after its initial publication. Use a separate folder per investigation when retaining prior output matters; see [recovery behavior](reporting.md).

Snapshot input is bounded at 64 MiB. JSON and HTML investigation-report output are bounded at 128 MiB each; oversized reports fail before publication. This limit accommodates derived evidence while keeping output behavior explicit. Very large trees or findings can still produce substantial output and use memory before the output-size check. There is no streaming analysis or performance guarantee for every endpoint size.

## Verification scope

Portable tests and clean-install checks passed on macOS and hosted Windows Server 2025 x64. The Windows runs exercise native file publication, installed command entry points and real collection in an administrator context. They do not establish every desktop permission, filesystem or endpoint configuration. No captured fixture command is executed on any platform. The [verification record](testing.md) reports actual versions, results and collection limitations.

The Milestone 6 Windows workflow has executed successfully. Hosted Windows Server administrator coverage cannot substitute for ordinary-user or elevated Windows 10/11 desktop checks. The [release checklist](release-validation.md) tracks those separately. Print styles exist, but printed output still requires visual inspection.

Hosted captures encountered process-access denials and occasional 30-second PowerShell query timeouts, including scheduled-task enumeration. Such sources remain partial or failed with explicit issues; dependent persistence coverage is also reduced. A successful investigation means the available evidence was preserved and analyzed, not that every source was readable. Native regression work also identified and corrected LocalAccounts module discovery for versioned Windows installations.
