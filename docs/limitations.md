# Interpretation and operational limits

IRSnapshot 0.3.0 analyzes saved Windows evidence offline. It is a portfolio triage project, not an EDR, antivirus, continuous monitor, remediation tool, or forensic acquisition system. Live collection and HTML reporting remain later milestones.

## Snapshot scope

A snapshot covers a collection interval rather than one atomic instant. It cannot reconstruct exited processes, historical network ownership, past connections, deleted persistence, or events that were never captured. A missing parent or owner is retained as unresolved. PID matches are associations, not verified historical identity.

All seven collector records describe declared scope and failures. Successful collection means that scope was queried; it cannot promise visibility into every endpoint behavior. Failed/skipped sources are distinct from successfully empty sources. A denied field stays null and carries its collection issue. An analysis can finish successfully using incomplete evidence; the CLI still returns 3 when collection was partial, failed, or skipped.

## Matching limits

Rules are a transparent fixed set of heuristics with both false positives and false negatives. Legitimate installers, updaters, Office integrations, administrative scripts, and per-user applications can match. Conversely, an unsupported command form or absent field may hide a relevant behavior from these predicates. A zero-finding report is not a clean-host attestation.

Executable basenames do not prove file identity or publisher. Encoded command values remain opaque. The parser does not implement every PowerShell/Windows grammar variant, recursively inspect nested shells, deobfuscate scripts, evaluate inline code, or resolve commands through PATH. Persistence interpretation only supports the explicit forms documented in the [rule reference](rules.md).

Directory categories come from Windows lexical rules and captured path context. They do not measure ACLs, prove writability, establish trusted directories, authenticate binaries, or resolve aliases, links, junctions, or 8.3 names. Owner-specific environment values need an explicit SID; a username or task principal string does not establish one. Bounded variable expansion returns unresolved results when input exceeds its budgets.

The factual timeline uses captured boot, process-start, and session-logon times, plus labelled collection boundaries. Observation timestamps are not substitutes for missing event times. A scheduled trigger is a planned boundary, not proof that its action ran.

## Local files and output

Analysis performs no network requests or endpoint queries and never executes captured commands. Console evidence is rendered as literal text with control characters visible. JSON retains the original evidence, including command lines, usernames, addresses, and collection errors; those fields may contain sensitive information in real snapshots. Review the actual content before sharing a report.

The JSON report is a separate envelope containing `snapshot` and `analysis`; it is not itself a snapshot input to `analyze`. The output destination cannot alias the input snapshot, even when overwrite is requested. Other existing reports are preserved unless `--overwrite` is supplied. Atomic publication requires filesystem support: new-file no-clobber publication uses a hard link, and replacement uses an atomic rename. This is not chain-of-custody tooling or a power-loss durability guarantee.

Snapshot input is bounded at 64 MiB. JSON investigation-report output is bounded at 128 MiB; oversized reports fail before publication. This limit accommodates derived evidence while keeping output behavior explicit. Very large trees or findings can still produce substantial terminal output and use memory. There is no streaming analysis or performance guarantee for every endpoint size.

## Verification scope

Portable tests and clean-install checks run on the available macOS development host. They do not establish Windows installation, NTFS behavior, live collector permissions, or actual PowerShell execution behavior. No fixture command is run on any platform. The [verification record](testing.md) reports the Python versions, actual test results, and remaining Windows validation work.
