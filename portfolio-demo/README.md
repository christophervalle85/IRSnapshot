# IRSnapshot sample reports

I included three synthetic investigations to demonstrate evidence collection coverage, explainable findings, and standalone reporting. These files contain invented evidence rather than live endpoint captures. The reports open locally on macOS or Windows without Python or external services.

## View the reports

Download or clone the repository, or extract [portfolio-demo.zip](https://github.com/christophervalle85/IRSnapshot/blob/main/portfolio-demo.zip), then open the HTML files locally. GitHub displays HTML source rather than rendering these reports.

| Report | Findings | Demonstrates |
|---|---:|---|
| [review.html](review.html) | 13 | One finding per behavioral rule, with evidence and process context. |
| [partial.html](partial.html) | 11 | Useful findings retained alongside incomplete collection coverage. |
| [benign.html](benign.html) | 0 | A snapshot without matches to the implemented rules. |

Expand a finding to inspect the source evidence, reason for review, and possible benign explanation. Compare the report with its matching `.analysis.json` file and original snapshot in [samples/](samples/). No captured command is executed.

## Provenance and verification

The reports were generated on October 28, 2026, from the source revision recorded in [manifest.json](manifest.json). The manifest includes file hashes, expected findings and exit codes, snapshot identifiers, and the producing package version. Structural checks covered JSON validation, matching snapshot identifiers, internal HTML anchors, and absence of active content or external resources.

The [recorded Windows run](https://github.com/christophervalle85/IRSnapshot/actions/runs/38686690894) passed 562 portable tests and three live installed-wheel tests per Python version on elevated Windows Server 2025 x64. Windows 10/11 x64 ordinary/elevated desktop validation is deferred. This demonstration is included with version 1.0.0; its manifest records the generating version and original snapshot metadata. Ongoing work is tracked in [repository issues](https://github.com/christophervalle85/IRSnapshot/issues).

Synthetic examples establish expected behavior, not detection accuracy. Zero findings do not establish that a host is clean. The Mac supports offline sample analysis rather than live endpoint collection.

See [my design decisions and walkthrough](https://github.com/christophervalle85/IRSnapshot/blob/main/docs/portfolio.md), [rule reference](https://github.com/christophervalle85/IRSnapshot/blob/main/docs/rules.md), and [release checklist](https://github.com/christophervalle85/IRSnapshot/blob/main/docs/release-validation.md). Regenerate the reports with the repository's `analyze` and `report` commands using the included snapshots.
