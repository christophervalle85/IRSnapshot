# My IRSnapshot portfolio demonstration

I built IRSnapshot to collect a point-in-time Windows evidence snapshot, apply 13 explainable behavioral rules, correlate related records, and generate standalone JSON and HTML reports.

I prepared these synthetic reports on October 17, 2026, and added this walkthrough to the private repository on October 20, 2026. I included no live endpoint captures. I can demonstrate the reports on a Mac or Windows computer without installing Python.

## How I demonstrate the project

1. I open [review.html](review.html) locally and explain one of its 13 findings: the original evidence, the reason for review, and a possible benign explanation.
2. I open [partial.html](partial.html) and show how 11 findings remain useful while missing collection sources stay visible. I do not equate zero findings with a clean host.
3. I open [benign.html](benign.html), which has zero findings. I compare each report with its matching analysis JSON and original input in [samples/](samples/).

I download or clone the private repository, then open these HTML files from the `portfolio-demo` folder. GitHub displays HTML source rather than running the report. I need no external services to read the local reports.

## The engineering decisions I explain

I keep collection, models, analysis, correlation, and presentation separate. I retain original evidence alongside deterministic findings and available timeline events. I use fixed Windows queries and render captured strings literally. I save the snapshot before derived analysis and reports so a later failure preserves the evidence. I never execute commands captured in a snapshot.

## What I verified

I verified expected results of 0, 13, and 11 findings for the benign, review, and partial samples, respectively. I checked JSON models, matching snapshot identifiers, internal HTML links, and the absence of active content and external HTML resources. I recorded file hashes and the producing source commit in [manifest.json](manifest.json).

I also validated clean installation and all four commands through private CI on elevated Windows Server 2025 x64. I recorded 562 portable tests and three live tests passing on each of Python 3.12.10 and 3.15.0 in the [Windows run](https://github.com/christophervalle85/IRSnapshot/actions/runs/38686690894).

I still need Windows 10/11 x64 ordinary and elevated desktop checks, visual print/PDF inspection, and final release packaging before I close M6 and release v1. I use this bundle as an unreleased portfolio demonstration; the package version remains 0.5.0. I use my Mac for offline sample analysis rather than live Windows collection. I have not measured detection accuracy with these synthetic examples.

## How I describe it

I developed IRSnapshot, a Python Windows incident-response triage CLI with 13 explainable behavioral rules, typed evidence collection, deterministic JSON/HTML reporting, and snapshot-preserving failure recovery. I validated clean installation and live collection through private Windows CI.

I keep the subtitle precise: “Windows incident-response triage CLI — tested on Windows Server; desktop validation pending.” I keep the repository private.

I can regenerate the reports from the included snapshots using the repository's `analyze` and `report` commands. I describe the remaining checks in the [release checklist](../docs/release-validation.md) and the project's strengths in my [portfolio assessment](../docs/portfolio.md).
