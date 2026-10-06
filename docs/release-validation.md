# Release validation

Milestone 5 is released as `0.5.0`. Milestone 6 adds repeatable release checks; its final Windows execution and print review gates remain open. The [testing record](testing.md) contains observed results. A workflow file or a checklist alone is not evidence that a platform passed.

## Automated Windows checks

`.github/workflows/windows.yml` runs on push, pull request, or manual dispatch after this repository is hosted on GitHub. It uses Windows Server 2025 x64 and Python `3.12` plus `3.x`, which selects the latest stable Python 3. Each job records its resolved Python and runner context. [setup-python documents version ranges](https://github.com/actions/setup-python/blob/v6/docs/advanced-usage.md#specifying-a-python-version).

The workflow runs the portable suite, builds a wheel, installs it into a fresh environment, checks dependencies, exercises the installed command entry points and template, and explicitly selects the live Windows smoke test. That live test requires basic system/process evidence and all seven collector records, while allowing partial sources. It is a smoke gate; failures and source-level limitations still need review before a release.

GitHub's Windows runners use administrator accounts with UAC disabled. Successful CI therefore provides hosted Server integration evidence, not ordinary-user or Windows 10/11 desktop evidence. [GitHub documents the privilege context](https://docs.github.com/en/actions/reference/runners/github-hosted-runners#administrative-privileges). Live test tracebacks and captured logs are suppressed in CI, and the workflow uploads no endpoint snapshots, reports, or logs.

This local repository has no configured Git remote. The workflow has not been dispatched or observed here. Record the actual workflow URL, commit, resolved Python versions, runner image, and result when it runs.

## Reproduce a clean wheel check

From the source checkout with a development `.venv` installed, run in PowerShell. Stop on any failure; the checks below deliberately fail when the wheel is missing or ambiguous. A unique temporary directory keeps previous release files intact.

```powershell
$source = (Get-Location).Path
$stage = Join-Path ([IO.Path]::GetTempPath()) ("irsnapshot-release-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $stage | Out-Null
.\.venv\Scripts\python.exe -m pip wheel --no-deps --wheel-dir "$stage\wheels" .
if ($LASTEXITCODE -ne 0) { throw "Wheel build failed" }
.\.venv\Scripts\python.exe -m venv "$stage\venv"
if ($LASTEXITCODE -ne 0) { throw "Environment creation failed" }
$python = Join-Path $stage "venv\Scripts\python.exe"
$wheels = @(Get-ChildItem "$stage\wheels\irsnapshot-*.whl")
if ($wheels.Count -ne 1) { throw "Expected exactly one IRSnapshot wheel" }
$wheelPath = $wheels[0].FullName
& $python -m pip install $wheelPath
if ($LASTEXITCODE -ne 0) { throw "Wheel installation failed" }
& $python -m pip check
if ($LASTEXITCODE -ne 0) { throw "Dependency check failed" }
& $python -I "$source\scripts\verify_install.py" --samples "$source\samples"
if ($LASTEXITCODE -ne 0) { throw "Installed-package validation failed" }
```

On macOS/Linux, create an equivalent fresh virtual environment and use its `bin/python` path. The validator is portable; invoke it with `-I` to prevent the working directory or `PYTHONPATH` from shadowing the installed package. It refuses editable/source imports, verifies distribution/version/template consistency, uses a temporary working directory, and leaves samples unchanged. Keep the script with its source checkout; it is release tooling, not part of the installed application.

Expected synthetic results:

| Sample | Findings | Analyze/report exit |
|---|---:|---:|
| benign | 0 | 0 |
| review | 13 | 0 |
| partial | 11 | 3 |

The validator also checks overwrite refusal, deterministic explicit replacement, offline HTML links, and all four investigation files with collection replaced by synthetic input. It never executes captured commands or performs live collection. Exit `3` for the partial sample is expected; the validator itself returns `0` only after every check passes.

## Windows desktop execution

Use a Windows 10/11 x64 test endpoint you control, 64-bit Python 3.12 or newer, and Windows PowerShell 5.1. Run first in an ordinary PowerShell session, then repeat in a separately opened elevated session. The tool never requests elevation. Record whether elevation changes the collecting identity, because HKCU and Startup scope follow that identity.

Use a fresh wheel environment as above for the CLI walkthrough. Use a development environment for the opt-in test:

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_windows_smoke.py -m windows_live -q
```

For each privilege context, set `$python` to the fresh wheel interpreter and choose a unique local output folder. These commands intentionally collect real endpoint data:

```powershell
$case = Join-Path $env:LOCALAPPDATA ("IRSnapshot-validation-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $case | Out-Null
& $python -I -m irsnapshot collect --output "$case\snapshot.json"
$collectExit = $LASTEXITCODE
if ($collectExit -notin @(0, 3)) { throw "Collection failed: $collectExit" }
& $python -I -m irsnapshot analyze "$case\snapshot.json" --output "$case\analysis.json"
$analyzeExit = $LASTEXITCODE
if ($analyzeExit -notin @(0, 3)) { throw "Analysis failed: $analyzeExit" }
& $python -I -m irsnapshot report "$case\snapshot.json" --output "$case\report.html"
$reportExit = $LASTEXITCODE
if ($reportExit -notin @(0, 3)) { throw "Reporting failed: $reportExit" }
& $python -I -m irsnapshot run --output "$case\investigation"
$runExit = $LASTEXITCODE
if ($runExit -notin @(0, 3)) { throw "Investigation failed: $runExit" }
@{ collect = $collectExit; analyze = $analyzeExit; report = $reportExit; run = $runExit }
```

Inspect all seven coverage rows and issues in both reports. An exit of `3` can be appropriate for denied fields, but unexplained failures or systematic missing sources are release defects to investigate, not automatic passes. Confirm the saved snapshot reloads, JSON and HTML refer to the matching snapshot, the log exists, and re-running without `--overwrite` refuses existing output without changing its bytes. The separate `run` command performs a new collection, so its snapshot ID and ambient inventory will differ from the preceding `collect`.

Record locally for every run: date, source commit, wheel version/hash, Windows edition/build, Python version/bitness, PowerShell version, actual captured elevation, whether the collecting identity changed, command exits, seven collector statuses/counts, and reviewed limitations. Share only a reviewed summary; real evidence contains identity and command data.

| Required evidence | Result |
|---|---|
| Hosted Windows matrix, Python 3.12 and latest stable | Pending |
| Windows 10 x64, ordinary session | Pending |
| Windows 10 x64, elevated session | Pending |
| Windows 11 x64, ordinary session | Pending |
| Windows 11 x64, elevated session | Pending |

## HTML and final release review

Open the synthetic review and partial reports in a browser with networking disabled. Confirm readable wide/narrow layouts, working local navigation, expandable evidence, visible partial coverage, escaped source text, and no external resource requests. Existing Milestone 5 browser results are in the testing record.

Inspect print preview or export to PDF on both review and partial reports. Check long tables, page breaks, evidence visibility, and coverage labels; record browser/version and result. Manual print appearance remains unverified.

Pay particular attention to evidence inside initially closed disclosure sections. Confirm the intended evidence appears in the printed output, and explicitly expand required sections before printing if the browser does not include closed content. Do not infer printed evidence visibility from its presence in the HTML source.

Only close Milestone 6 after recording the Windows results, reviewing remaining limitations, completing print review, rerunning checks on the chosen release commit, and updating the changelog/version and release artifacts together. Keep the completed `0.5.0` artifacts as historical releases.
