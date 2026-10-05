"""Validate an installed IRSnapshot wheel using only synthetic sample evidence.

Run with the fresh installation's interpreter and isolated mode, for example:
    python -I scripts/verify_install.py --samples samples
"""
from html.parser import HTMLParser
from importlib.metadata import distribution
from importlib.resources import files
from pathlib import Path
import argparse
import json
import os
import re
import subprocess
import sys
import sysconfig
from tempfile import TemporaryDirectory
import tomllib
from unittest.mock import patch


def require(condition: bool, message: str) -> None:
    """Keep release checks active even when Python runs with optimization."""
    if not condition:
        raise RuntimeError(message)


def verify_installed_package(source_root: Path) -> None:
    """Reject source/editable imports and mismatched distribution metadata."""
    import irsnapshot

    source_root = source_root.resolve()
    installed = distribution('irsnapshot')
    direct_url = installed.read_text('direct_url.json')
    if direct_url is not None:
        metadata = json.loads(direct_url)
        require(not metadata.get('dir_info', {}).get('editable', False),
                'An editable install cannot validate a release wheel.')
    origin = Path(irsnapshot.__file__).resolve()
    require(not origin.is_relative_to(source_root),
            'IRSnapshot was imported from the source checkout; install a wheel in a fresh environment.')
    location = Path(installed.locate_file('')).resolve()
    require(not location.is_relative_to(source_root),
            'Distribution metadata came from the source checkout.')
    require(installed.files is not None, 'Installed distribution has no file manifest.')
    require(origin in {Path(installed.locate_file(item)).resolve() for item in installed.files},
            'Imported IRSnapshot is not a file in the installed distribution.')
    with (source_root / 'pyproject.toml').open('rb') as source:
        source_version = tomllib.load(source)['project']['version']
    require(installed.version == irsnapshot.__version__ == source_version,
            'Installed metadata, package version and source project version must match.')


def run_command(command: list[str], *, cwd: Path, expected: int = 0) -> subprocess.CompletedProcess:
    """Run UTF-8 CLI checks without source-path injection or raw failure output."""
    environment = os.environ.copy()
    for name in ('PYTHONPATH', 'PYTHONHOME'):
        environment.pop(name, None)
    environment.update(PYTHONUTF8='1', PYTHONIOENCODING='utf-8',
                       NO_COLOR='1', TERM='dumb', COLUMNS='120')
    try:
        result = subprocess.run(command, cwd=cwd, env=environment, stdin=subprocess.DEVNULL,
                                capture_output=True, encoding='utf-8', errors='strict',
                                timeout=60, check=False)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError('Validation command timed out.') from exc
    except OSError as exc:
        raise RuntimeError('Validation command could not be launched.') from exc
    require(result.returncode == expected,
            f'Validation command returned exit {result.returncode}; expected {expected}.')
    require('Traceback' not in result.stderr, 'Validation command emitted a traceback.')
    return result


class OfflineDocument(HTMLParser):
    """Check the static report's resource, active-content and anchor contract."""
    def __init__(self):
        super().__init__()
        self.tags: set[str] = set()
        self.anchors: list[str] = []
        self.ids: set[str] = set()
        self.in_style = False

    @staticmethod
    def check_css(css: str) -> None:
        require(re.search(r'url\s*\(|@import', css, re.IGNORECASE) is None,
                'HTML report contains a CSS resource reference.')

    def handle_starttag(self, tag, attributes):
        self.tags.add(tag)
        require(tag not in {'script', 'iframe', 'object', 'embed', 'link', 'img', 'base',
                            'form', 'audio', 'video', 'source', 'track', 'svg', 'math'},
                'HTML report contains active content or an external-resource element.')
        attrs = dict(attributes)
        require(not any(name.startswith('on') for name in attrs),
                'HTML report contains an event handler.')
        require(not {'src', 'srcdoc', 'srcset', 'poster', 'data', 'action', 'formaction',
                     'background', 'ping', 'xlink:href'} & attrs.keys(),
                'HTML report contains a resource attribute.')
        require('http-equiv' not in attrs, 'HTML report contains an HTTP-equivalent directive.')
        if 'href' in attrs:
            href = attrs['href'] or ''
            require(href.startswith('#') and len(href) > 1,
                    'HTML report contains a nonlocal or empty link.')
            self.anchors.append(href[1:])
        if 'id' in attrs:
            ident = attrs['id']
            require(bool(ident) and ident not in self.ids, 'HTML report has empty or duplicate IDs.')
            self.ids.add(ident)
        if 'style' in attrs:
            self.check_css(attrs['style'] or '')
        if tag == 'style':
            self.in_style = True

    def handle_endtag(self, tag):
        if tag == 'style':
            self.in_style = False

    def handle_data(self, data):
        if self.in_style:
            self.check_css(data)


def validate_html(path: Path) -> str:
    """Require a standalone HTML document with valid internal anchors."""
    markup = path.read_text(encoding='utf-8')
    document = OfflineDocument()
    document.feed(markup)
    document.close()
    require({'html', 'head', 'body', 'style', 'details', 'main'} <= document.tags,
            'HTML report is missing required document sections.')
    require(set(document.anchors) <= document.ids, 'HTML report has a broken internal anchor.')
    require('UTC' in markup, 'HTML report is missing UTC time labels.')
    return markup


def validate_samples(samples: Path, destination: Path) -> None:
    """Exercise offline CLI publication and orchestration with synthetic data."""
    from irsnapshot.investigation import run_investigation
    from irsnapshot.models import InvestigationReport
    from irsnapshot.storage import load_snapshot

    cases = [('benign', 0, 0), ('review', 13, 0), ('partial', 11, 3)]
    require({path.name for path in samples.glob('*.snapshot.json')} ==
            {f'{name}.snapshot.json' for name, _, _ in cases},
            'Sample set must contain exactly the benign, review and partial snapshots.')
    module = [sys.executable, '-X', 'utf8', '-I', '-m', 'irsnapshot']
    for name, finding_count, exit_code in cases:
        sample = samples / f'{name}.snapshot.json'
        original = sample.read_bytes()
        snapshot = load_snapshot(sample)
        json_output = destination / f'{name}.analysis.json'
        html_output = destination / f'{name}.html'
        for command, output in [('analyze', json_output), ('report', html_output)]:
            arguments = [command, str(sample), '--output', str(output)]
            run_command(module + arguments, cwd=destination, expected=exit_code)
            first = output.read_bytes()
            run_command(module + arguments, cwd=destination, expected=1)
            require(output.read_bytes() == first, f'{name}: no-clobber changed an existing report.')
            run_command(module + arguments + ['--overwrite'], cwd=destination, expected=exit_code)
            require(output.read_bytes() == first, f'{name}: explicit overwrite was not deterministic.')
            require(sample.read_bytes() == original, f'{name}: sample input was modified.')
        report = InvestigationReport.model_validate_json(json_output.read_bytes())
        require(report.snapshot == snapshot, f'{name}: report changed the original snapshot.')
        require(report.analysis.complete and len(report.analysis.findings) == finding_count,
                f'{name}: analysis completeness or finding count did not match expectations.')
        validate_html(html_output)

        # Substitute only collection; installed analysis/publication/logging stays real.
        folder = destination / f'{name}-investigation'
        with patch('irsnapshot.investigation.collect_snapshot', return_value=snapshot):
            result = run_investigation(folder)
            require(result == report, f'{name}: orchestration differs from standalone analysis.')
            require({path.name for path in folder.iterdir()} ==
                    {'snapshot.json', 'analysis.json', 'report.html', 'irsnapshot.log'},
                    f'{name}: orchestration did not publish exactly four artifacts.')
            prior = {path.name: path.read_bytes() for path in folder.iterdir()}
            try:
                run_investigation(folder)
            except FileExistsError:
                pass
            else:
                raise RuntimeError(f'{name}: orchestration accepted an occupied output directory.')
            require(all((folder / artifact).read_bytes() == content for artifact, content in prior.items()),
                    f'{name}: rejected orchestration changed existing artifacts.')
            require(run_investigation(folder, overwrite=True) == report,
                    f'{name}: overwritten orchestration changed analysis.')
        require(load_snapshot(folder / 'snapshot.json') == snapshot,
                f'{name}: orchestration changed the captured snapshot.')
        require(InvestigationReport.model_validate_json((folder / 'analysis.json').read_bytes()) == report,
                f'{name}: orchestration JSON failed model validation or changed the report.')
        require((folder / 'analysis.json').read_bytes() == json_output.read_bytes(),
                f'{name}: orchestration JSON differs from standalone output.')
        require((folder / 'report.html').read_bytes() == html_output.read_bytes(),
                f'{name}: orchestration HTML differs from standalone output.')
        require((folder / 'irsnapshot.log').stat().st_size > 0,
                f'{name}: orchestration log is empty.')
        require(sample.read_bytes() == original, f'{name}: orchestration modified the sample input.')
        validate_html(folder / 'report.html')
        print(f'{name}: {finding_count} findings, exit {exit_code}; offline reports and orchestration passed.')


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--samples', type=Path, required=True, help='Input-only synthetic sample directory.')
    arguments = parser.parse_args(argv)
    source_root = Path(__file__).resolve().parents[1]
    try:
        verify_installed_package(source_root)
        require(files('irsnapshot.reporting').joinpath('templates/report.html.j2').is_file(),
                'Installed HTML report template is missing.')
        samples = arguments.samples.resolve()
        require(samples.is_dir(), 'Synthetic sample directory does not exist.')
        console = Path(sysconfig.get_path('scripts')) / ('irsnapshot.exe' if os.name == 'nt' else 'irsnapshot')
        require(console.is_file(), 'Installed irsnapshot console script is missing.')
        installed_version = distribution('irsnapshot').version
        with TemporaryDirectory(prefix='irsnapshot-release-') as temporary:
            destination = Path(temporary).resolve()
            require(not destination.is_relative_to(source_root),
                    'Release validation temporary output must be outside the checkout.')
            require(not destination.is_relative_to(samples),
                    'Release validation temporary output must be outside the sample directory.')
            for command in ([str(console)], [sys.executable, '-X', 'utf8', '-I', '-m', 'irsnapshot']):
                result = run_command(command + ['--version'], cwd=destination)
                require(result.stdout.strip() == f'IRSnapshot {installed_version}',
                        'Installed CLI version does not match distribution metadata.')
                help_output = run_command(command + ['--help'], cwd=destination).stdout
                require(all(name in help_output for name in ('collect', 'analyze', 'report', 'run')),
                        'Installed CLI help is missing a supported command.')
                for name in ('collect', 'analyze', 'report', 'run'):
                    require('--output' in run_command(command + [name, '--help'], cwd=destination).stdout,
                            'Installed command help is missing its output option.')
            validate_samples(samples, destination)
        print('Installed-wheel validation passed using only synthetic evidence.')
        return 0
    except RuntimeError as exc:
        print(f'Installed-wheel validation failed: {exc}', file=sys.stderr)
    except Exception as exc:
        # Validation libraries may include evidence in exception values.
        print(f'Installed-wheel validation failed ({type(exc).__name__}).', file=sys.stderr)
    return 1


if __name__ == '__main__':
    raise SystemExit(main())
