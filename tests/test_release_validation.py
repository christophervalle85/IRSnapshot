"""Release checks must fail closed without exposing captured evidence."""
from pathlib import Path
import runpy
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts' / 'verify_install.py'


def validator():
    assert SCRIPT.is_file(), 'The portable installed-package validator is missing'
    return runpy.run_path(str(SCRIPT))


def test_rejects_source_import():
    verify = validator()['verify_installed_package']
    with pytest.raises(RuntimeError, match='source checkout|editable'):
        verify(ROOT)


def test_rejects_editable_install_outside_named_source_root(tmp_path):
    validator()
    # Isolate imports so checkout egg-info cannot mask real editable metadata.
    child = ('import runpy, sys; from pathlib import Path; '
             'runpy.run_path(sys.argv[1])["verify_installed_package"](Path(sys.argv[2]))')
    result = subprocess.run([sys.executable, '-I', '-c', child, str(SCRIPT), str(tmp_path)],
                            cwd=tmp_path, capture_output=True, encoding='utf-8', check=False)
    assert result.returncode != 0
    assert 'editable' in result.stderr


def test_subprocess_failure_is_not_success(tmp_path):
    run_command = validator()['run_command']
    with pytest.raises(RuntimeError, match='exit 7') as failure:
        run_command([sys.executable, '-c',
                     'import sys; print("synthetic secret"); sys.exit(7)'], cwd=tmp_path)
    assert 'synthetic secret' not in str(failure.value)


def test_subprocess_scrubs_import_environment_and_decodes_utf8(tmp_path, monkeypatch):
    run_command = validator()['run_command']
    monkeypatch.setenv('PYTHONPATH', str(ROOT))
    monkeypatch.setenv('PYTHONHOME', str(tmp_path / 'invalid-python-home'))
    child = ('import os, sys; '
             'sys.exit(8) if "PYTHONPATH" in os.environ or "PYTHONHOME" in os.environ '
             'else print("caf\\u00e9 \\U0001f50e")')
    result = run_command([sys.executable, '-c', child], cwd=tmp_path)
    assert result.stdout.strip() == 'café 🔎'


def test_expected_partial_subprocess_exit(tmp_path):
    run_command = validator()['run_command']
    result = run_command([sys.executable, '-c', 'raise SystemExit(3)'],
                         cwd=tmp_path, expected=3)
    assert result.returncode == 3


VALID_HTML = ('<!doctype html><html><head><style>body {color: black}</style></head>'
              '<body><main id="main"><a href="#main">UTC</a>'
              '<details>Evidence</details></main></body></html>')


@pytest.mark.parametrize('unsafe', [
    '<script>alert(1)</script>',
    '<img src="https://example.invalid/image.png">',
    '<a href="https://example.invalid">external</a>',
    '<a href="#missing">broken anchor</a>',
    '<span id="main">duplicate anchor</span>',
    '<span onclick="alert(1)">active content</span>',
    '<style>body {background: url(https://example.invalid)}</style>',
    '<style>@import "https://example.invalid/style.css";</style>',
    '<meta http-equiv="refresh" content="0;url=https://example.invalid">',
])
def test_html_validation_rejects_active_external_or_broken_markup(tmp_path, unsafe):
    validate_html = validator()['validate_html']
    document = tmp_path / 'report.html'
    document.write_text(VALID_HTML.replace('</main>', unsafe + '</main>'), encoding='utf-8')
    with pytest.raises(RuntimeError):
        validate_html(document)


def test_html_validation_accepts_offline_document(tmp_path):
    document = tmp_path / 'report.html'
    document.write_text(VALID_HTML, encoding='utf-8')
    assert validator()['validate_html'](document) == VALID_HTML


def test_validation_remains_active_under_python_optimization(tmp_path):
    validator()
    document = tmp_path / 'invalid.html'
    document.write_text(VALID_HTML.replace('#main', '#missing'), encoding='utf-8')
    child = ('import runpy, sys; '
             'runpy.run_path(sys.argv[1])["validate_html"](__import__("pathlib").Path(sys.argv[2]))')
    result = subprocess.run([sys.executable, '-O', '-c', child, str(SCRIPT), str(document)],
                            cwd=tmp_path, capture_output=True, encoding='utf-8', check=False)
    assert result.returncode != 0
    assert 'RuntimeError' in result.stderr


def test_script_rejects_editable_environment_before_validation(tmp_path):
    validator()
    result = subprocess.run([sys.executable, '-I', str(SCRIPT), '--samples', str(ROOT / 'samples')],
                            cwd=tmp_path, capture_output=True, encoding='utf-8', check=False)
    assert result.returncode == 1
    assert 'editable' in result.stderr or 'source checkout' in result.stderr
    assert 'Traceback' not in result.stderr
    assert not list(tmp_path.iterdir())


def test_synthetic_validation_writes_matching_outputs_without_modifying_samples(tmp_path):
    from irsnapshot.models import InvestigationReport
    from irsnapshot.storage import load_snapshot

    samples = ROOT / 'samples'
    before = {sample.name: sample.read_bytes() for sample in samples.glob('*.snapshot.json')}
    validator()['validate_samples'](samples, tmp_path)
    for sample, findings in [('benign', 0), ('review', 13), ('partial', 11)]:
        report = InvestigationReport.model_validate_json((tmp_path / f'{sample}.analysis.json').read_bytes())
        assert report.snapshot == load_snapshot(samples / f'{sample}.snapshot.json')
        assert len(report.analysis.findings) == findings
        folder = tmp_path / f'{sample}-investigation'
        assert {path.name for path in folder.iterdir()} == {
            'snapshot.json', 'analysis.json', 'report.html', 'irsnapshot.log'}
        assert (folder / 'analysis.json').read_bytes() == (tmp_path / f'{sample}.analysis.json').read_bytes()
        assert (folder / 'report.html').read_bytes() == (tmp_path / f'{sample}.html').read_bytes()
    assert {sample.name: sample.read_bytes() for sample in samples.glob('*.snapshot.json')} == before
