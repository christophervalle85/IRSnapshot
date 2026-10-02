"""Evidence-preserving investigation workflow with temporary local diagnostics."""
from contextlib import contextmanager
from pathlib import Path
import logging
import time
import traceback

from irsnapshot.analyzers.engine import analyze_snapshot
from irsnapshot.models import InvestigationReport
from irsnapshot.pipeline import collect_snapshot
from irsnapshot.reporting.html_report import write_html_report
from irsnapshot.reporting.json_report import write_json_report
from irsnapshot.reporting.process_tree import safe_text
from irsnapshot.storage import _publish_bytes, write_snapshot

logger = logging.getLogger(__name__)
_RESERVED = ('snapshot.json', 'analysis.json', 'report.html', 'irsnapshot.log')


class InvestigationError(RuntimeError):
    """A failed stage; metadata is safe for a concise console explanation."""
    def __init__(self, stage: str, snapshot_path: Path | None):
        super().__init__(f'Investigation failed during {stage}.')
        self.stage = stage
        self.snapshot_path = snapshot_path


class InvestigationInterrupted(KeyboardInterrupt):
    """Interrupted workflow retaining the path of newly published evidence."""
    def __init__(self, stage: str, snapshot_path: Path | None):
        super().__init__(f'Investigation interrupted during {stage}.')
        self.stage = stage
        self.snapshot_path = snapshot_path


def _prepare_output(output: Path, overwrite: bool) -> None:
    if output.is_symlink():
        raise ValueError('Investigation output must be a directory, not a symlink.')
    if output.exists():
        if not output.is_dir():
            raise ValueError('Investigation output must be a directory.')
        if not overwrite and any(output.iterdir()):
            raise FileExistsError('Investigation output must be new or empty; use --overwrite.')
    else:
        output.mkdir(parents=True)
    for name in _RESERVED:
        path = output / name
        if path.is_symlink() or (path.exists() and not path.is_file()):
            raise ValueError('Reserved investigation artifacts must be regular files, not directories or symlinks.')


def _open_log(path: Path, overwrite: bool):
    # Replacement creates a new inode: old hardlink targets are never truncated.
    # The log is deliberately incremental after this atomic initial publication.
    _publish_bytes(b'', path, overwrite=overwrite)
    return path.open('a', encoding='utf-8', newline='\n')


class _SafeLogHandler(logging.Handler):
    """Latch log failures for safe stage boundaries without stderr diagnostics."""
    def __init__(self, stream):
        super().__init__()
        self.stream = stream
        self.failure: Exception | None = None
        formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s', '%Y-%m-%d %H:%M:%S UTC')
        formatter.converter = time.gmtime
        self.setFormatter(formatter)

    def emit(self, record):
        try:
            # A copied record leaves later restored handlers unaffected.
            safe_record = logging.makeLogRecord(record.__dict__.copy())
            message = record.getMessage()
            if record.exc_info:
                message += '\n' + ''.join(traceback.format_exception(*record.exc_info, chain=True))
            if record.stack_info:
                message += '\n' + record.stack_info
            safe_record.msg = safe_text(message)
            safe_record.args = ()
            safe_record.exc_info = safe_record.exc_text = safe_record.stack_info = None
            self.stream.write(self.format(safe_record) + '\n')
            self.stream.flush()
        except Exception as exc:
            if self.failure is None:
                self.failure = exc

    def check(self):
        if self.failure is not None:
            raise self.failure


@contextmanager
def _scoped_logging(stream):
    package = logging.getLogger('irsnapshot')
    loggers = [package] + [value for name, value in logging.Logger.manager.loggerDict.copy().items()
                           if name.startswith('irsnapshot.') and isinstance(value, logging.Logger)]
    states = {item: (item.level, item.disabled, item.propagate, list(item.handlers)) for item in loggers}
    handler = _SafeLogHandler(stream)
    try:
        for item in loggers:
            item.handlers = [handler] if item is package else []
            item.setLevel(logging.INFO if item is package else logging.NOTSET)
            item.disabled = False
            item.propagate = item is not package
        yield handler
    finally:
        for item, (level, disabled, propagate, handlers) in states.items():
            item.handlers = handlers
            item.setLevel(level)
            item.disabled = disabled
            item.propagate = propagate
        handler.close()
        stream.close()


def run_investigation(output: Path, *, overwrite: bool = False) -> InvestigationReport:
    """Collect, save original evidence, analyze and publish standalone reports.

    Existing evidence survives until a replacement snapshot is saved. After that
    stale reports are removed before analysis. The UTF-8 log is incremental after
    atomic initial publication; logger state and file handles are always restored.
    """
    output = Path(output)
    _prepare_output(output, overwrite)
    stream = _open_log(output / 'irsnapshot.log', overwrite)
    snapshot_path = None
    stage = 'collection'
    try:
        with _scoped_logging(stream) as diagnostics:
            try:
                logger.info('Collection started')
                diagnostics.check()
                snapshot = collect_snapshot()
                diagnostics.check()
                stage = 'snapshot publication'
                write_snapshot(snapshot, output / 'snapshot.json', overwrite=overwrite)
                snapshot_path = output / 'snapshot.json'
                # Remove stale reports before any diagnostic or downstream work
                # that could fail after the new evidence has been published.
                stage = 'stale report cleanup'
                if overwrite:
                    for name in ('analysis.json', 'report.html'):
                        (output / name).unlink(missing_ok=True)
                logger.info('Snapshot saved to %s', snapshot_path)
                diagnostics.check()
                stage = 'analysis'
                logger.info('Analysis started')
                diagnostics.check()
                report = InvestigationReport(snapshot=snapshot, analysis=analyze_snapshot(snapshot))
                diagnostics.check()
                stage = 'JSON publication'
                logger.info('JSON report publication started')
                diagnostics.check()
                write_json_report(report, output / 'analysis.json', overwrite=overwrite)
                diagnostics.check()
                stage = 'HTML publication'
                logger.info('HTML report publication started')
                diagnostics.check()
                write_html_report(report, output / 'report.html', overwrite=overwrite)
                diagnostics.check()
                stage = 'completion logging'
                logger.info('Investigation completed')
                diagnostics.check()
                stage = 'log finalization'
                return report
            except BaseException:
                # Never let a broken log hide the original failed stage/evidence.
                try:
                    logger.error('Investigation stopped during %s', stage, exc_info=True)
                except Exception:
                    pass
                raise
    except KeyboardInterrupt as exc:
        raise InvestigationInterrupted(stage, snapshot_path) from exc
    except Exception as exc:
        raise InvestigationError(stage, snapshot_path) from exc
