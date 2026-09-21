"""Validated full-evidence JSON reports, atomically published without clobbering."""
from pathlib import Path

from irsnapshot.models import InvestigationReport
from irsnapshot.storage import _publish_bytes

MAX_REPORT_BYTES = 128 * 1024 * 1024


def write_json_report(report: InvestigationReport, output: Path, *, overwrite: bool = False) -> None:
    """Retain the snapshot and analysis; reject reports larger than 128 MiB.

    The directory must already exist. Publication has the same atomic/no-clobber
    filesystem requirements as snapshot storage. This generic writer has no input
    file identity; the analyze CLI separately guards input/output aliases.
    """
    validated = InvestigationReport.model_validate(report)
    payload = (validated.model_dump_json(indent=2) + '\n').encode('utf-8')
    if len(payload) > MAX_REPORT_BYTES:
        raise ValueError('Report exceeds the supported file size limit (128 MiB)')
    _publish_bytes(payload, Path(output), overwrite=overwrite)
