"""Validated JSON input and atomic, no-clobber snapshot publication."""

import json
import logging
import os
import tempfile
from pathlib import Path

from pydantic import ValidationError

from irsnapshot.models import SystemSnapshot

logger = logging.getLogger(__name__)
MAX_SNAPSHOT_BYTES = 64 * 1024 * 1024


class SnapshotValidationError(ValueError):
    """The file cannot be interpreted as a supported, valid snapshot."""


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for name, value in pairs:
        if name in result:
            raise SnapshotValidationError("Duplicate JSON object keys are not allowed")
        result[name] = value
    return result


def _reject_nonfinite(value: str) -> None:
    raise SnapshotValidationError("Non-finite JSON numbers are not allowed")


def load_snapshot(path: Path) -> SystemSnapshot:
    """Read UTF-8 JSON; invalid evidence raises SnapshotValidationError, I/O raises OSError."""
    with Path(path).open("rb") as source:
        raw = source.read(MAX_SNAPSHOT_BYTES + 1)
    if len(raw) > MAX_SNAPSHOT_BYTES:
        raise SnapshotValidationError("Snapshot exceeds the supported file size limit (64 MiB)")
    try:
        data = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_unique_object,
            parse_constant=_reject_nonfinite,
        )
    except SnapshotValidationError:
        raise
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise SnapshotValidationError("Snapshot must contain a UTF-8 JSON object") from exc
    if not isinstance(data, dict):
        raise SnapshotValidationError("Snapshot must contain a JSON object")
    if data.get("schema_version") != "1.0":
        raise SnapshotValidationError("An explicit supported schema_version of '1.0' is required")
    try:
        result = SystemSnapshot.model_validate(data)
    except ValidationError as exc:
        # Include field locations and error types, never values or raw commands.
        details = "; ".join(
            f"{'.'.join(map(str, error['loc'])) or 'snapshot'}: {error['type']}"
            for error in exc.errors(include_input=False, include_context=False)[:5]
        )
        raise SnapshotValidationError(f"Invalid snapshot: {details}") from exc
    logger.debug("Loaded snapshot %s", result.snapshot_id)
    return result


def write_snapshot(snapshot: SystemSnapshot, path: Path, *, overwrite: bool = False) -> None:
    """Publish a complete file atomically; refuse existing paths unless overwrite is explicit.

    A hard link provides race-safe no-clobber publication on supporting filesystems
    (including NTFS). Unsupported filesystems raise OSError rather than using an
    unsafe check-then-write fallback. The parent directory must already exist.
    """
    validated = SystemSnapshot.model_validate(snapshot)
    payload = (validated.model_dump_json(indent=2) + "\n").encode("utf-8")
    if len(payload) > MAX_SNAPSHOT_BYTES:
        raise SnapshotValidationError("Snapshot exceeds the supported file size limit (64 MiB)")
    _publish_bytes(payload, Path(path), overwrite=overwrite)
    logger.info("Saved snapshot %s to %s", validated.snapshot_id, path)


def _publish_bytes(payload: bytes, destination: Path, *, overwrite: bool = False) -> None:
    """Publish validated bytes atomically in an existing destination directory."""
    temporary: Path | None = None
    try:
        # Close before publishing: Windows cannot rename an open NamedTemporaryFile.
        with tempfile.NamedTemporaryFile(
            mode="wb", prefix=f".{destination.name}.", suffix=".tmp",
            dir=destination.parent, delete=False,
        ) as stream:
            temporary = Path(stream.name)
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        if overwrite:
            os.replace(temporary, destination)
        else:
            os.link(temporary, destination)
    finally:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                # Preserve the original publication error; surface leftover evidence.
                logger.warning("Unable to remove temporary output file %s", temporary, exc_info=True)
