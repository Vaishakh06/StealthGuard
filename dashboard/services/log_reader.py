"""JSONL log reader with deduplication, tail tracking and error tolerance."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Iterator

logger = logging.getLogger("stealthguard.dashboard.log_reader")


def read_jsonl(path: Path, max_lines: int | None = None) -> list[dict]:
    """Read all valid JSONL records from *path*.

    Malformed lines are skipped and logged.  A missing file returns an
    empty list instead of raising.
    """
    if not path.exists():
        logger.debug("Log file does not exist: %s", path)
        return []

    records: list[dict] = []
    lines_read = 0

    try:
        with path.open("r", encoding="utf-8") as fh:
            for line in fh:
                lines_read += 1
                if max_lines is not None and lines_read > max_lines:
                    break
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    records.append(json.loads(stripped))
                except json.JSONDecodeError as exc:
                    logger.warning(
                        "Skipping malformed JSONL line %s in %s: %s",
                        lines_read,
                        path,
                        exc,
                    )
    except OSError as exc:
        logger.error("Unable to read %s: %s", path, exc)
        return []

    return records


def tail_jsonl(path: Path, since_line: int = 0) -> tuple[list[dict], int]:
    """Return new records appended after *since_line*.

    Returns (records, total_lines_seen).  This lets callers track their
    position and avoid re-processing already-seen records on refresh.
    """
    if not path.exists():
        return [], 0

    records: list[dict] = []
    total_lines = 0
    line_no = 0

    try:
        with path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line_no += 1
                total_lines = line_no
                if line_no <= since_line:
                    continue
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    records.append(json.loads(stripped))
                except json.JSONDecodeError:
                    continue
    except OSError as exc:
        logger.error("Unable to tail %s: %s", path, exc)
        return [], total_lines

    return records, total_lines
