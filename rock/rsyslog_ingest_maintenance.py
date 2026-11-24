#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Pre-create and clean up the hourly rsyslog ingest files read by wazuh-logcollector.

wazuh-logcollector reads newly discovered files from their end, so each hour's file is
created empty in advance. Files from finished hours are deleted once fully read, and the
oldest ones even if unread while the ingest files use more than MAX_USAGE of the volume.
"""

import datetime
import json
import logging
import shutil
import time
from pathlib import Path

DIRECTORY = Path("/var/log/collectors/rsyslog")
STATUS_FILE = Path("/var/ossec/queue/logcollector/file_status.json")
LEGACY_FILE_NAME = "rsyslog.log"  # written by previous charm revisions
GRACE = datetime.timedelta(minutes=5)
HOUR = datetime.timedelta(hours=1)
MAX_USAGE = 0.8

logger = logging.getLogger(__name__)


def path_for(hour: datetime.datetime) -> Path:
    """Get the ingest file for an hour, as named by the rsyslog dynaFile template."""
    return DIRECTORY / f"rsyslog-{hour:%Y-%m-%d-%H}.log"


def read_offsets() -> dict[str, int]:
    """Get the position up to which wazuh-logcollector has read each file."""
    try:
        files = json.loads(STATUS_FILE.read_text(encoding="utf-8"))["files"]
        return {entry["path"]: int(entry["offset"]) for entry in files}
    except (OSError, ValueError, KeyError, TypeError):
        return {}


def volume_size() -> int:
    """Get the size of the volume holding the ingest files."""
    return shutil.disk_usage(DIRECTORY).total


def run_once(now: datetime.datetime) -> None:
    """Pre-create the current and next hour's files and clean up finished ones."""
    hour = now.replace(minute=0, second=0, microsecond=0)
    for path in (path_for(hour), path_for(hour + HOUR)):
        try:
            path.touch(mode=0o640, exist_ok=False)
        except FileExistsError:
            continue
        shutil.chown(path, "syslog", "wazuh")

    offsets = read_offsets()
    # Names sort chronologically: files up to the last hour that ended before the grace period
    last_finished = path_for(now - GRACE - HOUR).name
    finished = [p for p in sorted(DIRECTORY.glob("rsyslog-*.log")) if p.name <= last_finished]
    for path in list(finished):
        size = path.stat().st_size
        if size == 0 or offsets.get(str(path), -1) >= size:
            path.unlink()
            finished.remove(path)
            logger.info("Deleted %s (%d bytes, fully read)", path, size)

    # Count the files rather than the volume usage: deleted files still open by rsyslog or
    # wazuh-logcollector only free their space once closed
    used = sum(p.stat().st_size for p in DIRECTORY.iterdir() if p.is_file())
    legacy = DIRECTORY / LEGACY_FILE_NAME
    if legacy.exists() and legacy.stat().st_mtime < (now - HOUR).timestamp():
        finished.insert(0, legacy)
    limit = MAX_USAGE * volume_size()
    while used > limit and finished:
        path = finished.pop(0)
        size = path.stat().st_size
        path.unlink()
        used -= size
        logger.warning(
            "Ingest files over %d%% of the volume: deleted %s (%d bytes, %d not read by Wazuh)",
            MAX_USAGE * 100,
            path,
            size,
            max(size - offsets.get(str(path), 0), 0),
        )


def main() -> None:
    """Run a maintenance pass every minute."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    while True:
        try:
            run_once(datetime.datetime.now())  # local time, as rsyslog
        except OSError:
            logger.exception("Maintenance pass failed")
        time.sleep(60)


if __name__ == "__main__":
    main()
