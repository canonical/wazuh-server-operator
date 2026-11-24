#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Pre-create and clean up the hourly rsyslog ingest files read by wazuh-logcollector.

rsyslog runs this program through omprog and sends it a line every 10 seconds (see
etc/rsyslog.d/wazuh.conf); each line triggers one maintenance pass.

wazuh-logcollector reads newly discovered files from their end, so each hour's file is
created empty in advance. Files from finished hours are deleted once fully read, and the
oldest ones even if unread while the ingest files use more than MAX_USAGE of the volume.
"""

import datetime
import json
import shutil
import sys
import syslog
import time
from pathlib import Path

DIRECTORY = Path("/var/log/collectors/rsyslog")
STATUS_FILE = Path("/var/ossec/queue/logcollector/file_status.json")
LEGACY_FILE_NAME = "rsyslog.log"  # written by previous charm revisions
GRACE = datetime.timedelta(minutes=5)
HOUR = datetime.timedelta(hours=1)
MAX_USAGE = 0.8
PASS_INTERVAL = 5  # seconds; rsyslog sends a burst of lines every 10 seconds


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
        path.touch(mode=0o640)

    offsets = read_offsets()
    # Names sort chronologically: files up to the last hour that ended before the grace period
    last_finished = path_for(now - GRACE - HOUR).name
    finished = [p for p in sorted(DIRECTORY.glob("rsyslog-*.log")) if p.name <= last_finished]
    for path in list(finished):
        size = path.stat().st_size
        if size == 0 or offsets.get(str(path), -1) >= size:
            path.unlink()
            finished.remove(path)
            syslog.syslog(syslog.LOG_INFO, f"Deleted {path} ({size} bytes, fully read)")

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
        unread = max(size - offsets.get(str(path), 0), 0)
        syslog.syslog(
            syslog.LOG_WARNING,
            f"Ingest files over {MAX_USAGE:.0%} of the volume: "
            f"deleted {path} ({size} bytes, {unread} not read by Wazuh)",
        )


def main() -> None:
    """Run a maintenance pass for each line received from rsyslog, at most every few seconds."""
    syslog.openlog("rsyslog-ingest-maintenance", syslog.LOG_PID)
    last_pass = -float(PASS_INTERVAL)
    for _ in sys.stdin:
        if time.monotonic() - last_pass < PASS_INTERVAL:
            continue
        last_pass = time.monotonic()
        try:
            run_once(datetime.datetime.now())  # local time, as rsyslog
        except OSError as exc:
            syslog.syslog(syslog.LOG_ERR, f"Maintenance pass failed: {exc}")


if __name__ == "__main__":
    main()
