#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Maintain the hourly rsyslog ingest files read by wazuh-logcollector.

rsyslog writes incoming logs to one file per hour (rsyslog-YYYY-MM-DD-HH.log) and
wazuh-logcollector reads them through a wildcard <localfile>. This service:

- Pre-creates the current and next hour's files, empty. wazuh-logcollector starts reading a
  newly discovered file from its end, so a file must be discovered while still empty for
  none of its lines to be skipped.
- Deletes files from finished hours once wazuh-logcollector has read all of them, according
  to the read positions it saves in file_status.json.
- Deletes the oldest finished files, even if unread, when the volume usage exceeds a limit,
  so that the volume never fills up.
"""

import argparse
import datetime
import grp
import json
import logging
import os
import pwd
import re
import time
from collections.abc import Callable
from pathlib import Path

logger = logging.getLogger("rsyslog-ingest-maintenance")

FILE_PATTERN = re.compile(r"^rsyslog-(\d{4})-(\d{2})-(\d{2})-(\d{2})\.log$")
# Ingest file written by previous charm revisions; only removed under disk pressure.
LEGACY_FILE_NAME = "rsyslog.log"
ONE_HOUR = datetime.timedelta(hours=1)


def file_name(hour: datetime.datetime) -> str:
    """Get the name of the ingest file for a given hour.

    Args:
        hour: the hour.

    Returns:
        the file name, matching the rsyslog dynaFile template.
    """
    return f"rsyslog-{hour:%Y-%m-%d-%H}.log"


def file_hour(name: str) -> datetime.datetime | None:
    """Get the hour an ingest file belongs to.

    Args:
        name: the file name.

    Returns:
        the hour, or None if the name is not an hourly ingest file.
    """
    match = FILE_PATTERN.match(name)
    if not match:
        return None
    year, month, day, hour = (int(group) for group in match.groups())
    return datetime.datetime(year, month, day, hour)  # local time, as rsyslog


def precreate(directory: Path, hours: list[datetime.datetime], uid: int, gid: int) -> None:
    """Create empty ingest files for the given hours if they do not exist yet.

    Args:
        directory: the ingest directory.
        hours: the hours to create files for.
        uid: the owner of the created files, -1 to leave it unchanged.
        gid: the group of the created files, -1 to leave it unchanged.
    """
    for hour in hours:
        path = directory / file_name(hour)
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o640)
        except FileExistsError:
            continue
        try:
            os.fchown(fd, uid, gid)
            os.fchmod(fd, 0o640)
        finally:
            os.close(fd)
        logger.info("Created %s", path)


def read_offsets(status_file: Path) -> dict[str, int]:
    """Read the positions up to which wazuh-logcollector has read each file.

    Args:
        status_file: the wazuh-logcollector file_status.json.

    Returns:
        the read offset for each file path. Empty if the status file is missing or invalid.
    """
    try:
        status = json.loads(status_file.read_text(encoding="utf-8"))
        return {entry["path"]: int(entry["offset"]) for entry in status.get("files", [])}
    except FileNotFoundError:
        return {}
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        logger.warning("Unable to read %s: %s", status_file, exc)
        return {}


def finished_files(
    directory: Path, now: datetime.datetime, grace: datetime.timedelta
) -> list[Path]:
    """List the ingest files from hours that ended more than the grace period ago.

    Args:
        directory: the ingest directory.
        now: the current local time.
        grace: how long to wait after the end of an hour before considering it finished.

    Returns:
        the finished files, oldest first.
    """
    finished = []
    for path in directory.iterdir():
        hour = file_hour(path.name)
        if hour is not None and hour + ONE_HOUR + grace <= now:
            finished.append((hour, path))
    return [path for _, path in sorted(finished)]


def delete_read_files(files: list[Path], offsets: dict[str, int]) -> None:
    """Delete files that are empty or have been fully read by wazuh-logcollector.

    Args:
        files: the candidate files, all from finished hours.
        offsets: the read offset for each file path.
    """
    for path in files:
        size = path.stat().st_size
        if size == 0 or offsets.get(str(path), -1) >= size:
            path.unlink()
            logger.info("Deleted %s (%d bytes, fully read)", path, size)


def disk_usage_percent(directory: Path) -> float:
    """Get the usage of the filesystem holding a directory.

    Args:
        directory: the directory.

    Returns:
        the used space, as a percentage of the space available to unprivileged users.
    """
    stats = os.statvfs(directory)
    used = stats.f_blocks - stats.f_bfree
    total = used + stats.f_bavail
    return 100.0 * used / total if total else 0.0


def enforce_usage_limit(
    directory: Path,
    files: list[Path],
    offsets: dict[str, int],
    max_usage_percent: float,
    usage: Callable[[Path], float] = disk_usage_percent,
) -> None:
    """Delete the oldest finished files, even if unread, while the volume is over the limit.

    Args:
        directory: the ingest directory.
        files: the finished files, oldest first.
        offsets: the read offset for each file path.
        max_usage_percent: the maximum usage of the volume.
        usage: function returning the volume usage, as a percentage.
    """
    candidates = [path for path in files if path.exists()]
    legacy = directory / LEGACY_FILE_NAME
    if legacy.exists():
        candidates.insert(0, legacy)
    while candidates and usage(directory) > max_usage_percent:
        path = candidates.pop(0)
        size = path.stat().st_size
        unread = size - max(offsets.get(str(path), 0), 0)
        path.unlink()
        logger.warning(
            "Volume usage over %s%%: deleted %s (%d bytes, %d bytes not read by Wazuh)",
            max_usage_percent,
            path,
            size,
            max(unread, 0),
        )


def run_once(  # pylint: disable=too-many-arguments
    directory: Path,
    status_file: Path,
    now: datetime.datetime,
    *,
    uid: int,
    gid: int,
    grace: datetime.timedelta,
    max_usage_percent: float,
    usage: Callable[[Path], float] = disk_usage_percent,
) -> None:
    """Run one maintenance pass.

    Args:
        directory: the ingest directory.
        status_file: the wazuh-logcollector file_status.json.
        now: the current local time.
        uid: the owner of the created files, -1 to leave it unchanged.
        gid: the group of the created files, -1 to leave it unchanged.
        grace: how long to wait after the end of an hour before cleaning up its file.
        max_usage_percent: the maximum usage of the volume.
        usage: function returning the volume usage, as a percentage.
    """
    current_hour = now.replace(minute=0, second=0, microsecond=0)
    precreate(directory, [current_hour, current_hour + ONE_HOUR], uid, gid)
    offsets = read_offsets(status_file)
    files = finished_files(directory, now, grace)
    delete_read_files(files, offsets)
    enforce_usage_limit(directory, files, offsets, max_usage_percent, usage)


def main() -> None:
    """Run the maintenance loop."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--directory", type=Path, default=Path("/var/log/collectors/rsyslog"))
    parser.add_argument(
        "--status-file",
        type=Path,
        default=Path("/var/ossec/queue/logcollector/file_status.json"),
    )
    parser.add_argument("--owner", default="syslog")
    parser.add_argument("--group", default="wazuh")
    parser.add_argument("--interval", type=int, default=60, help="seconds between passes")
    parser.add_argument("--grace", type=int, default=300, help="seconds after an hour ends")
    parser.add_argument("--max-usage-percent", type=float, default=80.0)
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    uid = pwd.getpwnam(args.owner).pw_uid
    gid = grp.getgrnam(args.group).gr_gid
    while True:
        try:
            run_once(
                args.directory,
                args.status_file,
                datetime.datetime.now(),  # local time, as rsyslog
                uid=uid,
                gid=gid,
                grace=datetime.timedelta(seconds=args.grace),
                max_usage_percent=args.max_usage_percent,
            )
        except OSError:
            logger.exception("Maintenance pass failed")
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
