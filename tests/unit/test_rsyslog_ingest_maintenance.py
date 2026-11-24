# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit tests for the rsyslog ingest files maintenance service shipped in the rock."""

import datetime
import importlib.util
import json
import os
from pathlib import Path

import pytest

_SPEC = importlib.util.spec_from_file_location(
    "rsyslog_ingest_maintenance", Path("rock/rsyslog_ingest_maintenance.py")
)
assert _SPEC is not None and _SPEC.loader is not None  # nosec
maintenance = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(maintenance)

NOW = datetime.datetime(2026, 11, 24, 14, 3)
GRACE = datetime.timedelta(minutes=5)


def _write(directory: Path, hour: int, content: str) -> Path:
    path = directory / f"rsyslog-2026-11-24-{hour:02d}.log"
    path.write_text(content, encoding="utf-8")
    return path


def _write_status(status_file: Path, offsets: dict[Path, int]) -> None:
    files = [{"path": str(p), "hash": "x", "offset": str(o)} for p, o in offsets.items()]
    status_file.write_text(json.dumps({"files": files}), encoding="utf-8")


def _run(directory: Path, status_file: Path, usage: float = 10.0) -> None:
    maintenance.run_once(
        directory,
        status_file,
        NOW,
        uid=-1,
        gid=-1,
        grace=GRACE,
        max_usage_percent=80.0,
        usage=lambda _: usage,
    )


def test_precreates_current_and_next_hour_files(tmp_path: Path) -> None:
    """
    arrange: an empty ingest directory.
    act: run a maintenance pass.
    assert: empty files for the current and next hours exist, readable only by owner and group.
    """
    _run(tmp_path, tmp_path / "missing.json")

    for hour in (14, 15):
        path = tmp_path / f"rsyslog-2026-11-24-{hour}.log"
        assert path.stat().st_size == 0
        assert path.stat().st_mode & 0o777 == 0o640


def test_precreate_keeps_existing_content(tmp_path: Path) -> None:
    """
    arrange: a current hour file with content.
    act: run a maintenance pass.
    assert: the file content is unchanged.
    """
    path = _write(tmp_path, 14, "line\n")

    _run(tmp_path, tmp_path / "missing.json")

    assert path.read_text(encoding="utf-8") == "line\n"


def test_deletes_only_finished_and_fully_read_files(tmp_path: Path) -> None:
    """
    arrange: files from finished hours (fully read, partially read, unknown, empty), from an
        hour that ended within the grace period and from the current hour, all fully read.
    act: run a maintenance pass.
    assert: only the finished files that are fully read or empty are deleted.
    """
    read = _write(tmp_path, 11, "a\nb\n")
    partially_read = _write(tmp_path, 12, "a\nb\n")
    unknown = _write(tmp_path, 10, "a\n")
    empty = _write(tmp_path, 9, "")
    within_grace = _write(tmp_path, 13, "a\n")
    current = _write(tmp_path, 14, "a\n")
    status_file = tmp_path / "file_status.json"
    _write_status(status_file, {read: 4, partially_read: 2, within_grace: 2, current: 2})

    _run(tmp_path, status_file)

    assert not read.exists()
    assert not empty.exists()
    assert partially_read.exists()
    assert unknown.exists()
    assert within_grace.exists()
    assert current.exists()


def test_usage_limit_deletes_oldest_finished_files_first(tmp_path: Path) -> None:
    """
    arrange: a legacy ingest file and unread files from finished hours and the current hour.
    act: run a maintenance pass while the volume stays over the usage limit.
    assert: the legacy and finished files are deleted, the current hour file is kept.
    """
    legacy = tmp_path / "rsyslog.log"
    legacy.write_text("old\n", encoding="utf-8")
    finished = [_write(tmp_path, hour, "a\n") for hour in (11, 12)]
    current = _write(tmp_path, 14, "a\n")

    _run(tmp_path, tmp_path / "missing.json", usage=95.0)

    assert not legacy.exists()
    assert not any(path.exists() for path in finished)
    assert current.exists()


def test_usage_limit_stops_once_under_limit(tmp_path: Path) -> None:
    """
    arrange: unread files from two finished hours.
    act: run a maintenance pass where deleting one file brings the volume under the limit.
    assert: only the oldest file is deleted.
    """
    oldest = _write(tmp_path, 11, "a\n")
    newer = _write(tmp_path, 12, "a\n")
    usages = iter([95.0, 50.0])

    maintenance.run_once(
        tmp_path,
        tmp_path / "missing.json",
        NOW,
        uid=-1,
        gid=-1,
        grace=GRACE,
        max_usage_percent=80.0,
        usage=lambda _: next(usages),
    )

    assert not oldest.exists()
    assert newer.exists()


@pytest.mark.parametrize("content", ["not json", '{"files": [{"path": "x"}]}'])
def test_invalid_status_file_deletes_nothing_unread(tmp_path: Path, content: str) -> None:
    """
    arrange: a file from a finished hour and an invalid status file.
    act: run a maintenance pass.
    assert: the file is kept.
    """
    path = _write(tmp_path, 11, "a\n")
    status_file = tmp_path / "file_status.json"
    status_file.write_text(content, encoding="utf-8")

    _run(tmp_path, status_file)

    assert path.exists()


def test_disk_usage_percent(tmp_path: Path) -> None:
    """
    arrange: a temporary directory.
    act: get the usage of its filesystem.
    assert: the usage matches statvfs.
    """
    stats = os.statvfs(tmp_path)
    used = stats.f_blocks - stats.f_bfree

    assert maintenance.disk_usage_percent(tmp_path) == pytest.approx(
        100.0 * used / (used + stats.f_bavail), abs=1.0
    )
