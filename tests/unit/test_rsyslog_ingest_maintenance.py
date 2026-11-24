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


@pytest.fixture(name="directory")
def directory_fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point the maintenance service to a temporary ingest directory on a large volume."""
    monkeypatch.setattr(maintenance, "DIRECTORY", tmp_path)
    monkeypatch.setattr(maintenance, "STATUS_FILE", tmp_path / "status" / "file_status.json")
    monkeypatch.setattr(maintenance, "volume_size", lambda: 10**9)
    monkeypatch.setattr(maintenance.shutil, "chown", lambda *_: None)
    return tmp_path


def _write(directory: Path, hour: int, content: str) -> Path:
    path = directory / f"rsyslog-2026-11-24-{hour:02d}.log"
    path.write_text(content, encoding="utf-8")
    return path


def _write_status(offsets: dict[Path, int]) -> None:
    files = [{"path": str(p), "hash": "x", "offset": str(o)} for p, o in offsets.items()]
    maintenance.STATUS_FILE.parent.mkdir()
    maintenance.STATUS_FILE.write_text(json.dumps({"files": files}), encoding="utf-8")


def test_precreates_current_and_next_hour_files(directory: Path) -> None:
    """
    arrange: an empty ingest directory.
    act: run a maintenance pass.
    assert: empty files for the current and next hours exist, readable only by owner and group.
    """
    maintenance.run_once(NOW)

    for hour in (14, 15):
        path = directory / f"rsyslog-2026-11-24-{hour}.log"
        assert path.stat().st_size == 0
        assert path.stat().st_mode & 0o777 == 0o640


def test_precreate_keeps_existing_content(directory: Path) -> None:
    """
    arrange: a current hour file with content.
    act: run a maintenance pass.
    assert: the file content is unchanged.
    """
    path = _write(directory, 14, "line\n")

    maintenance.run_once(NOW)

    assert path.read_text(encoding="utf-8") == "line\n"


def test_deletes_only_finished_and_fully_read_files(directory: Path) -> None:
    """
    arrange: files from finished hours (fully read, partially read, unknown, empty), from an
        hour that ended within the grace period and from the current hour, all fully read.
    act: run a maintenance pass.
    assert: only the finished files that are fully read or empty are deleted.
    """
    read = _write(directory, 11, "a\nb\n")
    partially_read = _write(directory, 12, "a\nb\n")
    unknown = _write(directory, 10, "a\n")
    empty = _write(directory, 9, "")
    within_grace = _write(directory, 13, "a\n")
    current = _write(directory, 14, "a\n")
    _write_status({read: 4, partially_read: 2, within_grace: 2, current: 2})

    maintenance.run_once(NOW)

    assert not read.exists()
    assert not empty.exists()
    assert partially_read.exists()
    assert unknown.exists()
    assert within_grace.exists()
    assert current.exists()


@pytest.mark.parametrize("content", ["not json", '{"files": [{"path": "x"}]}'])
def test_invalid_status_file_deletes_nothing_unread(directory: Path, content: str) -> None:
    """
    arrange: a file from a finished hour and an invalid status file.
    act: run a maintenance pass.
    assert: the file is kept.
    """
    path = _write(directory, 11, "a\n")
    maintenance.STATUS_FILE.parent.mkdir()
    maintenance.STATUS_FILE.write_text(content, encoding="utf-8")

    maintenance.run_once(NOW)

    assert path.exists()


def test_usage_limit_deletes_oldest_finished_files_first(
    directory: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """
    arrange: an idle legacy ingest file and unread files from finished hours and the current
        hour, using more than the limit even without the finished files.
    act: run a maintenance pass.
    assert: the legacy and finished files are deleted, the current hour file is kept.
    """
    legacy = directory / "rsyslog.log"
    legacy.write_text("old\n", encoding="utf-8")
    idle = (NOW - datetime.timedelta(hours=2)).timestamp()
    os.utime(legacy, (idle, idle))
    finished = [_write(directory, hour, "a\n") for hour in (11, 12)]
    current = _write(directory, 14, "a\n")
    monkeypatch.setattr(maintenance, "volume_size", lambda: 1)

    maintenance.run_once(NOW)

    assert not legacy.exists()
    assert not any(path.exists() for path in finished)
    assert current.exists()


def test_usage_limit_stops_once_under_limit(
    directory: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """
    arrange: two unread 100-byte files from finished hours on a 200-byte volume.
    act: run a maintenance pass.
    assert: only the oldest file is deleted, even though the volume usage is not measured again.
    """
    oldest = _write(directory, 11, "a" * 100)
    newer = _write(directory, 12, "a" * 100)
    monkeypatch.setattr(maintenance, "volume_size", lambda: 200)

    maintenance.run_once(NOW)

    assert not oldest.exists()
    assert newer.exists()


def test_usage_limit_keeps_legacy_file_still_written(
    directory: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """
    arrange: a legacy ingest file written to within the last hour, over the usage limit.
    act: run a maintenance pass.
    assert: the legacy file is kept.
    """
    legacy = directory / "rsyslog.log"
    legacy.write_text("live\n", encoding="utf-8")
    recent = (NOW - datetime.timedelta(minutes=1)).timestamp()
    os.utime(legacy, (recent, recent))
    monkeypatch.setattr(maintenance, "volume_size", lambda: 1)

    maintenance.run_once(NOW)

    assert legacy.exists()
