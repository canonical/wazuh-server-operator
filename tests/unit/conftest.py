# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Shared fixtures and helpers for wazuh-server-operator unit tests."""

import subprocess  # nosec
from pathlib import Path
from unittest.mock import MagicMock

import ops
import pytest
from ops.testing import Container, Context, Exec, Manager, State

import wazuh

# Minimal metadata for Scenario-backed tests that only need a "wazuh-server" container,
# without any of the charm's actual relations/config.
CHARM_META = {
    "name": "wazuh",
    "containers": {"wazuh-server": {"resource": "wazuh-server-image"}},
}


def _git_execs() -> set[Exec]:
    """Build Exec stubs for the git plumbing commands wazuh._needs_sync() relies on.

    Models a custom-config-repository that has already been cloned to
    /root/repository, pointing at tag "v5" at commit "abc123".

    Returns:
        A set of Exec stubs to register on the "wazuh-server" container.
    """
    return {
        Exec(
            ["git", "-C", wazuh.REPOSITORY_PATH, "config", "--get", "remote.origin.url"],
            stdout="git+ssh://git@github.com/fake_repo/url.git",
        ),
        Exec(
            ["git", "-C", wazuh.REPOSITORY_PATH, "describe", "--tags", "--exact-match"],
            stdout="v5",
        ),
        Exec(
            ["git", "-C", wazuh.REPOSITORY_PATH, "rev-parse", "HEAD"],
            stdout="abc123",
        ),
    }


@pytest.fixture(name="synced_wazuh_container")
def synced_wazuh_container_fixture(monkeypatch: pytest.MonkeyPatch):
    """A connected "wazuh-server" container primed for a pending config sync.

    The custom-config-repository is modeled as already cloned at commit "abc123",
    while "deadbeef" is recorded as the last commit applied to /var/ossec, so
    wazuh._needs_sync() reports that a sync is due.

    Args:
        monkeypatch: pytest's monkeypatch fixture.

    Yields:
        A tuple of (container, save_applied_commit_marker_mock).
    """
    save_applied_commit_marker_mock = MagicMock()
    monkeypatch.setattr(wazuh, "save_applied_commit_marker", save_applied_commit_marker_mock)

    ctx = Context(ops.CharmBase, meta=CHARM_META)
    state = State(containers={Container("wazuh-server", can_connect=True, execs=_git_execs())})
    with Manager(ctx, ctx.on.update_status(), state) as manager:
        container = manager.charm.unit.get_container("wazuh-server")
        container.push(
            wazuh.WAZUH_APPLIED_COMMIT_PATH,
            "deadbeef\n",
            encoding="utf-8",
            make_dirs=True,
        )
        # Seed a real file under the cloned repository so that sync_wazuh_config_files'
        # own container.exists()/isdir() checks on the repo source path reflect reality,
        # rather than needing to be faked.
        container.push(
            f"{wazuh.REPO_WAZUH_CONF_PATH}/etc/ossec.conf",
            "<ossec_config></ossec_config>",
            encoding="utf-8",
            make_dirs=True,
        )
        yield container, save_applied_commit_marker_mock


def track_exec(
    monkeypatch: pytest.MonkeyPatch, container: ops.Container, *names: str
) -> list[list[str]]:
    """Record every container.exec() invocation whose argv[0] is one of `names`.

    Tracked commands succeed with empty output and are appended, in call order, to
    the returned list. Anything else is passed through to the real (Scenario-backed)
    exec, so commands this test doesn't care about still behave normally.

    Args:
        monkeypatch: pytest's monkeypatch fixture.
        container: the container whose exec() calls should be tracked.
        names: the argv[0] values to intercept (for example "rsync", "chmod").

    Returns:
        The (initially empty) list that gets populated as tracked commands run.
    """
    mocked_proc = MagicMock()
    mocked_proc.wait_output.return_value = ("", "")
    real_exec = container.exec
    commands: list[list[str]] = []

    def side_effect(cmd, **kwargs):
        if cmd[0] in names:
            commands.append(cmd)
            return mocked_proc
        return real_exec(cmd, **kwargs)

    monkeypatch.setattr(container, "exec", MagicMock(side_effect=side_effect))
    return commands


def fake_missing_paths(
    monkeypatch: pytest.MonkeyPatch, container: ops.Container, *missing: str
) -> None:
    """Make container.exists() report False for the given paths, True for anything else.

    Args:
        monkeypatch: pytest's monkeypatch fixture.
        container: the container whose exists() should be faked.
        missing: the paths that should be reported as absent.
    """
    monkeypatch.setattr(container, "exists", lambda path: path not in missing)


def real_rsync(monkeypatch: pytest.MonkeyPatch, container: ops.Container) -> None:
    """Let container.exec() run the real rsync binary against this container's backing files.

    Scenario-backed containers are rooted at a real, on-disk directory
    (container._pebble._root); this translates the container paths rsync is
    invoked with into that directory and runs the actual rsync binary, so tests
    can seed real files and assert on their real contents/existence afterwards,
    rather than only inspecting the rsync command-line arguments.

    The `--chown root:wazuh` rsync is invoked with is stripped before running, since
    the "wazuh" user/group isn't expected to exist on the machine running the tests.
    chmod/chown/find invocations (the permission fixups that follow the rsync calls
    in sync_wazuh_config_files) are left as harmless no-ops, same as track_exec.

    Args:
        monkeypatch: pytest's monkeypatch fixture.
        container: the container whose exec() should run real rsync commands.
    """
    root = Path(str(container._pebble._root))  # type: ignore[attr-defined] # pylint: disable=protected-access
    real_exec = container.exec
    mocked_proc = MagicMock()
    mocked_proc.wait_output.return_value = ("", "")

    def to_host_path(arg: str) -> str:
        if not arg.startswith("/"):
            return arg
        trailing_slash = arg.endswith("/") and arg != "/"
        host_path = str(root / arg.lstrip("/"))
        return f"{host_path}/" if trailing_slash else host_path

    def side_effect(cmd, **kwargs):
        if cmd[0] in ("chmod", "chown", "find"):
            return mocked_proc
        if cmd[0] != "rsync":
            return real_exec(cmd, **kwargs)

        rsync_args = []
        skip_next = False
        for arg in cmd:
            if skip_next:
                skip_next = False
                continue
            if arg == "--chown":
                skip_next = True
                continue
            rsync_args.append(to_host_path(arg))

        completed = subprocess.run(  # nosec
            rsync_args, capture_output=True, text=True, check=False
        )
        if completed.returncode != 0:
            raise ops.pebble.ExecError(
                rsync_args, completed.returncode, completed.stdout, completed.stderr
            )
        proc = MagicMock()
        proc.wait_output.return_value = (completed.stdout, completed.stderr)
        return proc

    monkeypatch.setattr(container, "exec", MagicMock(side_effect=side_effect))
