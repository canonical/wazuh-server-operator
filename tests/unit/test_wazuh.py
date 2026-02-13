# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

# pylint: disable=too-many-locals

"""Wazuh unit tests."""

import secrets
import unittest
import unittest.mock
from pathlib import Path
from unittest.mock import ANY, MagicMock, patch

import ops
import pytest
import yaml
from lxml import etree  # nosec
from ops.testing import Harness
from pydantic import AnyUrl

import wazuh

CHARM_METADATA = """
name: wazuh
containers:
  wazuh-server:
"""


@pytest.mark.parametrize("enable_vulnerability_detection", [True, False])
@pytest.mark.parametrize("unit_name", ["wazuh-server/0", "wazuh-server/1"])
def test_update_configuration(
    monkeypatch: pytest.MonkeyPatch, enable_vulnerability_detection: bool, unit_name: str
) -> None:
    """
    arrange: copy the Wazuh configuration files into a container and mock the service restart.
    act: save the master node configuration with a set of indexer IPs for multiple units.
    assert: the IPs have been persisted in the corresponding files.
    """
    indexer_endpoints = ["10.0.0.2:9200", "10.0.0.3:9200"]
    master_ip = "10.1.0.2"
    harness = Harness(ops.CharmBase, meta=CHARM_METADATA)
    harness.begin_with_initial_hooks()
    container = harness.charm.unit.get_container("wazuh-server")
    exec_process = unittest.mock.MagicMock()
    exec_process.wait_output = unittest.mock.MagicMock(return_value=(0, 0))
    exec_mock = unittest.mock.MagicMock(return_value=exec_process)
    monkeypatch.setattr(container, "exec", exec_mock)
    filebeat_content = Path("tests/unit/resources/filebeat.yml").read_text(encoding="utf-8")
    container.push(wazuh.FILEBEAT_CONFIG_FILE, filebeat_content, make_dirs=True)
    ossec_content = Path("tests/unit/resources/ossec.conf").read_text(encoding="utf-8")
    container.push(wazuh.OSSEC_CONF_PATH, ossec_content, make_dirs=True)

    key = secrets.token_hex(32)
    wazuh.sync_filebeat_config(container, indexer_endpoints)
    wazuh.sync_ossec_conf(
        container,
        indexer_endpoints,
        master_ip,
        unit_name,
        key,
        enable_vulnerability_detection=enable_vulnerability_detection,
    )

    filebeat_config = container.pull(wazuh.FILEBEAT_CONFIG_FILE, encoding="utf-8").read()
    filebeat_config_yaml = yaml.safe_load(filebeat_config)
    assert "output.elasticsearch" in filebeat_config_yaml
    assert "hosts" in filebeat_config_yaml["output.elasticsearch"]
    assert filebeat_config_yaml["output.elasticsearch"]["hosts"] == indexer_endpoints
    ossec_config = container.pull(wazuh.OSSEC_CONF_PATH, encoding="utf-8").read()
    tree = etree.fromstring(f"<root>{ossec_config}</root>")  # nosec
    hosts = tree.xpath("/root/ossec_config/indexer/hosts//host")
    assert len(hosts) == len(indexer_endpoints)
    for idx, host in enumerate(hosts):
        assert host.text == f"https://{indexer_endpoints[idx]}"
    assert (
        unit_name.replace("/", "-") == tree.xpath("/root/ossec_config/cluster/node_name")[0].text
    )
    node_type = tree.xpath("/root/ossec_config/cluster/node_type")[0].text
    assert node_type == "master" if unit_name == "wazuh-server/0" else "worker"
    address = tree.xpath("/root/ossec_config/cluster/nodes/node")[0]
    assert address.text == master_ip
    if enable_vulnerability_detection:
        assert not tree.xpath("/root/ossec_config/vulnerability-detection")
    else:
        assert tree.xpath("/root/ossec_config/vulnerability-detection/enabled")[0].text == "no"


def test_install_certificates() -> None:
    """
    arrange: do nothing.
    act: save some content as certificates.
    assert: the files have been saved with the provided content.
    """
    harness = Harness(ops.CharmBase, meta=CHARM_METADATA)
    harness.begin_with_initial_hooks()
    container = harness.charm.unit.get_container("wazuh-server")
    wazuh.sync_certificates(
        container,
        path=wazuh.FILEBEAT_CERTIFICATES_PATH,
        private_key="private_key",
        public_key="public_key",
        root_ca="root_ca",
        user="root",
        group="root",
    )

    assert (
        container.pull(
            wazuh.FILEBEAT_CERTIFICATES_PATH / "certificate.key", encoding="utf-8"
        ).read()
        == "private_key"
    )
    assert (
        container.pull(
            wazuh.FILEBEAT_CERTIFICATES_PATH / "certificate.pem", encoding="utf-8"
        ).read()
        == "public_key"
    )
    assert (
        container.pull(wazuh.FILEBEAT_CERTIFICATES_PATH / "root-ca.pem", encoding="utf-8").read()
        == "root_ca"
    )


def test_configure_agent_password() -> None:
    """
    arrange: do nothing.
    act: save some content as agent password.
    assert: the files have been saved with the provided content.
    """
    harness = Harness(ops.CharmBase, meta=CHARM_METADATA)
    harness.begin_with_initial_hooks()
    container = harness.charm.unit.get_container("wazuh-server")
    password = secrets.token_hex()
    wazuh.sync_agent_password(container, password=password)

    assert password == container.pull(wazuh.AGENT_PASSWORD_PATH, encoding="utf-8").read()


def test_sync_config_repo_when_branch_specified() -> None:
    """
    arrange: do nothing.
    act: configure git specifying a branch name.
    assert: the files have been saved with the appropriate content.
    """
    harness = Harness(ops.CharmBase, meta=CHARM_METADATA)
    harness.handle_exec(
        "wazuh-server",
        ["git", "-C", wazuh.REPOSITORY_PATH, "config", "--get", "remote.origin.url"],
        result="",
    )
    harness.handle_exec(
        "wazuh-server",
        ["git", "-C", wazuh.REPOSITORY_PATH, "rev-parse", "--abbrev-ref", "HEAD"],
        result="",
    )
    harness.handle_exec(
        "wazuh-server",
        ["git", "-C", wazuh.REPOSITORY_PATH, "describe", "--tags", "--exact-match"],
        result="",
    )
    harness.handle_exec(
        "wazuh-server", ["ssh-keyscan", "-t", "rsa", "git.server"], result="know_host"
    )
    harness.handle_exec("wazuh-server", ["rm", "-Rf", wazuh.REPOSITORY_PATH], result="")
    custom_config_repository = AnyUrl("git+ssh://user1@git.server/repo_name@main")
    harness.handle_exec(
        "wazuh-server",
        [
            "git",
            "clone",
            "--depth",
            "1",
            "--branch",
            "main",
            "git+ssh://user1@git.server/repo_name",
            "/root/repository",
        ],
        result="",
    )
    harness.begin_with_initial_hooks()
    container = harness.charm.unit.get_container("wazuh-server")
    custom_config_ssh_key = "somekey"
    wazuh.sync_config_repo(container, custom_config_repository, custom_config_ssh_key)
    assert container.pull(wazuh.KNOWN_HOSTS_PATH, encoding="utf-8").read() == "know_host"
    assert container.pull(wazuh.RSA_PATH, encoding="utf-8").read() == "somekey\n"


def test_sync_config_repo_when_no_branch_specified(*_) -> None:
    """
    arrange: do nothing.
    act: configure git without specifying a branch name.
    assert: the files have been saved with the appropriate content.
    """
    harness = Harness(ops.CharmBase, meta=CHARM_METADATA)
    harness.handle_exec(
        "wazuh-server",
        ["git", "-C", wazuh.REPOSITORY_PATH, "config", "--get", "remote.origin.url"],
        result="",
    )
    harness.handle_exec(
        "wazuh-server",
        ["git", "-C", wazuh.REPOSITORY_PATH, "rev-parse", "--abbrev-ref", "HEAD"],
        result="",
    )
    harness.handle_exec(
        "wazuh-server",
        ["git", "-C", wazuh.REPOSITORY_PATH, "describe", "--tags", "--exact-match"],
        result="",
    )
    harness.handle_exec(
        "wazuh-server", ["ssh-keyscan", "-t", "rsa", "git.server"], result="know_host"
    )
    harness.handle_exec("wazuh-server", ["rm", "-Rf", wazuh.REPOSITORY_PATH], result="")
    custom_config_repository = AnyUrl("git+ssh://user1@git.server/repo_name")
    harness.handle_exec(
        "wazuh-server",
        [
            "git",
            "clone",
            "--depth",
            "1",
            "git+ssh://user1@git.server/repo_name",
            "/root/repository",
        ],
        result="",
    )
    harness.begin_with_initial_hooks()
    container = harness.charm.unit.get_container("wazuh-server")
    custom_config_ssh_key = "somekey"
    wazuh.sync_config_repo(container, custom_config_repository, custom_config_ssh_key)
    assert container.pull(wazuh.KNOWN_HOSTS_PATH, encoding="utf-8").read() == "know_host"
    assert container.pull(wazuh.RSA_PATH, encoding="utf-8").read() == "somekey\n"


def test_sync_config_repo_when_no_key_no_repository_specified() -> None:
    """
    arrange: do nothing.
    act: configure git without specifying a repository.
    assert: the files have been saved with the appropriate content.
    """
    harness = Harness(ops.CharmBase, meta=CHARM_METADATA)
    harness.handle_exec(
        "wazuh-server",
        ["git", "-C", wazuh.REPOSITORY_PATH, "config", "--get", "remote.origin.url"],
        result="",
    )
    harness.handle_exec(
        "wazuh-server",
        ["git", "-C", wazuh.REPOSITORY_PATH, "rev-parse", "--abbrev-ref", "HEAD"],
        result="",
    )
    harness.handle_exec("wazuh-server", ["rm", "-Rf", wazuh.REPOSITORY_PATH], result="")
    harness.begin_with_initial_hooks()
    container = harness.charm.unit.get_container("wazuh-server")
    wazuh.sync_config_repo(container, None, None)
    assert not container.exists(wazuh.KNOWN_HOSTS_PATH)
    assert not container.exists(wazuh.RSA_PATH)


@unittest.mock.patch.object(wazuh, "pull_config_repo")
def test_sync_config_repo_when_branch_up_to_date(
    wazuh_pull_config_repo_mock: unittest.mock.Mock,
) -> None:
    """
    arrange: do nothing.
    act: configure git with a repository and branch.
    assert: the repo branch is fetched even if already present
        (no guarantee local copy has the latest commits).
    """
    harness = Harness(ops.CharmBase, meta=CHARM_METADATA)
    harness.handle_exec(
        "wazuh-server",
        ["git", "-C", wazuh.REPOSITORY_PATH, "config", "--get", "remote.origin.url"],
        result="git+ssh://git@github.com/fake_repo/url.git",
    )
    harness.handle_exec(
        "wazuh-server",
        ["git", "-C", wazuh.REPOSITORY_PATH, "rev-parse", "--abbrev-ref", "HEAD"],
        result="main",
    )
    harness.handle_exec(
        "wazuh-server",
        ["git", "-C", wazuh.REPOSITORY_PATH, "describe", "--tags", "--exact-match"],
        result="",
    )
    harness.begin_with_initial_hooks()
    container = harness.charm.unit.get_container("wazuh-server")
    wazuh.sync_config_repo(
        container,
        repository=AnyUrl("git+ssh://git@github.com/fake_repo/url.git@main"),
        repo_ssh_key=None,
    )
    assert wazuh_pull_config_repo_mock.called


@unittest.mock.patch.object(wazuh, "pull_config_repo")
def test_sync_config_repo_when_tag_and_head_up_to_date(
    wazuh_pull_config_repo_mock: unittest.mock.Mock,
) -> None:
    """
    arrange: repo url/tag are matching and so are HEAD and stored head.
    act: call sync_config_repo.
    assert: the repo is not fetched.
    """
    harness = Harness(ops.CharmBase, meta=CHARM_METADATA)
    harness.handle_exec(
        "wazuh-server",
        ["git", "-C", wazuh.REPOSITORY_PATH, "config", "--get", "remote.origin.url"],
        result="git+ssh://git@github.com/fake_repo/url.git",
    )
    # if repo was checked out with --depth 1 --branch <tag>
    harness.handle_exec(
        "wazuh-server",
        ["git", "-C", wazuh.REPOSITORY_PATH, "rev-parse", "--abbrev-ref", "HEAD"],
        result="HEAD",
    )
    harness.handle_exec(
        "wazuh-server",
        ["git", "-C", wazuh.REPOSITORY_PATH, "describe", "--tags", "--exact-match"],
        result="v5",
    )
    # current head
    harness.handle_exec(
        "wazuh-server", ["git", "-C", wazuh.REPOSITORY_PATH, "rev-parse", "HEAD"], result="abc123"
    )
    harness.begin_with_initial_hooks()
    container = harness.charm.unit.get_container("wazuh-server")
    # write marker == HEAD
    container.push(
        wazuh.WAZUH_APPLIED_COMMIT_PATH,
        "abc123\n",
        encoding="utf-8",
        make_dirs=True,
    )
    updated: bool = wazuh.sync_config_repo(
        container,
        repository=AnyUrl("git+ssh://git@github.com/fake_repo/url.git@v5"),
        repo_ssh_key=None,
    )
    assert updated is False
    wazuh_pull_config_repo_mock.assert_not_called()


@unittest.mock.patch.object(wazuh, "save_applied_commit_marker")
def test_sync_wazuh_config_files_when_head_mismatch_triggers_save_applied_commit_marker(
    wazuh_save_applied_commit_marker: unittest.mock.Mock,
) -> None:
    """
    arrange: when wazuh tries to sync and heads are not matching, a resync is called.
    act: wazuh config files resync.
    assert: save_applied_commit_marker is called.
    """
    harness = Harness(ops.CharmBase, meta=CHARM_METADATA)
    harness.handle_exec(
        "wazuh-server",
        ["git", "-C", wazuh.REPOSITORY_PATH, "config", "--get", "remote.origin.url"],
        result="git+ssh://git@github.com/fake_repo/url.git",
    )
    harness.handle_exec(
        "wazuh-server",
        ["git", "-C", wazuh.REPOSITORY_PATH, "describe", "--tags", "--exact-match"],
        result="v5",
    )
    harness.handle_exec(
        "wazuh-server",
        ["git", "-C", wazuh.REPOSITORY_PATH, "rev-parse", "HEAD"],
        result="abc123",
    )

    harness.begin_with_initial_hooks()
    container = harness.charm.unit.get_container("wazuh-server")

    # stored head differs
    container.push(
        wazuh.WAZUH_APPLIED_COMMIT_PATH,
        "deadbeef\n",
        encoding="utf-8",
        make_dirs=True,
    )

    mocked_proc = MagicMock()
    mocked_proc.wait_output.return_value = ("", "")

    real_exec = container.exec
    with (
        patch.object(container, "exists", return_value=True),
        patch.object(
            container,
            "exec",
            side_effect=lambda cmd, *a, **kv: (
                mocked_proc
                if cmd[0] in ["rsync", "find", "chmod", "chown"]
                else real_exec(cmd, *a, **kv)
            ),
        ),
    ):
        changed = wazuh.sync_wazuh_config_files(container)

    assert changed is True
    wazuh_save_applied_commit_marker.assert_called_once_with(ANY, wazuh.WAZUH_APPLIED_COMMIT_PATH)


@unittest.mock.patch.object(wazuh, "save_applied_commit_marker")
def test_sync_rsyslog_config_files_when_head_mismatch_triggers_save_applied_commit_marker(
    wazuh_save_applied_commit_marker: unittest.mock.Mock,
) -> None:
    """
    arrange: when rsyslog tries to sync and heads are not matching, a resync is called.
    act: rsyslog config files resync.
    assert: save_applied_commit_marker is called.
    """
    harness = Harness(ops.CharmBase, meta=CHARM_METADATA)
    harness.handle_exec(
        "wazuh-server",
        ["git", "-C", wazuh.REPOSITORY_PATH, "config", "--get", "remote.origin.url"],
        result="git+ssh://git@github.com/fake_repo/url.git",
    )
    harness.handle_exec(
        "wazuh-server",
        ["git", "-C", wazuh.REPOSITORY_PATH, "describe", "--tags", "--exact-match"],
        result="v5",
    )
    harness.handle_exec(
        "wazuh-server",
        ["git", "-C", wazuh.REPOSITORY_PATH, "rev-parse", "HEAD"],
        result="abc123",
    )

    harness.begin_with_initial_hooks()
    container = harness.charm.unit.get_container("wazuh-server")

    # stored head differs
    container.push(
        wazuh.RSYSLOG_APPLIED_COMMIT_PATH,
        "deadbeef\n",
        encoding="utf-8",
        make_dirs=True,
    )

    changed = wazuh.sync_rsyslog_config_files(container)

    assert changed is True
    wazuh_save_applied_commit_marker.assert_called_once_with(
        ANY, wazuh.RSYSLOG_APPLIED_COMMIT_PATH
    )


@unittest.mock.patch.object(wazuh, "save_applied_commit_marker")
def test_sync_wazuh_config_files_when_head_match_not_trigger_save_applied_commit_marker(
    wazuh_save_applied_commit_marker: unittest.mock.Mock,
) -> None:
    """
    arrange: when wazuh tries to sync but heads are matching, there is no need on re-sync.
    act: wazuh config files do not resync.
    assert: save_applied_commit_marker is not called.
    """
    harness = Harness(ops.CharmBase, meta=CHARM_METADATA)
    harness.handle_exec(
        "wazuh-server",
        ["git", "-C", wazuh.REPOSITORY_PATH, "config", "--get", "remote.origin.url"],
        result="git+ssh://git@github.com/fake_repo/url.git",
    )
    harness.handle_exec(
        "wazuh-server",
        ["git", "-C", wazuh.REPOSITORY_PATH, "describe", "--tags", "--exact-match"],
        result="v5",
    )
    harness.handle_exec(
        "wazuh-server",
        ["git", "-C", wazuh.REPOSITORY_PATH, "rev-parse", "HEAD"],
        result="abc123",
    )

    harness.begin_with_initial_hooks()
    harness.set_can_connect("wazuh-server", True)
    container = harness.charm.unit.get_container("wazuh-server")

    # stored head differs
    container.push(
        wazuh.WAZUH_APPLIED_COMMIT_PATH,
        "abc123\n",
        encoding="utf-8",
        make_dirs=True,
    )

    changed = wazuh.sync_wazuh_config_files(container)

    assert changed is False
    wazuh_save_applied_commit_marker.assert_not_called()


@unittest.mock.patch.object(wazuh, "save_applied_commit_marker")
def test_sync_rsyslog_config_files_when_head_match_not_trigger_save_applied_commit_marker(
    wazuh_save_applied_commit_marker: unittest.mock.Mock,
) -> None:
    """
    arrange: when rsyslog tries to sync but heads are matching, there is no need on re-sync.
    act: rsyslog config files do not resync.
    assert: save_applied_commit_marker is not called.
    """
    harness = Harness(ops.CharmBase, meta=CHARM_METADATA)
    harness.handle_exec(
        "wazuh-server",
        ["git", "-C", wazuh.REPOSITORY_PATH, "config", "--get", "remote.origin.url"],
        result="git+ssh://git@github.com/fake_repo/url.git",
    )
    harness.handle_exec(
        "wazuh-server",
        ["git", "-C", wazuh.REPOSITORY_PATH, "describe", "--tags", "--exact-match"],
        result="v5",
    )
    harness.handle_exec(
        "wazuh-server",
        ["git", "-C", wazuh.REPOSITORY_PATH, "rev-parse", "HEAD"],
        result="abc123",
    )

    harness.begin_with_initial_hooks()
    container = harness.charm.unit.get_container("wazuh-server")

    container.push(
        wazuh.RSYSLOG_APPLIED_COMMIT_PATH,
        "abc123\n",
        encoding="utf-8",
        make_dirs=True,
    )

    changed = wazuh.sync_rsyslog_config_files(container)

    assert changed is False
    wazuh_save_applied_commit_marker.assert_not_called()


def test_get_current_repo_commit() -> None:
    """
    arrange: get current repo returns the actual repo head.
    act: get the current repo head.
    assert: the current repo head matches the actual repo head.
    """
    harness = Harness(ops.CharmBase, meta=CHARM_METADATA)

    harness.handle_exec(
        "wazuh-server",
        ["git", "-C", wazuh.REPOSITORY_PATH, "rev-parse", "HEAD"],
        result="abc123",
    )

    harness.begin_with_initial_hooks()
    harness.set_can_connect("wazuh-server", True)
    container = harness.charm.unit.get_container("wazuh-server")

    container.make_dir(wazuh.REPOSITORY_PATH, make_parents=True)

    commit = wazuh.get_current_repo_commit(container)

    assert commit == "abc123"


def test_save_applied_commit_marker() -> None:
    """
    arrange: save applied commit marker.
    act: marker is placed at the specified path.
    assert: saved commit equals expected commit.
    """
    harness = Harness(ops.CharmBase, meta=CHARM_METADATA)

    harness.handle_exec(
        "wazuh-server",
        ["git", "-C", wazuh.REPOSITORY_PATH, "rev-parse", "HEAD"],
        result="abc123",
    )

    harness.begin_with_initial_hooks()
    harness.set_can_connect("wazuh-server", True)
    container = harness.charm.unit.get_container("wazuh-server")

    container.make_dir(wazuh.REPOSITORY_PATH, make_parents=True)

    wazuh.save_applied_commit_marker(container, wazuh.WAZUH_APPLIED_COMMIT_PATH)

    commit_saved = container.pull(wazuh.WAZUH_APPLIED_COMMIT_PATH, encoding="utf-8").read().strip()

    assert commit_saved == "abc123"


def test_get_version() -> None:
    """
    arrange: mock the system call to fetch the version.
    act: fetch the version.
    assert: the version is correctly parsed from the output.
    """
    harness = Harness(ops.CharmBase, meta=CHARM_METADATA)
    harness.begin_with_initial_hooks()
    harness.handle_exec(
        "wazuh-server",
        ["/var/ossec/bin/wazuh-control", "info"],
        result='WAZUH_VERSION="v4.11.0"\nWAZUH_REVISION="40921"\nWAZUH_TYPE="server"\n',
    )
    container = harness.charm.unit.get_container("wazuh-server")
    version = wazuh.get_version(container)
    assert version == "v4.11.0"
