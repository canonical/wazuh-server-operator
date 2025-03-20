# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

# pylint: disable=too-many-locals

"""Wazuh unit tests."""

import secrets
import unittest
import unittest.mock
from pathlib import Path

import ops
import pytest
import yaml
from lxml import etree  # nosec
from ops.testing import Harness

import wazuh

CHARM_METADATA = """
name: wazuh
containers:
  wazuh-server:
"""


def test_update_configuration_when_on_master(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    arrange: copy the Wazuh configuration files into a container and mock the service restart.
    act: save the master node configuration with a set of indexer IPs for multiple units.
    assert: the IPs have been persisted in the corresponding files.
    """
    indexer_ips = ["10.0.0.2:9200", "10.0.0.3:9200"]
    master_ip = "10.1.0.2"
    harness = Harness(ops.CharmBase, meta=CHARM_METADATA)
    harness.begin_with_initial_hooks()
    container = harness.charm.unit.get_container("wazuh-server")
    exec_process = unittest.mock.MagicMock()
    exec_process.wait_output = unittest.mock.MagicMock(return_value=(0, 0))
    exec_mock = unittest.mock.MagicMock(return_value=exec_process)
    monkeypatch.setattr(container, "exec", exec_mock)
    filebeat_content = Path("tests/unit/resources/filebeat.yml").read_text(encoding="utf-8")
    container.push(wazuh.FILEBEAT_CONF_PATH, filebeat_content, make_dirs=True)
    ossec_content = Path("tests/unit/resources/ossec.conf").read_text(encoding="utf-8")
    container.push(wazuh.OSSEC_CONF_PATH, ossec_content, make_dirs=True)

    key = secrets.token_hex(32)
    wazuh.update_configuration(container, indexer_ips, master_ip, "wazuh-server/0", key)

    filebeat_config = container.pull(wazuh.FILEBEAT_CONF_PATH, encoding="utf-8").read()
    filebeat_config_yaml = yaml.safe_load(filebeat_config)
    assert "output.elasticsearch" in filebeat_config_yaml
    assert "hosts" in filebeat_config_yaml["output.elasticsearch"]
    assert filebeat_config_yaml["output.elasticsearch"]["hosts"] == indexer_ips
    ossec_config = container.pull(wazuh.OSSEC_CONF_PATH, encoding="utf-8").read()
    tree = etree.fromstring(f"<root>{ossec_config}</root>")  # nosec
    hosts = tree.xpath("/root/ossec_config/indexer/hosts//host")
    assert len(hosts) == len(indexer_ips)
    for idx, host in enumerate(hosts):
        assert host.text == f"https://{indexer_ips[idx]}"
    assert "wazuh-server-0" == tree.xpath("/root/ossec_config/cluster/node_name")[0].text
    assert "master" == tree.xpath("/root/ossec_config/cluster/node_type")[0].text
    address = tree.xpath("/root/ossec_config/cluster/nodes/node")[0]
    assert address.text == master_ip


def test_update_configuration_when_on_worker(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    arrange: copy the Wazuh configuration files into a container and mock the service restart.
    act: save the master node configuration with a set of indexer IPs for multiple units.
    assert: the IPs have been persisted in the corresponding files.
    """
    indexer_ips = ["10.0.0.2:9200", "10.0.0.3:9200"]
    master_ip = "10.1.0.2"
    harness = Harness(ops.CharmBase, meta=CHARM_METADATA)
    harness.begin_with_initial_hooks()
    container = harness.charm.unit.get_container("wazuh-server")
    exec_process = unittest.mock.MagicMock()
    exec_process.wait_output = unittest.mock.MagicMock(return_value=(0, 0))
    exec_mock = unittest.mock.MagicMock(return_value=exec_process)
    monkeypatch.setattr(container, "exec", exec_mock)
    filebeat_content = Path("tests/unit/resources/filebeat.yml").read_text(encoding="utf-8")
    container.push(wazuh.FILEBEAT_CONF_PATH, filebeat_content, make_dirs=True)
    ossec_content = Path("tests/unit/resources/ossec.conf").read_text(encoding="utf-8")
    container.push(wazuh.OSSEC_CONF_PATH, ossec_content, make_dirs=True)

    key = secrets.token_hex(32)
    wazuh.update_configuration(container, indexer_ips, master_ip, "wazuh-server/1", key)

    filebeat_config = container.pull(wazuh.FILEBEAT_CONF_PATH, encoding="utf-8").read()
    filebeat_config_yaml = yaml.safe_load(filebeat_config)
    assert "output.elasticsearch" in filebeat_config_yaml
    assert "hosts" in filebeat_config_yaml["output.elasticsearch"]
    assert filebeat_config_yaml["output.elasticsearch"]["hosts"] == indexer_ips
    ossec_config = container.pull(wazuh.OSSEC_CONF_PATH, encoding="utf-8").read()
    tree = etree.fromstring(f"<root>{ossec_config}</root>")  # nosec
    hosts = tree.xpath("/root/ossec_config/indexer/hosts//host")
    assert len(hosts) == len(indexer_ips)
    for idx, host in enumerate(hosts):
        assert host.text == f"https://{indexer_ips[idx]}"
    assert "wazuh-server-1" == tree.xpath("/root/ossec_config/cluster/node_name")[0].text
    assert "worker" == tree.xpath("/root/ossec_config/cluster/node_type")[0].text
    address = tree.xpath("/root/ossec_config/cluster/nodes/node")[0]
    assert address.text == master_ip


def test_install_certificates() -> None:
    """
    arrange: do nothing.
    act: save some content as certificates.
    assert: the files have been saved with the provided content.
    """
    harness = Harness(ops.CharmBase, meta=CHARM_METADATA)
    harness.begin_with_initial_hooks()
    container = harness.charm.unit.get_container("wazuh-server")
    wazuh.install_certificates(
        container,
        path=wazuh.FILEBEAT_CERTIFICATES_PATH,
        private_key="private_key",
        public_key="public_key",
        root_ca="root_ca",
        user="root",
        group="root",
    )

    assert (
        "private_key"
        == container.pull(
            wazuh.FILEBEAT_CERTIFICATES_PATH / "certificate.key", encoding="utf-8"
        ).read()
    )
    assert (
        "public_key"
        == container.pull(
            wazuh.FILEBEAT_CERTIFICATES_PATH / "certificate.pem", encoding="utf-8"
        ).read()
    )
    assert (
        "root_ca"
        == container.pull(
            wazuh.FILEBEAT_CERTIFICATES_PATH / "root-ca.pem", encoding="utf-8"
        ).read()
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
    wazuh.configure_agent_password(container, password=password)

    assert password == container.pull(wazuh.AGENT_PASSWORD_PATH, encoding="utf-8").read()


def test_configure_git_when_branch_specified() -> None:
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
        "wazuh-server", ["ssh-keyscan", "-t", "rsa", "git.server"], result="know_host"
    )
    harness.handle_exec("wazuh-server", ["rm", "-rf", f"{wazuh.REPOSITORY_PATH}/*"], result="")
    custom_config_repository = "git+ssh://user1@git.server/repo_name@main"
    harness.handle_exec(
        "wazuh-server",
        [
            "git",
            "clone",
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
    wazuh.configure_git(container, custom_config_repository, custom_config_ssh_key)
    assert "know_host" == container.pull(wazuh.KNOWN_HOSTS_PATH, encoding="utf-8").read()
    assert "somekey\n" == container.pull(wazuh.RSA_PATH, encoding="utf-8").read()


def test_configure_git_when_no_branch_specified() -> None:
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
        "wazuh-server", ["ssh-keyscan", "-t", "rsa", "git.server"], result="know_host"
    )
    harness.handle_exec("wazuh-server", ["rm", "-rf", f"{wazuh.REPOSITORY_PATH}/*"], result="")
    custom_config_repository = "git+ssh://user1@git.server/repo_name"
    harness.handle_exec(
        "wazuh-server",
        [
            "git",
            "clone",
            "git+ssh://user1@git.server/repo_name",
            "/root/repository",
        ],
        result="",
    )
    harness.begin_with_initial_hooks()
    container = harness.charm.unit.get_container("wazuh-server")
    custom_config_ssh_key = "somekey"
    wazuh.configure_git(container, custom_config_repository, custom_config_ssh_key)
    assert "know_host" == container.pull(wazuh.KNOWN_HOSTS_PATH, encoding="utf-8").read()
    assert "somekey\n" == container.pull(wazuh.RSA_PATH, encoding="utf-8").read()


def test_configure_git_when_no_key_no_repository_specified() -> None:
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
    harness.handle_exec("wazuh-server", ["rm", "-rf", f"{wazuh.REPOSITORY_PATH}/*"], result="")
    harness.begin_with_initial_hooks()
    container = harness.charm.unit.get_container("wazuh-server")
    wazuh.configure_git(container, None, None)
    assert not container.exists(wazuh.KNOWN_HOSTS_PATH)
    assert not container.exists(wazuh.RSA_PATH)


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
        result='WAZUH_VERSION="v4.9.2"\nWAZUH_REVISION="40921"\nWAZUH_TYPE="server"\n',
    )
    container = harness.charm.unit.get_container("wazuh-server")
    version = wazuh.get_version(container)
    assert "v4.9.2" == version
