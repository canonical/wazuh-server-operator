# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Wazhub unit tests."""

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


def test_update_configuration(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    arrange: copy the Wazuh configuration files into a container and mock the service restart.
    act: save a configuration with a set of indexer IPs.
    assert: the IPs have been persisted in the corresponding files.
    """
    indexer_ips = ["10.0.0.2", "10.0.0.3"]
    harness = Harness(ops.CharmBase, meta=CHARM_METADATA)
    harness.begin_with_initial_hooks()
    container = harness.charm.unit.get_container("wazuh-server")
    exec_process = unittest.mock.MagicMock()
    exec_process.wait_output = unittest.mock.MagicMock(return_value=(0, 0))
    exec_mock = unittest.mock.MagicMock(return_value=exec_process)
    monkeypatch.setattr(container, "exec", exec_mock)
    filebeat_content = Path("tests/unit/resources/filebeat.yml").read_text(encoding="utf-8")
    container.push(wazuh.FILEBEAT_CONF_PATH, filebeat_content, make_dirs=True)
    ossec_content = Path("tests/unit/resources/ossec.xml").read_text(encoding="utf-8")
    container.push(wazuh.OSSEC_CONF_PATH, ossec_content, make_dirs=True)

    wazuh.update_configuration(container, indexer_ips)

    filebeat_config = container.pull(wazuh.FILEBEAT_CONF_PATH, encoding="utf-8").read()
    filebeat_config_yaml = yaml.safe_load(filebeat_config)
    assert "hosts" in filebeat_config_yaml
    assert filebeat_config_yaml["hosts"] == [f"{ip}:9200" for ip in indexer_ips]
    ossec_config = container.pull(wazuh.OSSEC_CONF_PATH, encoding="utf-8").read()
    tree = etree.fromstring(ossec_config)  # nosec
    hosts = tree.xpath("/indexer/hosts//host")
    assert len(hosts) == len(indexer_ips)
    for idx, host in enumerate(hosts):
        assert host.text == f"https://{indexer_ips[idx]}:9200"


def test_update_configuration_when_restart_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    arrange: copy the Wazuh configuration files into a container and mock the service restart so
        that it errors.
    act: save a configuration with a set of indexer IPs.
    assert: a WazuhInstallationError is raised.
    """
    indexer_ips = ["92.0.0.1", "92.0.0.2"]
    harness = Harness(ops.CharmBase, meta=CHARM_METADATA)
    harness.begin_with_initial_hooks()
    container = harness.charm.unit.get_container("wazuh-server")
    exec_process = unittest.mock.MagicMock()
    exec_error = ops.pebble.ExecError(
        command=["systemctl", "daemon-reload"], exit_code=1, stdout="", stderr=""
    )
    exec_process.wait_output = unittest.mock.MagicMock(side_effect=exec_error)
    exec_mock = unittest.mock.MagicMock(return_value=exec_process)
    monkeypatch.setattr(container, "exec", exec_mock)
    filebeat_content = Path("tests/unit/resources/filebeat.yml").read_text(encoding="utf-8")
    container.push(wazuh.FILEBEAT_CONF_PATH, filebeat_content, make_dirs=True)
    ossec_content = Path("tests/unit/resources/ossec.xml").read_text(encoding="utf-8")
    container.push(wazuh.OSSEC_CONF_PATH, ossec_content, make_dirs=True)

    with pytest.raises(wazuh.WazuhInstallationError):
        wazuh.update_configuration(container, indexer_ips)


def test_install_certificates() -> None:
    """
    arrange: do nothing.
    act: save some content as certificates.
    assert: the files have been saved with the provider content.
    """
    harness = Harness(ops.CharmBase, meta=CHARM_METADATA)
    harness.begin_with_initial_hooks()
    container = harness.charm.unit.get_container("wazuh-server")
    wazuh.install_certificates(container, private_key="private_key", public_key="public_key")

    assert (
        "private_key"
        == container.pull(wazuh.CERTIFICATES_PATH / "filebeat-key.pem", encoding="utf-8").read()
    )
    assert (
        "public_key"
        == container.pull(wazuh.CERTIFICATES_PATH / "filebeat.pem", encoding="utf-8").read()
    )
