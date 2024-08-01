# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Wazhub unit tests."""

import unittest.mock
import ops
import yaml
from lxml import etree  # nosec
from ops.testing import Harness
from pathlib import Path

import wazuh
import unittest
import pytest

CHARM_METADATA = """
name: wazuh
containers:
  default:
    resource: wazuh-server-image
"""


def test_update_configuration(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    arrange: copy the Wazuh configuration files into a container
    act: save a configuration with a set of indexer IPs
    assert: the IPs have been persisted in the corresponding files
    """
    indexer_ips = ["92.0.0.1", "92.0.0.2"]
    harness = Harness(ops.CharmBase, meta=CHARM_METADATA)
    harness.begin_with_initial_hooks()
    container = harness.charm.unit.get_container("default")
    exec_process = unittest.mock.MagicMock()
    exec_process.wait_output = unittest.mock.MagicMock(return_value=(0, 0))
    exec_mock = unittest.mock.MagicMock(return_value=exec_process)
    monkeypatch.setattr(container, "exec", exec_mock)
    filebeat_content = Path("tests/unit/resources/partial_filebeat.yml").read_text()
    container.push(wazuh.FILEBEAT_CONF_PATH, filebeat_content, make_dirs=True)
    ossec_content = Path("tests/unit/resources/partial_ossec.xml").read_text()
    container.push(wazuh.OSSEC_CONF_PATH, ossec_content, make_dirs=True)

    wazuh.update_configuration(container, indexer_ips)

    with open(wazuh.FILEBEAT_CONF_PATH, encoding="utf-8") as config_file:
        content = yaml.safe_load(config_file)
        assert "hosts" in content
        assert content["hosts"] == [f"{ip}:9200" for ip in indexer_ips]
    with open(wazuh.OSSEC_CONF_PATH, encoding="utf-8") as config_file:
        tree = etree.fromstring(config_file.read())  # nosec
        hosts = tree.xpath("/indexer/hosts/host")
        assert len(hosts) == len(indexer_ips)
        for idx, host in enumerate(hosts):
            assert host.text == f"https://{indexer_ips[idx]}:9200"
