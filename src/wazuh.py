#!/usr/bin/env python3

# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

# pylint: disable=import-outside-toplevel

"""Wazuh operational logic."""

from pathlib import Path

import ops
import yaml

# Bandit classifies this import as vulnerable. For more details, see
# https://github.com/PyCQA/bandit/issues/767
from lxml import etree  # nosec

CERTIFICATES_PATH = Path("/etc/filebeat/certs")
FILEBEAT_CONF_PATH = Path("/etc/filebeat/filebeat.yml")
OSSEC_CONF_PATH = Path("/var/ossec/etc/ossec.conf")


class WazuhInstallationError(Exception):
    """Base exception for Wazuh errors."""


def update_configuration(container: ops.Container, indexer_ips: list[str]) -> None:
    """Update Wazuh configuration.

    Arguments:
        container: the container for which to update the configuration.
        indexer_ips: list of indexer IPs to configure.

    Raises:
        WazuhInstallationError: if an error occurs while installing.
    """
    ip_ports = [f"{ip}:9200" for ip in indexer_ips]
    filebeat_config = container.pull(FILEBEAT_CONF_PATH, encoding="utf-8").read()
    filebeat_config_yaml = yaml.safe_load(filebeat_config)
    filebeat_config_yaml["hosts"] = ip_ports
    container.push(FILEBEAT_CONF_PATH, yaml.safe_dump(filebeat_config_yaml), encoding="utf-8")

    ossec_config = container.pull(OSSEC_CONF_PATH, encoding="utf-8").read()
    ossec_config_tree = etree.fromstring(ossec_config)  # nosec
    hosts = ossec_config_tree.xpath("/indexer/hosts")
    hosts[0].clear()
    for ip_port in ip_ports:
        new_host = etree.Element("host")
        new_host.text = f"https://{ip_port}"
        hosts[0].append(new_host)
    container.push(
        OSSEC_CONF_PATH, etree.tostring(ossec_config_tree, pretty_print=True), encoding="utf-8"
    )

    proc = container.exec(["systemctl", "daemon-reload"])
    try:
        proc.wait_output()
    except (ops.pebble.ChangeError, ops.pebble.ExecError) as exc:
        raise WazuhInstallationError("Error reloading the wazuh daemon.") from exc


def install_certificates(container: ops.Container, public_key: str, private_key: str) -> None:
    """Update Wazuh filebeat certificates.

    Arguments:
        container: the container for which to update the configuration.
        public_key: the certificate's public key.
        private_key: the certificate's private key.
    """
    container.push(CERTIFICATES_PATH / "filebeat.pem", public_key, make_dirs=True)
    container.push(CERTIFICATES_PATH / "filebeat-key.pem", private_key, make_dirs=True)
