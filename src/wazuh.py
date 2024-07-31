#!/usr/bin/env python3

# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Wazhub operational logic."""

from pathlib import Path

import ops
from lxml import etree

FILEBEAT_CONF_PATH = Path("/etc/filebeat/filebeat.yml")
OSSEC_CONF_PATH = Path("/var/ossec/etc/ossec.conf")


class WazuhInstallationError(Exception):
    """Base exception for Jenkins errors."""


def update_configuration(container: ops.Container, indexer_ips: list[str]) -> None:
    """Update Wazhub configuration.

    Arguments:
        container: the container for which to update the configuration.
        indexer_ips: list of indexer IPs to configure.

    Raises:
        WazuhInstallationError: if an error occurs while installing.
    """
    ip_ports = [f"{ip}:92000" for ip in indexer_ips]
    filebeat_config = container.pull(FILEBEAT_CONF_PATH, encoding="utf-8").read()
    new_filebeat_config = ""
    for line in filebeat_config:
        new_line = line
        if line.startswith("hosts:"):
            new_line = f"hosts: [{', '.join(ip_ports)}]"
        new_filebeat_config = new_filebeat_config + new_line
    container.push(FILEBEAT_CONF_PATH, new_filebeat_config, encoding="utf-8")

    ossec_config = container.pull(OSSEC_CONF_PATH, encoding="utf-8").read()
    ossec_config_tree = etree.fromstring(ossec_config)  # nosec
    hosts = ossec_config_tree.xpath("/indexer/hosts")
    hosts.clear()
    for ip_port in ip_ports:
        new_host = etree.Element("host")
        new_host.text = f"https://{ip_port}"
        hosts.append(new_host)
    container.push(
        OSSEC_CONF_PATH,
        etree.to_string(ossec_config_tree, pretty_print=True),
        encoding="utf-8",
    )

    proc = container.exec(["systemctl", "daemon-reload"])
    try:
        proc.wait_output()
    except (ops.pebble.ChangeError, ops.pebble.ExecError) as exc:
        raise WazuhInstallationError("Error reloading the wazuh daemon.") from exc
