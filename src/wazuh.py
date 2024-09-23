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
WAZUH_USER = "wazuh"
WAZUH_GROUP = "wazuh"
KNOWN_HOSTS_PATH = "/var/lib/pebble/default/.ssh/known_hosts"
RSA_PATH = "/var/lib/pebble/default/.ssh/id_rsa"
REPOSITORY_PATH = "/home/wazuh/repository"


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
    # Enclose the config file in an element since it might have repeated roots
    ossec_config_tree = etree.fromstring(f"<root>{ossec_config}</root>")  # nosec
    hosts = ossec_config_tree.xpath("/root/ossec_config/indexer/hosts")
    hosts[0].clear()
    for ip_port in ip_ports:
        new_host = etree.Element("host")
        new_host.text = f"https://{ip_port}"
        hosts[0].append(new_host)
    elements = ossec_config_tree.xpath("//ossec_config")
    content = b""
    for element in elements:
        content = content + etree.tostring(element, pretty_print=True)
    container.push(OSSEC_CONF_PATH, content, encoding="utf-8")

    proc = container.exec(["/var/ossec/bin/wazuh-control", "reload"])
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


def configure_git(container: ops.Container, git_repository: str, git_ssh_key: str) -> None:
    """Configure git.

    Args:
        container: the container to configure git for.
        git_repository: the git repository to add to known hosts.
        git_ssh_key: the SSH key for the git repository.
    """
    hostname = git_repository.split("@")[1].split("/")[0]
    process = container.exec(["ssh-keyscan", "-t", "rsa", hostname])
    output, _ = process.wait_output()
    container.push(
        KNOWN_HOSTS_PATH,
        output,
        encoding="utf-8",
        make_dirs=True,
        user=WAZUH_USER,
        group=WAZUH_GROUP,
        permissions=0o600,
    )
    container.push(
        RSA_PATH,
        git_ssh_key,
        encoding="utf-8",
        make_dirs=True,
        user=WAZUH_USER,
        group=WAZUH_GROUP,
        permissions=0o600,
    )
    process = container.exec(["git", "clone", git_repository, REPOSITORY_PATH])
    process.wait_output()


def pull_configuration_files(container: ops.Container) -> None:
    """Pull configuration files from the repository.

    Args:
        container: the container to pull the files into.
    """
    process = container.exec(["git", "--git-dir" f"{REPOSITORY_PATH}/.git", "pull"])
    process.wait_output()
    process = container.exec(["rsync", f"{REPOSITORY_PATH}", "/"])
    process.wait_output()
