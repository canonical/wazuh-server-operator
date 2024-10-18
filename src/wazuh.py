#!/usr/bin/env python3

# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

# pylint: disable=import-outside-toplevel

"""Wazuh operational logic."""

import logging
import typing
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

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
KNOWN_HOSTS_PATH = "/root/.ssh/known_hosts"
RSA_PATH = "/root/.ssh/id_rsa"
REPOSITORY_PATH = "/root/repository"


logger = logging.getLogger(__name__)


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
    ip_ports = [f"{ip}" for ip in indexer_ips]
    filebeat_config = container.pull(FILEBEAT_CONF_PATH, encoding="utf-8").read()
    filebeat_config_yaml = yaml.safe_load(filebeat_config)
    filebeat_config_yaml["output.elasticsearch"]["hosts"] = ip_ports
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


def install_certificates(
    container: ops.Container, public_key: str, private_key: str, root_ca: str
) -> None:
    """Update Wazuh filebeat certificates.

    Arguments:
        container: the container for which to update the configuration.
        public_key: the certificate's public key.
        private_key: the certificate's private key.
        root_ca: the certifciate's CA public key.
    """
    container.push(CERTIFICATES_PATH / "filebeat.pem", public_key, make_dirs=True)
    container.push(CERTIFICATES_PATH / "filebeat-key.pem", private_key, make_dirs=True)
    container.push(CERTIFICATES_PATH / "root-ca.pem", root_ca, make_dirs=True)


def _get_current_configuration_url(container: ops.Container) -> str:
    """Get the current remote repository for configuration.

    Args:
        container: the container to configure git for.

    Returns:
        The repository URL.
    """
    process = container.exec(
        ["git", "-C", REPOSITORY_PATH, "config", "--get", "remote.origin.url"]
    )
    remote_url = ""
    try:
        remote_url, _ = process.wait_output()
    except ops.pebble.ExecError as ex:
        logging.debug(ex)
    return remote_url.rstrip()


def _get_current_configuration_url_branch(container: ops.Container) -> str:
    """Get the current remote repository branch for configuration.

    Args:
        container: the container to configure git for.

    Returns:
        The repository branch.
    """
    process = container.exec(["git", "-C", REPOSITORY_PATH, "rev-parse", "--abbrev-ref", "HEAD"])
    branch = ""
    try:
        branch, _ = process.wait_output()
    except ops.pebble.ExecError as ex:
        logging.debug(ex)
    return branch.rstrip()


def configure_git(
    container: ops.Container,
    custom_config_repository: typing.Optional[str],
    custom_config_ssh_key: typing.Optional[str],
) -> None:
    """Configure git.

    Args:
        container: the container to configure git for.
        custom_config_repository: the git repository to add to known hosts in format
        git+ssh://<user>@<url>:<branch>.
        custom_config_ssh_key: the SSH key for the git repository.
    """
    if custom_config_ssh_key:
        container.push(
            RSA_PATH,
            custom_config_ssh_key,
            encoding="utf-8",
            make_dirs=True,
            user=WAZUH_USER,
            group=WAZUH_GROUP,
            permissions=0o600,
        )

    base_url = None
    branch = None
    if custom_config_repository:
        url = urlsplit(custom_config_repository)
        path_parts = url.path.split("@")
        branch = path_parts[1] if len(path_parts) > 1 else None
        base_url = urlunsplit(url._replace(path=path_parts[0]))
        process = container.exec(["ssh-keyscan", "-t", "rsa", str(url.hostname)])
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
    if (
        _get_current_configuration_url(container) != base_url
        or _get_current_configuration_url_branch(container) != branch
    ):
        process = container.exec(["rm", "-rf", REPOSITORY_PATH])
        process.wait_output()

        if base_url:
            command = ["git", "clone"]
            if branch:
                command = command + ["--branch", branch]
            command = command + [base_url, REPOSITORY_PATH]
            process = container.exec(command)
            process.wait_output()


def pull_configuration_files(container: ops.Container) -> None:
    """Pull configuration files from the repository.

    Args:
        container: the container to pull the files into.
    """
    try:
        process = container.exec(["git", "--git-dir", f"{REPOSITORY_PATH}/.git", "pull"])
        process.wait_output()
        process = container.exec(
            [
                "rsync",
                "-ra",
                "--chown",
                "wazuh:wazuh",
                f"{REPOSITORY_PATH}/var/ossec/",
                "/var/ossec",
            ]
        )
        process.wait_output()
    except ops.pebble.ExecError as ex:
        logging.debug(ex)


def configure_filebeat_user(container: ops.Container, username: str, password: str) -> None:
    """Configure the filebeat user.

    Args:
        container: the container to configure the user for.
        username: the username.
        password: the password.
    """
    try:
        process = container.exec(
            ["filebeat", "keystore", "add", "username", "--stdin", "--force"],
            stdin=username,
        )
        process.wait_output()
        process = container.exec(
            ["filebeat", "keystore", "add", "password", "--stdin", "--force"],
            stdin=password,
        )
        process.wait_output()
    except ops.pebble.ExecError as ex:
        logging.debug(ex)
