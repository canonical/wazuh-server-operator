#!/usr/bin/env python3

# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Wazuh operational logic."""

import logging
import re
import secrets
import string
import typing
from enum import Enum
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import ops
import requests
import requests.adapters
import yaml

# Bandit classifies this import as vulnerable. For more details, see
# https://github.com/PyCQA/bandit/issues/767
from lxml import etree  # nosec

AGENT_PASSWORD_PATH = Path("/var/ossec/etc/authd.pass")
COLLECTORS_LOG_PATH = Path("/var/log/collectors")
COLLECTORS_RSYSLOG_LOG_PATH = COLLECTORS_LOG_PATH / "rsyslog"
CONTAINER_NAME = "wazuh-server"
FILEBEAT_CERTIFICATES_PATH = Path("/etc/filebeat/certs")
FILEBEAT_USER = "root"
FILEBEAT_CMD = [
    "/usr/share/filebeat/bin/filebeat",
    "--path.home",
    "/usr/share/filebeat",
    "--path.config",
    "/etc/filebeat",
    "--path.data",
    "/var/lib/filebeat",
    "--path.logs",
    "/var/log/filebeat",
]
FILEBEAT_CONF_PATH = Path("/etc/filebeat/filebeat.yml")
KNOWN_HOSTS_PATH = "/root/.ssh/known_hosts"
LOGS_PATH = Path("/var/ossec/logs")
OSSEC_CONF_PATH = Path("/var/ossec/etc/ossec.conf")
RSA_PATH = "/root/.ssh/id_rsa"
REPOSITORY_PATH = "/root/repository"
SYSLOG_CERTIFICATES_PATH = Path("/etc/rsyslog.d/certs")
SYSLOG_USER = "syslog"
API_PORT = 55000
AUTH_ENDPOINT = f"https://localhost:{API_PORT}/security/user/authenticate"
WAZUH_GROUP = "wazuh"
WAZUH_USER = "wazuh"


logger = logging.getLogger(__name__)


class WazuhInstallationError(Exception):
    """Base exception for Wazuh errors."""


class WazuhAuthenticationError(Exception):
    """Wazuh authentication errors."""


class WazuhConfigurationError(WazuhInstallationError):
    """Wazuh configuration errors."""


class NodeType(Enum):
    """Enum for the Wazuh node types.

    Attrs:
        WORKER: worker.
        MASTER: master.
    """

    WORKER = "worker"
    MASTER = "master"


def _update_filebeat_configuration(container: ops.Container, ip_ports: list[str]) -> None:
    """Update Filebeat configuration.

    Arguments:
        container: the container for which to update the configuration.
        ip_ports: list of indexer IPs and ports to configure.
    """
    filebeat_config = container.pull(FILEBEAT_CONF_PATH, encoding="utf-8").read()
    filebeat_config_yaml = yaml.safe_load(filebeat_config)
    filebeat_config_yaml["output.elasticsearch"]["hosts"] = ip_ports
    container.push(
        FILEBEAT_CONF_PATH, yaml.safe_dump(filebeat_config_yaml, sort_keys=False), encoding="utf-8"
    )


# Won't sacrify cohesion and readability to make pylint happier
def _update_wazuh_configuration(  # pylint: disable=too-many-locals, too-many-arguments
    container: ops.Container,
    ip_ports: list[str],
    master_address: str,
    unit_name: str,
    cluster_key: str,
    *,
    opencti_token: str | None = None,
    opencti_url: str | None = None,
) -> None:
    """Update Wazuh configuration.

    Arguments:
        container: the container for which to update the configuration.
        ip_ports: list of indexer IPs and ports to configure.
        master_address: the master unit addresses.
        unit_name: the unit's name.
        cluster_key: the Wazuh key for the cluster nodes.
        opencti_token: OpenCTI API token.
        opencti_url: OpenCTI URL.

    Raises:
        WazuhConfigurationError: if the configuration is invalid or missing required elements.
    """
    ossec_config = container.pull(OSSEC_CONF_PATH, encoding="utf-8").read()
    # Enclose the config file in an element since it might have repeated roots
    ossec_config_tree = etree.fromstring(f"<root>{ossec_config}</root>")
    hosts = ossec_config_tree.xpath("/root/ossec_config/indexer/hosts")
    if not hosts:
        raise WazuhConfigurationError("No indexer hosts found in the configuration.")
    hosts[0].clear()
    for ip_port in ip_ports:
        new_host = etree.Element("host")
        new_host.text = f"https://{ip_port}"
        hosts[0].append(new_host)

    cluster = ossec_config_tree.xpath("/root/ossec_config/cluster")
    if cluster:
        cluster[0].getparent().remove(cluster[0])
    node_name = unit_name.replace("/", "-")
    # Unit 0 is always present, so the presence of a master node is guaranteed
    node_type = NodeType.MASTER if unit_name.split("/")[1] == "0" else NodeType.WORKER
    elements = ossec_config_tree.xpath("//ossec_config")
    new_cluster = etree.fromstring(
        _generate_cluster_snippet(node_name, node_type, master_address, cluster_key)
    )
    elements[0].append(new_cluster)

    integrations = ossec_config_tree.xpath(".//integration[starts-with(name, 'custom-opencti-')]")
    if integrations and (not opencti_token or not opencti_url):
        raise WazuhConfigurationError(
            "Missing OpenCTI token or url for custom-opencti integrations. "
            "Ensure OpenCTI is integrated with Wazuh."
        )

    for integration in integrations:
        api_key = integration.find("api_key")
        if api_key is None:
            raise WazuhConfigurationError(
                f"Missing API key in {etree.tostring(integration, pretty_print=True).decode()}."
            )
        api_key.text = opencti_token

        hook_url = integration.find("hook_url")
        if hook_url is None:
            raise WazuhConfigurationError(
                f"Missing hook_url in {etree.tostring(integration, pretty_print=True).decode()}."
            )
        hook_url.text = f"{opencti_url}/graphql"

    content = b"".join([etree.tostring(element, pretty_print=True) for element in elements])
    container.push(OSSEC_CONF_PATH, content, encoding="utf-8")


def update_configuration(  # pylint: disable=too-many-arguments, too-many-positional-arguments
    container: ops.Container,
    indexer_ips: list[str],
    master_address: str,
    unit_name: str,
    cluster_key: str,
    opencti_url: str | None = None,
    opencti_token: str | None = None,
) -> None:
    """Update the workload configuration.

    Arguments:
        container: the container for which to update the configuration.
        indexer_ips: list of indexer IPs to configure.
        master_address: the master unit addresses.
        unit_name: the unit's name.
        cluster_key: the Wazuh key for the cluster nodes.
        opencti_url: the URL used for OpenCTI APIs.
        opencti_token: OpenCTI API token.
    """
    ip_ports = [f"{ip}" for ip in indexer_ips]
    _update_filebeat_configuration(container, ip_ports)
    _update_wazuh_configuration(
        container,
        ip_ports,
        master_address,
        unit_name,
        cluster_key,
        opencti_token=opencti_token,
        opencti_url=opencti_url,
    )


def install_certificates(  # pylint: disable=too-many-arguments,too-many-positional-arguments
    container: ops.Container,
    path: Path,
    public_key: str,
    private_key: str,
    root_ca: str,
    user: str,
    group: str,
) -> None:
    """Update TLS certificates.

    Arguments:
        container: the container for which to update the configuration.
        path: the path in which to copy the certificates.
        public_key: the certificate's public key.
        private_key: the certificate's private key.
        root_ca: the certifciate's CA public key.
        user: the usesr owning the files.
        group: the group owning the files.
    """
    container.push(
        path / "certificate.pem",
        public_key,
        make_dirs=True,
        permissions=0o400,
        user=user,
        group=group,
    )
    container.push(
        path / "certificate.key",
        private_key,
        make_dirs=True,
        permissions=0o400,
        user=user,
        group=group,
    )
    container.push(
        path / "root-ca.pem", root_ca, make_dirs=True, permissions=0o400, user=user, group=group
    )


def configure_agent_password(container: ops.Container, password: str) -> None:
    """Configure the agent password.

    Arguments:
        container: the container for which to update the password.
        password: the password for authenticating the agents.
    """
    container.push(
        AGENT_PASSWORD_PATH,
        password,
        user=WAZUH_USER,
        group=WAZUH_GROUP,
        make_dirs=True,
        permissions=0o640,
    )


def _get_current_configuration_url(container: ops.Container) -> str:
    """Get the current remote repository for configuration.

    Args:
        container: the container to configure git for.

    Returns:
        The repository URL.
    """
    process = container.exec(
        ["git", "-C", REPOSITORY_PATH, "config", "--get", "remote.origin.url"], timeout=1
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
    process = container.exec(
        ["git", "-C", REPOSITORY_PATH, "rev-parse", "--abbrev-ref", "HEAD"], timeout=1
    )
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
            f"{custom_config_ssh_key}\n",
            encoding="utf-8",
            make_dirs=True,
            user=WAZUH_USER,
            group=WAZUH_GROUP,
            permissions=0o600,
        )

    base_url = None
    branch = None
    try:
        if custom_config_repository:
            url = urlsplit(custom_config_repository)
            path_parts = url.path.split("@")
            branch = path_parts[1] if len(path_parts) > 1 else None
            base_url = urlunsplit(url._replace(path=path_parts[0]))
            process = container.exec(["ssh-keyscan", "-t", "rsa", str(url.hostname)], timeout=10)
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
            process = container.exec(["rm", "-Rf", REPOSITORY_PATH], timeout=1)
            process.wait_output()

            if base_url:
                command = ["git", "clone", "--depth", "1"]
                if branch:
                    command = command + ["--branch", branch]
                command = command + [base_url, REPOSITORY_PATH]
                process = container.exec(command, timeout=60)
                process.wait_output()
    except ops.pebble.ExecError as ex:
        raise WazuhInstallationError from ex


def pull_configuration_files(container: ops.Container) -> None:
    """Pull configuration files from the repository.

    Args:
        container: the container to pull the files into.

    Raises:
        WazuhInstallationError: if an error occurs while pulling the files.
    """
    try:
        process = container.exec(
            [
                "rsync",
                "-a",
                "--chown",
                "wazuh:wazuh",
                "--delete",
                "--include=etc/",
                "--include=etc/*.conf",
                "--include=etc/decoders/***",
                "--include=etc/rules/***",
                "--include=etc/shared/",
                "--include=etc/shared/*.conf",
                "--include=etc/shared/**/",
                "--include=etc/shared/**/*.conf",
                "--include=integrations/***",
                "--include=ruleset/***",
                "--exclude=*",
                "/root/repository/var/ossec/",
                "/var/ossec",
            ],
            timeout=10,
        )
        process.wait_output()
    except ops.pebble.ExecError as ex:
        raise WazuhInstallationError from ex


def set_filesystem_permissions(container: ops.Container) -> None:
    """Configure the filesystem permissions.

    Args:
        container: the container to configure the user for.

    Raises:
        WazuhInstallationError: if an error occurs while setting the permissions.
    """
    try:
        process = container.exec(
            ["mkdir", "-p", str(COLLECTORS_RSYSLOG_LOG_PATH)],
            timeout=1,
        )
        process.wait_output()
        process = container.exec(
            ["chmod", "o-rx", str(COLLECTORS_RSYSLOG_LOG_PATH)],
            timeout=1,
        )
        process.wait_output()
        process = container.exec(
            ["chown", "syslog:wazuh", str(COLLECTORS_RSYSLOG_LOG_PATH)],
            timeout=1,
        )
        process.wait_output()
    except ops.pebble.ExecError as ex:
        raise WazuhInstallationError from ex


def configure_filebeat_user(container: ops.Container, username: str, password: str) -> None:
    """Configure the filebeat user.

    Args:
        container: the container to configure the user for.
        username: the username.
        password: the password.

    Raises:
        WazuhInstallationError: if an error occurs while configuring the user.
    """
    try:
        process = container.exec(
            FILEBEAT_CMD + ["keystore", "add", "username", "--stdin", "--force"],
            stdin=username,
            timeout=1,
        )
        process.wait_output()
        process = container.exec(
            FILEBEAT_CMD + ["keystore", "add", "password", "--stdin", "--force"],
            stdin=password,
            timeout=1,
        )
        process.wait_output()
    except ops.pebble.ExecError as ex:
        raise WazuhInstallationError from ex


def _generate_cluster_snippet(
    node_name: str, node_type: NodeType, master_address: str, cluster_key: str
) -> str:
    """Generate the cluster configuration snippet for a unit.

    Args:
        node_name: the node name.
        node_type: the Wazuh node type.
        master_address: the for unit 0 in the cluster.
        cluster_key: the Wazuh key for the cluster nodes.

    Returns: the content for the cluster node for the Wazuh configuration.
    """
    return f"""

        <cluster>
            <name>wazuh</name>
            <node_name>{node_name}</node_name>
            <key>{cluster_key}</key>
            <node_type>{node_type.value}</node_type>
            <port>1516</port>
            <bind_addr>0.0.0.0</bind_addr>
            <nodes>
                <node>{master_address}</node>
            </nodes>
            <hidden>no</hidden>
            <disabled>no</disabled>
        </cluster>

    """


def authenticate_user(username: str, password: str) -> str:
    """Authenticate an API user.

    Args:
        username: the username.
        password: the password for the user.

    Returns: the JWT token

    Raises:
        WazuhAuthenticationError: if the user can't authenticate.
        WazuhInstallationError: if any error occurs.
    .
    """
    # The certificates might be self signed and there's no security hardening in
    # passing them to the request since tampering with `localhost` would mean the
    # container filesystem is compromised
    try:
        session = requests.Session()
        retries = requests.adapters.Retry(connect=10, backoff_factor=0.2, status_forcelist=[500])
        session.mount("https://", requests.adapters.HTTPAdapter(max_retries=retries))
        response = session.get(  # nosec
            AUTH_ENDPOINT,
            auth=(username, password),
            timeout=10,
            verify=False,
        )
        # The old password has already been changed. Nothing to do.
        if response.status_code == 401:
            raise WazuhAuthenticationError(f"The provided password for {username} is not valid.")
        response.raise_for_status()
        token = response.json()["data"]["token"] if response.json()["data"] else None
        if token is None:
            raise WazuhInstallationError(f"Response for {username} does not contain token.")
        return token
    except requests.exceptions.RequestException as exc:
        raise WazuhInstallationError from exc


def change_api_password(username: str, password: str, token: str) -> None:
    """Change Wazuh's API password for a given user.

    Args:
        username: the username to change the user for.
        password: the new password for the user.
        token: the auth token for the API.

    Raises:
        WazuhInstallationError: if an error occurs while processing the requests.
    """
    # The certificates might be self signed and there's no security hardening in
    # passing them to the request since tampering with `localhost` would mean the
    # container filesystem is compromised
    try:
        headers = {"Authorization": f"Bearer {token}"}
        response = requests.get(  # nosec
            f"https://localhost:{API_PORT}/security/users",
            headers=headers,
            timeout=10,
            verify=False,
        )
        response.raise_for_status()
        data = response.json()["data"]
        user_id = [
            user["id"] for user in data["affected_items"] if data and user["username"] == username
        ][0]
        response = requests.put(  # nosec
            f"https://localhost:{API_PORT}/security/users/{user_id}",
            headers=headers,
            json={"password": password},
            timeout=10,
            verify=False,
        )
        response.raise_for_status()
    except requests.exceptions.RequestException as exc:
        raise WazuhInstallationError("Error modifying the default password.") from exc


def generate_api_password() -> str:
    """Generate a password that complies with the API password imposed by Wazuh.

    Returns: a string with a compliant password.
    """
    charsets = [
        string.ascii_lowercase,
        string.ascii_uppercase,
        string.digits,
        "!#$%&()*+,-./:;<=>?@[]^_{|}~",
    ]
    password = [secrets.choice("".join(charsets)) for _ in range(11)]
    for charset in charsets:
        char = secrets.choice(charset)
        password.insert(secrets.randbelow(len(password) + 1), char)
    return "".join(password)


def create_readonly_api_user(username: str, password: str, token: str) -> None:
    """Create a new readonly user for Wazuh's API.

    Args:
        username: the username for the user.
        password: the password for the user.
        token: the auth token for the API.

    Raises:
        WazuhInstallationError: if an error occurs while processing the requests.
    """
    # The certificates might be self signed and there's no security hardening in
    # passing them to the request since tampering with `localhost` would mean the
    # container filesystem is compromised
    try:
        headers = {"Authorization": f"Bearer {token}"}
        response = requests.get(  # nosec
            f"https://localhost:{API_PORT}/security/users",
            headers=headers,
            json={"username": username, "password": password},
            timeout=10,
            verify=False,
        )
        logger.debug(response.json())
        data = response.json()["data"]
        user_id = [
            user["id"] for user in data["affected_items"] if data and user["username"] == username
        ]
        if not user_id:
            response = requests.post(  # nosec
                f"https://localhost:{API_PORT}/security/users",
                headers=headers,
                json={"username": username, "password": password},
                timeout=10,
                verify=False,
            )
            response.raise_for_status()
            logger.debug(response.json())
            data = response.json()["data"]
        user_id = [
            user["id"] for user in data["affected_items"] if data and user["username"] == username
        ][0]
        response = requests.get(  # nosec
            f"https://localhost:{API_PORT}/security/roles",
            headers=headers,
            timeout=10,
            verify=False,
        )
        response.raise_for_status()
        logger.debug(response.json())
        data = response.json()["data"]
        role_id = [
            role["id"] for role in data["affected_items"] if data and role["name"] == "readonly"
        ][0]
        response = requests.post(  # nosec
            f"https://localhost:{API_PORT}/security/users/{user_id}/roles?role_ids={role_id}",
            headers=headers,
            timeout=10,
            verify=False,
        )
        response.raise_for_status()
    except requests.exceptions.RequestException as exc:
        raise WazuhInstallationError("Error creating a readonly user.") from exc


def get_version(container: ops.Container) -> str:
    """Get the Wazuh version.

    Arguments:
        container: the container in which to check the version.

    Returns: the Wazuh version number.
    """
    process = container.exec(["/var/ossec/bin/wazuh-control", "info"], timeout=1)
    version_string, _ = process.wait_output()
    version = re.search('^WAZUH_VERSION="(.*)"', version_string)
    return version.group(1) if version else ""
