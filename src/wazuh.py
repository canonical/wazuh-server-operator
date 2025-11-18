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

import ops
import requests
import requests.adapters
import urllib3
import yaml

# Bandit classifies this import as vulnerable. For more details, see
# https://github.com/PyCQA/bandit/issues/767
from lxml import etree  # nosec
from pydantic import AnyUrl

# reduce unhelpful log volume
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logging.getLogger("urllib3").setLevel(logging.WARNING)

AGENT_PASSWORD_PATH = Path("/var/ossec/etc/authd.pass")
COLLECTORS_LOG_PATH = Path("/var/log/collectors")
RSYSLOG_LOG_DIR = COLLECTORS_LOG_PATH / "rsyslog"
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
RSYSLOG_SERVICE_LOG_PATH = Path("/var/log/rsyslog.log")
FILEBEAT_LOG_PATH = Path("/var/log/filebeat")
WAZUH_CONF_PATH = "/var/ossec"
OSSEC_CONF_PATH = Path(WAZUH_CONF_PATH, "etc/ossec.conf")
REPOSITORY_PATH = "/root/repository"
WAZUH_APPLIED_COMMIT_PATH = REPOSITORY_PATH + "/.wazuh_applied_commit"
RSYSLOG_APPLIED_COMMIT_PATH = REPOSITORY_PATH + "/.rsyslog_applied_commit"
REPO_WAZUH_CONF_PATH = REPOSITORY_PATH + WAZUH_CONF_PATH
RSYSLOG_CONF_PATH = "/etc/rsyslog.conf"
RSYSLOG_CONF_DIR_PATH = "/etc/rsyslog.d"
REPO_RSYSLOG_CONF_PATH = REPOSITORY_PATH + RSYSLOG_CONF_PATH
REPO_RSYSLOG_CONF_DIR_PATH = REPOSITORY_PATH + RSYSLOG_CONF_DIR_PATH
RSA_PATH = "/root/.ssh/id_rsa"
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


class WazuhNotReadyError(WazuhInstallationError):
    """Wazuh errors due to long-running installation process."""


class NodeType(Enum):
    """Enum for the Wazuh node types.

    Attrs:
        WORKER: worker.
        MASTER: master.
    """

    WORKER = "worker"
    MASTER = "master"


def get_current_repo_commit(container: ops.Container) -> typing.Optional[str]:
    """Actual HEAD of the cloned repo, or None if non-existing.

    Arguments:
        container: the container for which to read the actual repo commit.

    Returns:
        typing.Optional[str]: the actual commit.

    Raises:
       ExecError: Git rev-parse of the repo failed.
    """
    if not container.isdir(REPOSITORY_PATH):
        return None

    try:
        process = container.exec(["git", "-C", REPOSITORY_PATH, "rev-parse", "HEAD"])
        out, _ = process.wait_output()
        head = out.strip()
        return head or None

    except ops.pebble.APIError as e:
        logger.debug(
            "Pebble API error while reading applied commit marker at %s: %s", REPOSITORY_PATH, e
        )
        raise

    except ops.pebble.ExecError as e:
        logger.warning(
            "git rev-parse of the repository failed, probably not initialized yet: %s", str(e)
        )
        return None


def _read_applied_commit(container: ops.Container, path: str) -> typing.Optional[str]:
    """Read the last commit successfully applied.

    Arguments:
        container: the container for which to read the commit.
        path: the path where the last commit was applied.

    Returns:
        typing.Optional[str]: the last commit applied.
    """
    if not container.exists(path):
        return None

    try:
        commit_applied = container.pull(path).read().strip()
        return commit_applied or None
    except ops.pebble.PathError:
        logger.debug("Failed to read applied commit though path was confirmed to exist (%s)", path)
        return None


def save_applied_commit_marker(container: ops.Container, path: str) -> None:
    """Save actual HEAD as applied, call only after successful reconciliation.

    Arguments:
        container: the container in which to flag the commit as applied.
        path: the path where to save the commit.
    """
    head = get_current_repo_commit(container)
    if head:
        container.push(
            path,
            f"{head}\n",
            encoding="utf-8",
            make_dirs=True,
            permissions=0o644,
        )


def sync_filebeat_config(container: ops.Container, indexer_endpoints: list[str]) -> bool:
    """Update Filebeat configuration.

    Arguments:
        container: the container for which to update the configuration.
        indexer_endpoints: list of indexer IPs and ports to configure.

    Returns:
        bool: True if updates were made, False if config was already up to date.
    """
    filebeat_config = container.pull(FILEBEAT_CONF_PATH, encoding="utf-8").read()
    filebeat_config_yaml = yaml.safe_load(filebeat_config)
    if set(filebeat_config_yaml["output.elasticsearch"]["hosts"]) == set(indexer_endpoints):
        return False
    filebeat_config_yaml["output.elasticsearch"]["hosts"] = indexer_endpoints
    container.push(
        FILEBEAT_CONF_PATH, yaml.safe_dump(filebeat_config_yaml, sort_keys=False), encoding="utf-8"
    )
    return True


# Won't sacrify cohesion and readability to make pylint happier
def sync_ossec_conf(  # pylint: disable=too-many-locals, too-many-arguments  # noqa: C901
    container: ops.Container,
    ip_ports: list[str],
    master_address: str,
    unit_name: str,
    cluster_key: str,
    *,
    opencti_token: str | None = None,
    opencti_url: str | None = None,
    enable_vulnerability_detection: bool = True,
) -> bool:
    """Update Wazuh configuration.

    Arguments:
        container: the container for which to update the configuration.
        ip_ports: list of indexer IPs and ports to configure.
        master_address: the master unit addresses.
        unit_name: the unit's name.
        cluster_key: the Wazuh key for the cluster nodes.
        opencti_token: OpenCTI API token.
        opencti_url: OpenCTI URL.
        enable_vulnerability_detection: whether to enable Wazuh's vulnerability detection module.

    Returns:
        bool: True if config has changed, False if no updates were made

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
        logger.warning("Missing OpenCTI token or url for custom-opencti integrations.")

    for integration in integrations:
        api_key = integration.find("api_key")
        if api_key is not None and opencti_token is not None:
            api_key.text = opencti_token

        hook_url = integration.find("hook_url")
        if hook_url is not None and opencti_url is not None:
            hook_url.text = f"{opencti_url}/graphql"

    if vuln_conf := ossec_config_tree.xpath("/root/ossec_config/vulnerability-detection"):
        elements[0].remove(vuln_conf[0])
    if not enable_vulnerability_detection:
        new_conf = etree.fromstring(
            (
                "<vulnerability-detection>"
                + "<enabled>no</enabled>"
                + "<index-status>no</index-status>"
                + "</vulnerability-detection>"
            )
        )
        elements[0].append(new_conf)

    new_conf_bytes: bytes = b"".join(
        [etree.tostring(element, pretty_print=True, encoding="utf-8") for element in elements]
    )
    conf_string = new_conf_bytes.decode("utf-8")
    # remove blank lines
    new_conf = "\n".join([line for line in conf_string.splitlines() if line != ""])
    if ossec_config == new_conf:
        logger.info("ossec.conf has not changed, nothing to write")
        return False
    logger.info("writing new configuration to %s", OSSEC_CONF_PATH)
    container.push(OSSEC_CONF_PATH, new_conf, encoding="utf-8")
    return True


def sync_permissions(
    container: ops.Container,
    path: str,
    permissions: int,
    user: str | None = None,
    group: str | None = None,
) -> bool:
    """Sync permissions on an arbitrary filepath.

    Arguments:
        container: the container for which to update the configuration.
        path: the path on which to sync permissions.
        permissions: the integer-formatted Linux file permissions to set, i.e. 0o400.
        user: (optional) the file owner's username.
        group: (optional) the file owner's groupname.

    Returns:
        bool: True if a change was made, False if permissions were up to date
    """
    made_changes = False
    if not container.exists(path):
        logger.warning("cannot sync permissions on '%s', path does not exist", path)
        return made_changes

    try:
        stdout: str = container.exec(["stat", "-c", "%a", path]).wait_output()[0].strip()
        current_permissions = int(stdout, 8)
        if current_permissions != permissions:
            made_changes = True
            container.exec(["chmod", f"{permissions:o}", path]).wait_output()

        needs_chown: bool = False
        if user is not None:
            current_user: str = container.exec(["stat", "-c", "%U", path]).wait_output()[0].strip()
            needs_chown = needs_chown or (current_user != user)
        if group is not None:
            current_group: str = (
                container.exec(["stat", "-c", "%G", path]).wait_output()[0].strip()
            )
            needs_chown = needs_chown or (current_group != group)
        if needs_chown:
            user_string = user if user is not None else ""
            group_string = f":{group}" if group is not None else ""
            container.exec(["chown", f"{user_string}{group_string}", path]).wait_output()
            made_changes = True

        return made_changes
    except ops.pebble.ExecError as ex:
        logger.warning("Encountered error setting permissions on %s: %s", path, ex)
        return False


def sync_certificates(  # pylint: disable=too-many-arguments,too-many-positional-arguments
    container: ops.Container,
    path: Path,
    public_key: str,
    private_key: str,
    root_ca: str,
    user: str,
    group: str,
) -> bool:
    """Update TLS certificates.

    Arguments:
        container: the container for which to update the configuration.
        path: the path in which to copy the certificates.
        public_key: the certificate's public key.
        private_key: the certificate's private key.
        root_ca: the certifciate's CA public key.
        user: the usesr owning the files.
        group: the group owning the files.

    Returns:
        bool: True if a change was made, False if certs were already installed
    """
    pairs = (
        ("certificate.pem", public_key),
        ("certificate.key", private_key),
        ("root-ca.pem", root_ca),
    )
    made_change = False
    for filename, source in pairs:
        filepath = path / filename
        current_content = ""
        if container.exists(filepath):
            current_content = container.pull(filepath, encoding="utf-8").read()
        if current_content != source:
            made_change = True
            container.push(
                filepath, source, make_dirs=True, permissions=0o400, user=user, group=group
            )
        else:
            made_change = made_change or sync_permissions(container, filepath.as_posix(), 0o400)
    if made_change:
        logger.info("installed certificates to %s", path)
    return made_change


def sync_agent_password(container: ops.Container, password: str) -> bool:
    """Configure the agent password.

    Arguments:
        container: the container for which to update the password.
        password: the password for authenticating the agents.

    Returns:
        bool: True if password was updated, False if already synced
    """
    current_value = ""
    if container.exists(AGENT_PASSWORD_PATH):
        current_value = container.pull(AGENT_PASSWORD_PATH, encoding="utf-8").read()
    if current_value == password:
        logger.debug("agent password already up to date")
        return False
    logger.info("updating agent password")
    container.push(
        AGENT_PASSWORD_PATH,
        password,
        user=WAZUH_USER,
        group=WAZUH_GROUP,
        make_dirs=True,
        permissions=0o640,
    )
    return True


def _get_current_repo_url(container: ops.Container) -> str:
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


def _get_current_repo_tag(container: ops.Container) -> str:
    """Get the current remote repository tag for configuration.

    Args:
        container: the container to configure git for.

    Returns:
        The repository branch.
    """
    process = container.exec(
        ["git", "-C", REPOSITORY_PATH, "describe", "--tags", "--exact-match"], timeout=1
    )
    tag = ""
    try:
        tag, _ = process.wait_output()
    except ops.pebble.ExecError as ex:
        logging.debug(ex)
    return tag.rstrip()


def pull_config_repo(
    container: ops.Container, hostname: str, base_url: str, ref: str | None
) -> None:
    """Pull a local copy of the specified repository.

    Args:
        container: the container to configure git for.
        hostname: hostname of the git repository server
        base_url: base_url of the repository
        ref: branch or tag name to pull. Can be null/None.

    Raises:
        WazuhInstallationError: if an error occurs while configuring git.
    """
    logger.info("cloning the '%s' ref of '%s'", ref, base_url)
    try:
        process = container.exec(["ssh-keyscan", "-t", "rsa", str(hostname)], timeout=10)
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
        container.exec(["rm", "-Rf", REPOSITORY_PATH], timeout=1).wait_output()
        command = ["git", "clone", "--depth", "1"]
        if ref is not None:
            command = command + ["--branch", ref]
        command = command + [base_url, REPOSITORY_PATH]
        container.exec(command, timeout=60).wait_output()
    except ops.pebble.ExecError as ex:
        logger.error("git clone of custom_config_repository failed")
        raise WazuhInstallationError from ex


def sync_config_repo(
    container: ops.Container,
    repository: typing.Optional[AnyUrl],
    repo_ssh_key: typing.Optional[str],
) -> bool:
    """Synchronize a local copy of the custom config repository.

    Args:
        container: the container to configure git for.
        repository: the git repository to add to known hosts in format
        git+ssh://<user>@<host>@<branch|tag>.
        repo_ssh_key: the SSH key for the git repository.

    Returns:
        bool: True if a pull was executed, False if there was nothing to sync

    Raises:
        WazuhInstallationError: if an error occurs while configuring git.
    """
    if repository is None:
        # nothing to do
        return False

    if not (isinstance(repository.host, str) and isinstance(repository.path, str)):
        logger.error("repository URL (%s) is missing hostname or path", str(repository))
        raise WazuhInstallationError

    path, *ref_string = repository.path.split(sep="@", maxsplit=1)
    ref = ref_string[0] if len(ref_string) == 1 else None
    username = f"{repository.username}@" if isinstance(repository.username, str) else ""
    base_url = f"{repository.scheme}://{username}{repository.host}{path}"

    repo = _get_current_repo_url(container)
    is_right_repo: bool = base_url in (repo, f"git+ssh://{repo}")
    is_right_tag: bool = ref is not None and _get_current_repo_tag(container) == ref

    already_synced = is_right_repo and is_right_tag

    if already_synced:
        logger.info("custom_config_repository is already up to date")
        return False

    if repo_ssh_key:
        container.push(
            RSA_PATH,
            f"{repo_ssh_key}\n",
            encoding="utf-8",
            make_dirs=True,
            user=WAZUH_USER,
            group=WAZUH_GROUP,
            permissions=0o600,
        )

    pull_config_repo(container, hostname=repository.host, base_url=base_url, ref=ref)
    return True


def sync_wazuh_config_files(container: ops.Container) -> bool:
    """Sync Wazuh configuration files from the local config repository.

    Args:
        container: the container to pull the files into.

    Returns:
        bool: True if a sync was executed, False if there was nothing to sync.

    Raises:
        WazuhInstallationError: if an error occurs while pulling the files.
    """
    current_head = get_current_repo_commit(container)
    applied_head = _read_applied_commit(container, WAZUH_APPLIED_COMMIT_PATH)

    if current_head is not None and current_head == applied_head:
        return False

    source, dest = REPO_WAZUH_CONF_PATH, WAZUH_CONF_PATH
    if not container.exists(source):
        logger.info("path '%s' does not exist, no files to patch", source)
        return False
    if container.isdir(source) and source[-1] != "/":
        source += "/"
    try:
        logger.info("patching files from %s to %s", source, dest)
        container.exec(
            [
                "rsync",
                "-a",
                "--chown",
                "root:wazuh",
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
                "--exclude=*",
                source,
                dest,
            ],
            timeout=10,
        ).wait_output()

        # Copy patch files in ruleset directory
        container.exec(
            [
                "rsync",
                "-a",
                "--chown",
                "root:wazuh",
                "--include=ruleset/***",
                "--exclude=*",
                source,
                dest,
            ],
            timeout=10,
        ).wait_output()

        # Find all files within the integrations directory and make them executable.
        # This ensures all integration scripts are runnable by the wazuh group.
        container.exec(
            [
                "find",
                "/var/ossec/integrations",
                "-type",
                "f",
                "-exec",
                "chmod",
                "750",
                "{}",
                "+",
            ],
            timeout=10,
        ).wait_output()

        # Adds correct permissions to the /etc/shared/default directory
        # 770 required for the manager to create the merged.mg file
        container.exec(
            ["chmod", "770", "/var/ossec/etc/shared/default"],
            timeout=10,
        ).wait_output()

        save_applied_commit_marker(container, WAZUH_APPLIED_COMMIT_PATH)
        return True
    except ops.pebble.ExecError as ex:
        raise WazuhInstallationError from ex


def sync_rsyslog_config_files(container: ops.Container) -> bool:
    """Sync rsyslog configuration files from the local config repository.

    Args:
        container: the container to pull the files into.

    Returns:
        bool: True if a sync was executed, False if there was nothing to sync.

    Raises:
        WazuhInstallationError: if an error occurs while pulling the files.
    """
    current_head = get_current_repo_commit(container)
    applied_head = _read_applied_commit(container, RSYSLOG_APPLIED_COMMIT_PATH)

    if current_head is not None and current_head == applied_head:
        return False

    pairs = (
        (REPO_RSYSLOG_CONF_PATH, RSYSLOG_CONF_PATH),
        (REPO_RSYSLOG_CONF_DIR_PATH, RSYSLOG_CONF_DIR_PATH),
    )
    for source, dest in pairs:
        if not container.exists(source):
            logger.info("path '%s' does not exist, no files to patch", source)
            continue
        try:
            logger.info("patching files from %s to %s", source, dest)
            if container.isdir(source) and source[-1] != "/":
                source += "/"
            # default ownership (root:root) and perms (f: 644 / d: 755) should be sufficient
            container.exec(["rsync", "-a", source, dest], timeout=10).wait_output()
        except ops.pebble.ExecError as ex:
            raise WazuhInstallationError from ex

    save_applied_commit_marker(container, RSYSLOG_APPLIED_COMMIT_PATH)
    return True


def ensure_rsyslog_output_dir(container: ops.Container) -> bool:
    """Configure the filesystem to enable writing received rsyslog data to disk.

    Args:
        container: the container to configure the user for.

    Returns:
        bool: True if changes were made, False if no changes were necessary.
    """
    made_changes = False
    permissions = 0o750
    user = "syslog"
    group = "wazuh"
    if not container.isdir(RSYSLOG_LOG_DIR):
        made_changes = True
        container.make_dir(
            path=RSYSLOG_LOG_DIR,
            make_parents=True,
            permissions=permissions,
            user=user,
            group=group,
        )
    made_changes = made_changes or sync_permissions(
        container, RSYSLOG_LOG_DIR.as_posix(), permissions, user, group
    )
    return made_changes


def sync_filebeat_user(container: ops.Container, username: str, password: str) -> bool:
    """Configure the filebeat user.

    Args:
        container: the container to configure the user for.
        username: the username.
        password: the password.

    Returns:
        bool: True if updates were made, False if user is already configured.

    Raises:
        WazuhInstallationError: if an error occurs while configuring the user.
    """
    try:
        container.exec(["filebeat", "test", "output"], timeout=5).wait_output()
        # configured credentials are correct
        return False
    except ops.pebble.ExecError:
        # current user is not authorized, proceed to configure user
        pass
    try:
        container.exec(
            FILEBEAT_CMD + ["keystore", "add", "username", "--stdin", "--force"],
            stdin=username,
            timeout=1,
        ).wait_output()
        container.exec(
            FILEBEAT_CMD + ["keystore", "add", "password", "--stdin", "--force"],
            stdin=password,
            timeout=1,
        ).wait_output()
        return True
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
        WazuhNotReadyError: if wazuh is not yet ready to accept requests.
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
        logger.debug("Got Wazuh API auth token for username %s", username)
        return token
    except requests.exceptions.ConnectionError as exc:
        logger.warning("Wazuh API authentication failed: %s", exc)
        raise WazuhNotReadyError from exc
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
        logger.info("Changed API password for user %s", username)
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


def create_api_user(username: str, password: str, token: str, rolename: str = "readonly") -> None:
    """Create a new readonly user for Wazuh's API.

    Args:
        username: the username for the user.
        password: the password for the user.
        token: the auth token for the API.
        rolename: (optional) the user's rbac role. default: readonly.

    Raises:
        WazuhAuthenticationError: if a 401 error occurs while processing the requests.
        WazuhInstallationError: if any non-401 error occurs while processing the requests.
    """
    # The certificates might be self signed and there's no security hardening in
    # passing them to the request since tampering with `localhost` would mean the
    # container filesystem is compromised
    response = None
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
        ]
        if not user_id:  # user has not been created yet
            response = requests.post(  # nosec
                f"https://localhost:{API_PORT}/security/users",
                headers=headers,
                json={"username": username, "password": password},
                timeout=10,
                verify=False,
            )
            response.raise_for_status()
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
        data = response.json()["data"]
        role_id = [
            role["id"] for role in data["affected_items"] if data and role["name"] == rolename
        ][0]
        response = requests.post(  # nosec
            f"https://localhost:{API_PORT}/security/users/{user_id}/roles?role_ids={role_id}",
            headers=headers,
            timeout=10,
            verify=False,
        )
        response.raise_for_status()
        logger.info("Created user %s", username)
    except requests.exceptions.RequestException as exc:
        if isinstance(response, requests.Response) and response.status_code == 401:
            raise WazuhAuthenticationError("401 error creating an API user") from exc
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
