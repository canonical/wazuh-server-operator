# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Integration test helpers."""

import logging
import socket
import ssl
from pathlib import Path

import sh
import yaml
from juju.model import Model

logger = logging.getLogger(__name__)


async def get_k8s_service_address(model: Model, service_name: str) -> str:
    """Get the address of a LoadBalancer Kubernetes service using kubectl.

    Args:
        model: the Juju model.
        service_name: The name of the Kubernetes service.

    Returns:
        The LoadBalancer service address as a string.
    """
    # sh.kubectl.get.service actually exists
    return sh.kubectl.get.service(  # pylint: disable=no-member
        service_name, namespace=model.name, o="jsonpath={.status.loadBalancer.ingress[0].ip}"
    )


async def get_ca_certificate() -> str:
    """Returns the CA certificate of the Wazuh server

    Returns:
        str: the CA certificate.
    """
    output = sh.juju.run(  # pylint: disable=no-member
        "self-signed-certificates/0",
        "get-ca-certificate",
        "--no-color",
        model="localhost:testing-machine",
        format="yaml",
    )
    return yaml.safe_load(output)["self-signed-certificates/0"]["results"]["ca-certificate"]


async def send_syslog_over_tls(message: str, host: str, server_ca: str, valid_cn: bool) -> bool:
    """Send a syslog message over TLS.

    Args:
        message: the message to send.
        host: the rsyslog server to connect to.
        server_ca: the CA to authenticate the server.
        valid_cn: should the syslog client have a valid CN.

    Returns:
        bool: True if no error occurred from the client perspective.
              It doesn't mean the message has been accepted on the server.
    """
    test_dir = Path(__file__).parent
    context = ssl.create_default_context(cadata=server_ca)

    client_type = "good"
    if not valid_cn:
        client_type = "bad"

    context.load_cert_chain(
        certfile=test_dir / f"certs/{client_type}-client.crt",
        keyfile=test_dir / f"certs/{client_type}-client.key",
    )
    context.check_hostname = False

    with socket.create_connection((host, 6514)) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls_sock:
            syslog_message = f"test-client testlogger: {message}\n"
            tls_sock.sendall(syslog_message.encode("utf-8"))
            tls_sock.shutdown(socket.SHUT_RDWR)
            tls_sock.close()
            return True

    return False


async def get_wazuh_ip() -> str:
    """Returns Wazuh server IP
    Not sure why: the applications["wazuh-server"].units[0] returns None.

    Returns:
        str: the IP of the Wazuh server.

    Raises:
        RuntimeError: if the Wazuh server is unreachable.
    """
    output = sh.juju(  # pylint: disable=no-member
        "show-unit",
        "wazuh-server/0",
        format="yaml",
    )
    output = yaml.safe_load(output)["wazuh-server/0"]
    if "address" not in output:
        raise RuntimeError("Wazuh server is down, no IP found.")
    return output["address"]


async def found_in_logs(pattern: str) -> bool:
    """Grep logs on the server to see if a pattern is found.

    Args:
        pattern: the pattern to look for

    Returns:
        bool: True if the pattern was found
    """
    try:
        sh.juju.ssh(  # pylint: disable=no-member
            "--container=wazuh-server", "wazuh-server/0", f"grep {pattern} /tmp/rsyslog.log"
        )
        return True
    except sh.ErrorReturnCode_1:  # pylint: disable=no-member
        return False


async def configure_single_node(machine_model_name: str) -> None:
    """Call the shell helper to configure wazuh-indexer for single node mode

    Args:
        machine_model_name: name of the machine model to initially switch to
    """
    logger.info("Configure single node")
    sh.bash(  # pylint: disable=too-many-function-args
        Path(__file__).parent / "config_single_node_index.sh",
        machine_model_name,
    )
