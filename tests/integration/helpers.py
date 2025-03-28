# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Integration test helpers."""

import json
import logging
import socket
import ssl

import yaml
import sh
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


async def send_syslog_over_tls(message: str, host: str, server_ca: str) -> bool:
    """Send a syslog message over TLS."""
    context = ssl.create_default_context(cadata=server_ca)
    context.check_hostname = False

    with socket.create_connection((host, 6514)) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls_sock:
            syslog_message = f"{message}\n"
            tls_sock.sendall(syslog_message.encode("utf-8"))
            return True

    return False


async def get_ca_certificate() -> str:
    output = sh.juju.run(
        "self-signed-certificates/0",
        "get-ca-certificate",
        "--no-color",
        model="localhost:test-w-machine",
        format="yaml",
    )
    return yaml.safe_load(output)["self-signed-certificates/0"]["results"]["ca-certificate"]


async def get_wazuh_ip() -> str:
    output = sh.juju(
        "show-unit",
        "wazuh-server/0",
        format="yaml",
    )
    output = yaml.safe_load(output)["wazuh-server/0"]
    if "address" not in output:
        raise RuntimeError("Wazuh server is down, no IP found.")
    return output["address"]


async def found_in_logs(pattern: str) -> str:
    try:
        sh.juju.ssh(
            "--container=wazuh-server", "wazuh-server/0", f"grep {pattern} /tmp/rsyslog.log"
        )
        return True
    except sh.ErrorReturnCode_1:
        return False
