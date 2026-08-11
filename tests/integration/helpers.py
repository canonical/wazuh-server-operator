# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Integration test helpers."""

import asyncio
import base64
import datetime
import json
import logging
import socket
import ssl
import time
from pathlib import Path

import sh
import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
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

    with (
        socket.create_connection((host, 6514)) as sock,
        context.wrap_socket(sock, server_hostname=host) as tls_sock,
    ):
        syslog_message = f"test-client testlogger: {message}\n"
        tls_sock.sendall(syslog_message.encode("utf-8"))
        return True

    return False


async def get_wazuh_ip(model_url: str) -> str:
    """Returns Wazuh server IP
    Not sure why: the applications["wazuh-server"].units[0] returns None.

    Args:
        model_url: model containing wazuh-server in format <controller>:<model>

    Returns:
        str: the IP of the Wazuh server.

    Raises:
        RuntimeError: if the Wazuh server is unreachable.
    """
    output = sh.juju(  # pylint: disable=no-member
        "show-unit",
        "wazuh-server/0",
        "-m",
        model_url,
        format="yaml",
    )
    output = yaml.safe_load(output)["wazuh-server/0"]
    if "address" not in output:
        raise RuntimeError("Wazuh server is down, no IP found.")
    return output["address"]


async def found_in_logs(
    pattern: str, model_name: str, unit_name: str, timeout: float = 0.0
) -> bool:
    """Grep logs on the server to see if a pattern is found.

    Args:
        pattern: the pattern to look for
        model_name: the name of the Juju model.
        unit_name: the name of the unit.
        timeout: seconds to keep polling if not found immediately. Defaults to 0 (single check).

    Returns:
        bool: True if the pattern was found
    """
    deadline = time.monotonic() + timeout
    while True:
        try:
            sh.juju.ssh(  # pylint: disable=no-member
                "-m",
                model_name,
                "--container=wazuh-server",
                unit_name,
                f"grep -F -- {pattern} /var/log/collectors/rsyslog/rsyslog.log",
            )
            return True
        except sh.ErrorReturnCode_1:  # pylint: disable=no-member
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            await asyncio.sleep(min(1.0, remaining))


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


def _pem(certificate: x509.Certificate) -> str:
    return certificate.public_bytes(serialization.Encoding.PEM).decode()


def _b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def _common_name(name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])


def _certificate(subject, public_key, issuer, signing_key, ca):
    # Key-usage/EKU are omitted on purpose: an absent extension means "unrestricted" in X.509,
    # which keeps these test certificates minimal while still validating against the root.
    now = datetime.datetime.now(datetime.timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .sign(signing_key, hashes.SHA256())
    )


class RsyslogCertificateAuthority:
    """A runtime root+intermediate CA whose signed leaf forms a 3-element chain."""

    def __init__(self) -> None:
        root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        root = _certificate(
            _common_name("wazuh-it-root"),
            root_key.public_key(),
            _common_name("wazuh-it-root"),
            root_key,
            True,
        )
        self._intermediate_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self._intermediate = _certificate(
            _common_name("wazuh-it-intermediate"),
            self._intermediate_key.public_key(),
            root.subject,
            root_key,
            True,
        )
        self.root_certificate = _pem(root)
        # Issuer-first (root then intermediate): the order manual-tls-certificates validates.
        self.ca_chain_pem = _pem(root) + _pem(self._intermediate)

    def sign_csr(self, csr_pem: str) -> str:
        csr = x509.load_pem_x509_csr(csr_pem.encode())
        leaf = _certificate(
            csr.subject,
            csr.public_key(),
            self._intermediate.subject,
            self._intermediate_key,
            False,
        )
        return _pem(leaf)


def _run_manual_tls_action(model_url: str, action: str, *params: str) -> dict:
    output = sh.juju.run(  # pylint: disable=no-member
        "manual-tls-certificates/0", action, *params, "--no-color", model=model_url, format="yaml"
    )
    return yaml.safe_load(output)["manual-tls-certificates/0"]["results"]


async def provision_rsyslog_certificates(
    model_url: str, ca: RsyslogCertificateAuthority, timeout: float = 180.0
) -> int:
    """Sign every outstanding rsyslog CSR through manual-tls-certificates (it never auto-issues).

    Polls until at least one certificate has been provided and none remain outstanding.
    """
    deadline = time.monotonic() + timeout
    num_provided = 0
    while True:
        results = _run_manual_tls_action(model_url, "get-outstanding-certificate-requests")
        requests = json.loads(results["result"])
        for request in requests:
            _run_manual_tls_action(
                model_url,
                "provide-certificate",
                f"relation-id={request['relation_id']}",
                f"certificate-signing-request={_b64(request['csr'])}",
                f"certificate={_b64(ca.sign_csr(request['csr']))}",
                f"ca-certificate={_b64(ca.root_certificate)}",
                f"ca-chain={_b64(ca.ca_chain_pem)}",
            )
            num_provided += 1
        if num_provided and not requests:
            return num_provided
        if time.monotonic() >= deadline:
            raise TimeoutError(
                f"Provided only {num_provided} rsyslog certificate(s) before timeout"
            )
        await asyncio.sleep(5)
