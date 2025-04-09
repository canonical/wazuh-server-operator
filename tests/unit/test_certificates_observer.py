# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.


"""Certificates observer unit tests."""

import secrets
from unittest.mock import MagicMock, Mock

import ops
import pytest
from ops.testing import Harness

import state
from certificates_observer import RELATION_NAME, CertificatesObserver

REQUIRER_METADATA = """
name: observer-charm
requires:
  certificates:
    interface: tls-certificates
"""


class ObservedCharm(state.CharmBaseWithState):
    """Class for requirer charm testing.

    Attrs:
        state: the charm state.
    """

    def __init__(self, *args):
        """Construct.

        Args:
            args: Variable list of positional arguments passed to the parent constructor.
        """
        super().__init__(*args)
        certificates = CertificatesObserver(self)
        self.certificates = certificates
        self.count = 0

    def reconcile(self, _: ops.HookEvent) -> None:
        """Reconcile the configuration with charm state."""
        self.count = self.count + 1

    @property
    def state(self) -> state.State | None:
        """The charm state."""
        password = secrets.token_hex()
        api_credentials = {
            "wazuh": secrets.token_hex(),
            "wazuh-wui": secrets.token_hex(),
            "prometheus": secrets.token_hex(),
        }
        cluster_key = secrets.token_hex(16)
        return state.State(
            agent_password=None,
            api_credentials=api_credentials,
            cluster_key=cluster_key,
            certificate="certificate",
            root_ca="root_ca",
            indexer_ips=["10.0.0.1"],
            filebeat_username="user1",
            filebeat_password=password,
            wazuh_config=state.WazuhConfig(
                api_credentials=api_credentials,
                custom_config_repository=None,
                custom_config_ssh_key=None,
                logs_ca_cert="fakeca",
            ),
            custom_config_ssh_key=None,
        )


def test_on_certificates_relation_joined(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    arrange: instantiate a charm implementing the certificates relation.
    act: integrate the charm leveraging the certificates integration.
    assert: assert: a new certificate unit is requested and the charms reaches active status.
    """
    harness = Harness(ObservedCharm, meta=REQUIRER_METADATA)
    harness.begin_with_initial_hooks()
    harness.add_relation(RELATION_NAME, "certificates-provider")
    relation = harness.charm.framework.model.get_relation(RELATION_NAME, 0)
    mock = Mock()
    monkeypatch.setattr(
        harness.charm.certificates.certificates, "request_certificate_creation", mock
    )
    monkeypatch.setattr(harness.charm.certificates, "get_csr", lambda: "csr")

    harness.charm.on.certificates_relation_joined.emit(relation)

    mock.assert_called_once_with(certificate_signing_request="csr")
    assert ops.WaitingStatus.name == harness.charm.unit.status.name


def test_on_certificate_available() -> None:
    """
    arrange: instantiate a charm implementing the certificates relation.
    act: integrate the charm leveraging the certificates integration and trigger an available
        certificate event.
    assert: the reconcile method is called.
    """
    harness = Harness(ObservedCharm, meta=REQUIRER_METADATA)
    harness.begin_with_initial_hooks()
    harness.add_relation(RELATION_NAME, "certificates-provider")

    harness.charm.certificates.certificates.on.certificate_available.emit(
        certificate_signing_request="csr",
        certificate="certificate",
        ca="ca",
        chain=[],
    )

    assert harness.charm.count == 1


def test_on_certificate_expired(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    arrange: instantiate a charm implementing the certificates relation.
    act: integrate the charm leveraging the certicicates integration and trigger an expired
        certificate event.
    assert: a new certificate unit is requested and the charms reaches waiting status
    """
    harness = Harness(ObservedCharm, meta=REQUIRER_METADATA)
    harness.begin_with_initial_hooks()
    harness.add_relation(RELATION_NAME, "certificates-provider")
    mock = Mock()
    monkeypatch.setattr(
        harness.charm.certificates.certificates, "request_certificate_creation", mock
    )
    monkeypatch.setattr(harness.charm.certificates, "get_csr", lambda: "csr")

    harness.charm.certificates.certificates.on.certificate_expiring.emit(
        certificate="certificate", expiry="2024-04-04"
    )

    mock.assert_called_once_with(certificate_signing_request="csr")


def test_on_certificate_invalidated(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    arrange: instantiate a charm implementing the certificates relation.
    act: integrate the charm leveraging the certicicates integration and trigger an invalidated
        certificate event.
    assert: a new certificate unit is requested and the charms reaches waiting status
    """
    harness = Harness(ObservedCharm, meta=REQUIRER_METADATA)
    harness.begin_with_initial_hooks()

    harness.add_relation(RELATION_NAME, "certificates-provider")
    mock = Mock()
    monkeypatch.setattr(
        harness.charm.certificates.certificates, "request_certificate_renewal", mock
    )
    secret_mock = MagicMock()
    monkeypatch.setattr(harness.charm.model, "get_secret", secret_mock)
    monkeypatch.setattr(
        harness.charm.certificates,
        "get_csr",
        lambda renew=False: "csr" if renew else "old_csr",
    )

    harness.charm.certificates.certificates.on.certificate_invalidated.emit(
        reason="revoked",
        certificate_signing_request="csr",
        certificate="certificate",
        ca="ca",
        chain=[],
    )

    mock.assert_called_once_with(
        old_certificate_signing_request="old_csr",
        new_certificate_signing_request="csr",
    )
    assert ops.WaitingStatus.name == harness.charm.unit.status.name
