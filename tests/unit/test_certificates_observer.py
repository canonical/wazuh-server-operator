# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Certificates observer unit tests."""


import unittest

import ops
import pytest
from ops.testing import Harness

import certificates_observer

REQUIRER_METADATA = """
name: observer-charm
requires:
  certificates:
    interface: tls-certificates
"""


class ObservedCharm(ops.CharmBase):
    """Class for requirer charm testing."""

    def __init__(self, *args):
        """Construct.

        Args:
            args: Variable list of positional arguments passed to the parent constructor.
        """
        super().__init__(*args)
        self.certificates = certificates_observer.CertificatesObserver(self)
        self.count = 0

    def reconcile(self) -> None:
        """Reconcile the configuration with charm state."""
        self.count = self.count + 1


def test_on_certificates_relation_joined(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    arrange: instantiate a charm implementing the certificates relation.
    act: integrate the charm leveraging the certificates integration.
    assert: assert: a new certificate unit is requested and the charms reaches active status.
    """
    harness = Harness(ObservedCharm, meta=REQUIRER_METADATA)
    harness.begin_with_initial_hooks()
    harness.add_relation(certificates_observer.RELATION_NAME, "certificates-provider")
    relation = harness.charm.framework.model.get_relation(certificates_observer.RELATION_NAME, 0)
    mock = unittest.mock.Mock()
    monkeypatch.setattr(
        harness.charm.certificates.certificates, "request_certificate_creation", mock
    )

    harness.charm.on.certificates_relation_joined.emit(relation)

    mock.assert_called_once()
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
    harness.add_relation(certificates_observer.RELATION_NAME, "certificates-provider")

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
    harness.add_relation(certificates_observer.RELATION_NAME, "certificates-provider")
    mock = unittest.mock.Mock()
    monkeypatch.setattr(
        harness.charm.certificates.certificates, "request_certificate_creation", mock
    )

    harness.charm.certificates.certificates.on.certificate_expiring.emit(
        certificate="certificate", expiry="2024-04-04"
    )

    mock.assert_called_once()
    assert ops.WaitingStatus.name == harness.charm.unit.status.name


def test_on_certificate_invalidated(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    arrange: instantiate a charm implementing the certificates relation.
    act: integrate the charm leveraging the certicicates integration and trigger an invalidated
        certificate event.
    assert: a new certificate unit is requested and the charms reaches waiting status
    """
    harness = Harness(ObservedCharm, meta=REQUIRER_METADATA)
    harness.begin_with_initial_hooks()

    harness.add_relation(certificates_observer.RELATION_NAME, "certificates-provider")
    mock = unittest.mock.Mock()
    monkeypatch.setattr(
        harness.charm.certificates.certificates, "request_certificate_creation", mock
    )

    harness.charm.certificates.certificates.on.certificate_invalidated.emit(
        reason="revoked",
        certificate_signing_request="csr",
        certificate="certificate",
        ca="ca",
        chain=[],
    )

    mock.assert_called_once()
    assert ops.WaitingStatus.name == harness.charm.unit.status.name
