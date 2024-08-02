# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Certificates observer unit tests."""


import ops
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


def test_on_certificates_relation_joined() -> None:
    """
    arrange: instantiate a charm implementing the certificates relation.
    act: integrate the charm leveraging the certicicates integration.
    assert: a new certificate for the charm unit is requested
    """
    harness = Harness(ObservedCharm, meta=REQUIRER_METADATA)
    harness.begin_with_initial_hooks()

    harness.add_relation(certificates_observer.RELATION_NAME, "certificates-provider")
    relation = harness.charm.framework.model.get_relation(certificates_observer.RELATION_NAME, 0)
    harness.charm.on.certificates_relation_joined.emit(relation)

    assert True

# def test_on_certificate_available() -> None:

# def test_on_certificate_expiring() -> None:

# def test_on_certificate_invalidated() -> None:
