# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""The Certificates relation observer."""

import logging
import secrets

import charms.tls_certificates_interface.v1.tls_certificates as certificates
import ops
from ops.framework import Object

import wazuh

logger = logging.getLogger(__name__)


class CertificatesObserver(Object):
    """The Certificates relation observer."""

    def __init__(self, charm: ops.CharmBase):
        """Initialize the observer and register event handlers.

        Args:
            charm: The parent charm to attach the observer to.
        """
        super().__init__(charm, "certificates")
        self._charm = charm
        self.private_key = secrets.token_urlsafe(20)
        self.certificates = certificates.TLSCertificatesRequiresV1(self._charm, "certificates")
        self.framework.observe(
            self._charm.on.certificates_relation_joined, self._on_certificates_relation_joined
        )
        self.framework.observe(
            self.certificates.on.certificate_available, self._on_certificate_available
        )
        self.framework.observe(
            self.certificates.on.certificate_expiring, self._on_certificate_expiring
        )
        self.framework.observe(
            self.certificates.on.certificate_revoked, self._on_certificate_revoked
        )

    def _request_certificate(self) -> None:
        """Send a certificate request."""
        csr = certificates.generate_csr(
            private_key=self.private_key.encode(), subject=self._charm.unit.name
        )

        self.certificates.request_certificate_creation(
            certificate_signing_request=csr.decode().removesuffix("\n")
        )

    def _on_certificates_relation_joined(self, _: ops.RelationJoinedEvent) -> None:
        """Relation joined event handler."""
        self._request_certificate()

    def _on_certificate_available(self, event: certificates.CertificateAvailableEvent) -> None:
        """Certificate available event handler.

        Args:
            event: the event triggering the handler.
        """
        wazuh.install_certificates(
            self._charm.unit.containers.get("wazuh-server"), self.private_key, event.certificate
        )

    def _on_certificate_expiring(self, _: certificates.CertificateExpiringEvent) -> None:
        """Certificate expired event handler."""
        self._request_certificate()
        logger.debug("Certificate expired.")
        self._charm.unit.status = ops.WaitingStatus("Waiting for a new certificate to be issued.")

    def _on_certificate_revoked(self, _: certificates.CertificateRevokedEvent) -> None:
        """Certificate revoked event handler."""
        self._request_certificate()
        logger.debug("Certificate revoked.")
        self._charm.unit.status = ops.WaitingStatus("Waiting for a new certificate to be issued.")
