# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""The Certificates relation observer."""

import logging

import charms.tls_certificates_interface.v3.tls_certificates as certificates
import ops
from ops.framework import Object

from state import CharmBaseWithState

logger = logging.getLogger(__name__)
RELATION_NAME = "certificates"


class CertificatesObserver(Object):
    """The Certificates relation observer.

    Attributes:
        filebeat_private_key: the private key for the certificates.
        filebeat_csr: the certificate signing request.
    """

    def __init__(self, charm: CharmBaseWithState):
        """Initialize the observer and register event handlers.

        Args:
            charm: The parent charm to attach the observer to.
        """
        super().__init__(charm, RELATION_NAME)
        self._charm = charm
        self.certificates = certificates.TLSCertificatesRequiresV3(self._charm, RELATION_NAME)
        self.framework.observe(
            self._charm.on.certificates_relation_joined, self._on_certificates_relation_joined
        )
        self.framework.observe(self.certificates.on.certificate_available, self._charm.reconcile)
        self.framework.observe(
            self.certificates.on.certificate_expiring, self._on_certificate_expiring
        )
        self.framework.observe(
            self.certificates.on.certificate_invalidated, self._on_certificate_invalidated
        )

    @property
    def filebeat_private_key(self) -> str:
        """Fetch the private key.

        Returns: the private key.
        """
        return self._get_private_key("certificate-private-key")

    def _get_private_key(self, label: str) -> str:
        """Fetch the private key.

        Attrs:
            label: the label identifying the private key.

        Returns: the private key.
        """
        private_key = None
        try:
            secret = self._charm.model.get_secret(label=label)
            private_key = secret.get_content().get("key")
        except ops.SecretNotFoundError:
            logger.debug("Secret for private key not found. One will be generated.")
            private_key = certificates.generate_private_key().decode()
            self._charm.app.add_secret(content={"key": private_key}, label=label)
        return private_key

    @property
    def filebeat_csr(self) -> bytes:
        """Fetch the certificate signing request.

        Returns: the certificate signing request.
        """
        return self._get_certificate_signing_request("certificate-csr")

    def _get_certificate_signing_request(self, label: str) -> bytes:
        """Fetch a certificate signing request.

        Attrs:
            label: the label identifying the certificate signing request.

        Returns: the certificate signing request.
        """
        csr = None
        try:
            secret = self._charm.model.get_secret(label=label)
            csr = secret.get_content().get("csr").encode("utf-8")
        except ops.SecretNotFoundError:
            logger.debug("Secret for private key not found. One will be generated.")
            csr = certificates.generate_csr(
                private_key=self.filebeat_private_key.encode(), subject=self._charm.unit.name
            )
            self._charm.app.add_secret(content={"csr": csr.decode("utf-8")}, label=label)
        return csr

    def _request_certificate(self) -> None:
        """Send a certificate request."""
        self.certificates.request_certificate_creation(
            certificate_signing_request=self.filebeat_csr
        )

    def _renew_certificate(self) -> None:
        """Send a certificate renewal request."""
        old_csr = self.filebeat_csr
        secret = self._charm.model.get_secret(label="certificate-csr")
        secret.remove_all_revisions()
        secret = self._charm.model.get_secret(label="certificate-private-key")
        secret.remove_all_revisions()
        self.certificates.request_certificate_renewal(
            old_certificate_signing_request=old_csr,
            new_certificate_signing_request=self.filebeat_csr,
        )

    def _on_certificates_relation_joined(self, _: ops.RelationJoinedEvent) -> None:
        """Relation joined event handler."""
        self._request_certificate()
        self._charm.unit.status = ops.WaitingStatus(
            "Certificate does not exist. Waiting for a new certificate to be issued."
        )

    def _on_certificate_expiring(self, _: certificates.CertificateExpiringEvent) -> None:
        """Certificate expiring event handler."""
        self._request_certificate()
        logger.debug("Certificate expiring. Requested new certificate.")

    def _on_certificate_invalidated(self, _: certificates.CertificateInvalidatedEvent) -> None:
        """Certificate invalidated event handler."""
        self._renew_certificate()
        logger.debug("Certificate invalidated.")
        self._charm.unit.status = ops.WaitingStatus(
            "Certificate invalidated. Waiting for a new certificate to be issued."
        )
