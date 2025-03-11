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
    """The Certificates relation observer."""

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

    def get_filebeat_private_key(self, renew: bool = False) -> str:
        """Fetch the private key for filebeat.

        Args:
            renew: whether to generate a new private key.

        Returns: the private key.
        """
        return self._get_private_key(label="filebeat-private-key", renew=renew)

    def get_syslog_private_key(self, renew: bool = False) -> str:
        """Fetch the private key for syslog.

        Args:
            renew: whether to generate a new private key.

        Returns: the private key.
        """
        return self._get_private_key(label="syslog-private-key", renew=renew)

    def _get_private_key(self, label: str, renew: bool) -> str:
        """Fetch the private key.

        Args:
            label: the label identifying the private key.
            renew: whether to generate a new private key.

        Returns: the private key.
        """
        if renew:
            secret = self._charm.model.get_secret(label=label)
            secret.remove_all_revisions()

        private_key = None
        try:
            secret = self._charm.model.get_secret(label=label)
            private_key = secret.get_content().get("key")
        except ops.SecretNotFoundError:
            logger.debug("Secret for private key not found. One will be generated.")
            private_key = certificates.generate_private_key().decode()
            self._charm.app.add_secret(content={"key": private_key}, label=label)
        return private_key

    def get_filebeat_csr(self, renew: bool = False) -> bytes:
        """Fetch the certificate signing request for filebeat.

        Args:
            renew: whether to generate a new certificate signing request.

        Returns: the certificate signing request.
        """
        return self._get_certificate_signing_request(
            label="filebeat-csr",
            subject=self._charm.traefik_route.traefik_route.external_host,
            renew=renew,
        )

    def get_syslog_csr(self, renew: bool = False) -> bytes:
        """Fetch the certificate signing request for syslog.

        Args:
            renew: whether to generate a new certificate signing request.

        Returns: the certificate signing request.
        """
        return self._get_certificate_signing_request(
            label="syslog-csr",
            subject=self._charm.traefik_route.traefik_route.external_host,
            renew=renew,
        )

    def _get_certificate_signing_request(self, subject: str, label: str, renew: bool) -> bytes:
        """Fetch a certificate signing request.

        Args:
            subject: the subject for the certificate signing request.
            label: the label identifying the certificate signing request.
            renew: whether to generate a new certificate signing request.

        Returns: the certificate signing request.
        """
        csr = None
        try:
            secret = self._charm.model.get_secret(label=label)
            if renew:
                csr = certificates.generate_csr(
                    private_key=self._get_private_key(label=label, renew=renew).encode(),
                    subject=subject,
                )
                secret.set_content(content={"csr": csr.decode("utf-8")})
            csr = secret.get_content().get("csr").encode("utf-8")
        except ops.SecretNotFoundError:
            logger.debug("Secret for private key not found. One will be generated.")
            csr = certificates.generate_csr(
                private_key=self._get_private_key(label=label, renew=renew).encode(),
                subject=subject,
            )
            self._charm.app.add_secret(content={"csr": csr.decode("utf-8")}, label=label)
        return csr

    def _on_certificates_relation_joined(self, _: ops.RelationJoinedEvent) -> None:
        """Relation joined event handler."""
        self.certificates.request_certificate_creation(
            certificate_signing_request=self.get_filebeat_csr()
        )
        self.certificates.request_certificate_creation(
            certificate_signing_request=self.get_syslog_csr()
        )
        self._charm.unit.status = ops.WaitingStatus(
            "Certificates do not exist. Waiting for new certificates to be issued."
        )

    def _on_certificate_expiring(self, event: certificates.CertificateExpiringEvent) -> None:
        """Certificate expiring event handler.

        Args:
            event: the event triggering the handler.
        """
        if event.certificate == self._charm.state.filebeat_certificate:
            self.certificates.request_certificate_creation(
                certificate_signing_request=self.get_filebeat_csr()
            )
            logger.debug("Filebat certificate expiring. Requested new certificate.")
        elif event.certificate == self._charm.state.syslog_certificate:
            self.certificates.request_certificate_creation(
                certificate_signing_request=self.get_syslog_csr()
            )
            logger.debug("Syslog certificate expiring. Requested new certificate.")

    def _on_certificate_invalidated(self, event: certificates.CertificateInvalidatedEvent) -> None:
        """Certificate invalidated event handler.

        Args:
            event: the event triggering the handler.
        """
        if event.certificate == self._charm.state.filebeat_certificate:
            self.certificates.request_certificate_renewal(
                old_certificate_signing_request=self.get_filebeat_csr(),
                new_certificate_signing_request=self.get_filebeat_csr(renew=True),
            )
            logger.debug("Filebat certificate invalidated.")
        elif event.certificate == self._charm.state.syslog_certificate:
            self.certificates.request_certificate_renewal(
                old_certificate_signing_request=self.get_syslog_csr(),
                new_certificate_signing_request=self.get_syslog_csr(renew=True),
            )
            logger.debug("Syslog certificate invalidated.")
        self._charm.unit.status = ops.WaitingStatus(
            "Certificate invalidated. Waiting for new certificate to be issued."
        )
