# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""The Certificates relation observer."""

import logging

import charms.tls_certificates_interface.v3.tls_certificates as certificates
import ops
from ops.framework import Object

from state import CharmBaseWithState, IncompleteStateError

logger = logging.getLogger(__name__)
RELATION_NAME = "certificates"
SECRET_LABEL = "certificates-secret"  # nosec


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
        self.framework.observe(
            self._charm.on.certificates_relation_broken, self._on_certificates_relation_broken
        )

    def get_private_key(self, renew: bool = False) -> str:
        """Fetch the private key for filebeat.

        Args:
            renew: whether to generate a new private key.

        Returns: the private key.
        """
        return self._get_private_key(label=SECRET_LABEL, renew=renew)

    def _get_private_key(self, label: str, renew: bool) -> str:
        """Fetch the private key.

        Args:
            label: the label identifying the private key.
            renew: whether to generate a new private key.

        Returns: the private key.
        """
        private_key = None
        try:
            secret = self._charm.model.get_secret(label=label)
            content = secret.get_content()
            if not content or renew:
                private_key = certificates.generate_private_key().decode()
                content["key"] = private_key
                if dict(secret.get_content(refresh=True)) != content:
                    secret.set_content(content=content)
            private_key = secret.get_content().get("key")
        except ops.SecretNotFoundError:
            logger.debug("Secret for private key not found. One will be generated.")
            private_key = certificates.generate_private_key().decode()
            self._charm.app.add_secret(content={"key": private_key}, label=label)
        return private_key

    def get_csr(self, renew: bool = False) -> bytes:
        """Fetch the certificate signing request for filebeat.

        Args:
            renew: whether to generate a new certificate signing request.

        Returns: the certificate signing request.

        Raises:
            IncompleteStateError: if the external hostname is not yet available.
        """
        subject = self._charm.external_hostname
        if not subject:
            raise IncompleteStateError("External hostname is not yet present.")
        return self._get_certificate_signing_request(
            label=SECRET_LABEL,
            subject=subject,
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
            content = secret.get_content()
            if "csr" not in content or renew:
                csr = certificates.generate_csr(
                    private_key=self._get_private_key(label=label, renew=renew).encode(),
                    subject=subject,
                )
            else:
                csr = content.get("csr").encode("utf-8")
        except ops.SecretNotFoundError:
            logger.debug("Secret for private key not found. One will be generated.")
            csr = certificates.generate_csr(
                private_key=self._get_private_key(label=label, renew=renew).encode(),
                subject=subject,
            )
        # Private key generation will add the secret when called by the first time
        secret = self._charm.model.get_secret(label=label)
        content = secret.get_content()
        content["csr"] = csr.decode("utf-8")
        if dict(secret.get_content(refresh=True)) != content:
            secret.set_content(content=content)
        return csr

    def _on_certificates_relation_joined(self, event: ops.RelationJoinedEvent) -> None:
        """Relation joined event handler."""
        try:
            self.certificates.request_certificate_creation(
                certificate_signing_request=self.get_csr()
            )
            self._charm.unit.status = ops.WaitingStatus(
                "Certificates do not exist. Waiting for new certificates to be issued."
            )
        except IncompleteStateError:
            self._charm.unit.status = ops.WaitingStatus("Charm not ready to make a CSR.")
            event.defer()

    def _on_certificates_relation_broken(self, _: ops.RelationBrokenEvent) -> None:
        """Relation broken event handler."""
        try:
            secret = self._charm.model.get_secret(label=SECRET_LABEL)
            secret.remove_all_revisions()
        except ops.SecretNotFoundError:
            logger.debug("Secret for private key not found. Skipping deletion.")

    def _on_certificate_expiring(self, event: certificates.CertificateExpiringEvent) -> None:
        """Certificate expiring event handler.

        Args:
            event: the event triggering the handler.
        """
        if event.certificate == self._charm.state.certificate:
            try:
                self.certificates.request_certificate_creation(
                    certificate_signing_request=self.get_csr()
                )
                logger.debug("TLS certificate expiring. Requested new certificate.")
            except IncompleteStateError:
                self._charm.unit.status = ops.WaitingStatus(
                    "Charm not ready to renew expired certificate."
                )
                event.defer()

    def _on_certificate_invalidated(self, event: certificates.CertificateInvalidatedEvent) -> None:
        """Certificate invalidated event handler.

        Args:
            event: the event triggering the handler.
        """
        if event.certificate == self._charm.state.certificate:
            try:
                self.certificates.request_certificate_renewal(
                    old_certificate_signing_request=self.get_csr(),
                    new_certificate_signing_request=self.get_csr(renew=True),
                )
                logger.debug("TLS certificate invalidated.")
                self._charm.unit.status = ops.WaitingStatus(
                    "Certificate invalidated. Waiting for new certificate to be issued."
                )
            except IncompleteStateError:
                self._charm.unit.status = ops.WaitingStatus(
                    "Charm not ready to renew the certificate."
                )
                event.defer()
