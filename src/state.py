# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Wazuh server charm state."""

import itertools
import logging
import os
import typing
from abc import ABC, abstractmethod

import charms.tls_certificates_interface.v3.tls_certificates as certificates
import ops
from pydantic import AnyHttpUrl, AnyUrl, BaseModel, Field, ValidationError, parse_obj_as

logger = logging.getLogger(__name__)


class CharmBaseWithState(ops.CharmBase, ABC):
    """CharmBase than can build a CharmState."""

    @abstractmethod
    def reconcile(self) -> None:
        """Reconcile configuration."""


class InvalidStateError(Exception):
    """Exception raised when a charm configuration is found to be invalid."""


class ProxyConfig(BaseModel):  # pylint: disable=too-few-public-methods
    """Proxy configuration.

    Attributes:
        http_proxy: The http proxy URL.
        https_proxy: The https proxy URL.
        no_proxy: Comma separated list of hostnames to bypass proxy.
    """

    http_proxy: typing.Optional[AnyHttpUrl]
    https_proxy: typing.Optional[AnyHttpUrl]
    no_proxy: typing.Optional[str]


class WazuhConfig(BaseModel):  # pylint: disable=too-few-public-methods
    """The Wazuh server charm configuration.

    Attributes:
        custom_config_repository: the git repository where the configuration is.
        custom_config_ssh_key: the secret key corresponding to SSH key for the git repository.
    """

    custom_config_repository: typing.Optional[AnyUrl] = None
    custom_config_ssh_key: typing.Optional[str] = None


class State(BaseModel):  # pylint: disable=too-few-public-methods
    """The Wazuh server charm state.

    Attributes:
        indexer_ips: list of Wazuh indexer IPs.
        username: the filebeat username.
        password: the filebeat password.
        certificate: the TLS certificate.
        root_ca: the CA certificate.
        custom_config_repository: the git repository where the configuration is.
        custom_config_ssh_key: the SSH key for the git repository.
        proxy: proxy configuration.
    """

    indexer_ips: typing.Annotated[list[str], Field(min_length=1)]
    username: str = Field(..., min_length=1)
    password: str = Field(..., min_length=1)
    certificate: str = Field(..., min_length=1)
    root_ca: str = Field(..., min_length=1)
    custom_config_repository: typing.Optional[AnyUrl] = None
    custom_config_ssh_key: typing.Optional[str] = None

    def __init__(  # pylint: disable=too-many-arguments, too-many-positional-arguments
        self,
        indexer_ips: list[str],
        username: str,
        password: str,
        certificate: str,
        root_ca: str,
        wazuh_config: WazuhConfig,
        custom_config_ssh_key: typing.Optional[str],
    ):
        """Initialize a new instance of the CharmState class.

        Args:
            indexer_ips: list of Wazuh indexer IPs.
            username: the filebeat username.
            password: the filebeat password.
            certificate: the TLS certificate.
            root_ca: the CA certificate.
            wazuh_config: Wazuh configuration.
            custom_config_ssh_key: the SSH key for the git repository.
        """
        super().__init__(
            indexer_ips=indexer_ips,
            username=username,
            password=password,
            certificate=certificate,
            root_ca=root_ca,
            custom_config_repository=wazuh_config.custom_config_repository,
            custom_config_ssh_key=custom_config_ssh_key,
        )

    @property
    def proxy(self) -> "ProxyConfig":
        """Get charm proxy configuration from juju charm environment.

        Returns:
            charm proxy configuration in the form of ProxyConfig.

        Raises:
            InvalidStateError: if the proxy configuration is invalid.
        """
        http_proxy = os.environ.get("JUJU_CHARM_HTTP_PROXY")
        https_proxy = os.environ.get("JUJU_CHARM_HTTPS_PROXY")
        no_proxy = os.environ.get("JUJU_CHARM_NO_PROXY")
        try:
            return ProxyConfig(
                http_proxy=parse_obj_as(AnyHttpUrl, http_proxy) if http_proxy else None,
                https_proxy=parse_obj_as(AnyHttpUrl, https_proxy) if https_proxy else None,
                no_proxy=no_proxy,
            )
        except ValidationError as exc:
            raise InvalidStateError("Invalid proxy configuration.") from exc

    @classmethod
    def from_charm(  # pylint: disable=unused-argument, too-many-locals
        cls,
        charm: ops.CharmBase,
        indexer_relation_data: dict[str, str],
        provider_certificates: list[certificates.ProviderCertificate],
        certitificate_signing_request: str,
    ) -> "State":
        """Initialize the state from charm.

        Args:
            charm: the root charm.
            indexer_relation_data: the Wazuh indexer app relation data.
            provider_certificates: the provider certificates.
            certitificate_signing_request: the certificate signing request.

        Returns:
            Current state of the charm.

        Raises:
            InvalidStateError: if the state is invalid.
        """
        try:
            secret_id = indexer_relation_data.get("secret-user")
            try:
                secret_content = charm.model.get_secret(id=secret_id).get_content()
            except ops.SecretNotFoundError as exc:
                raise InvalidStateError("Indexer secret not found.") from exc
            username = secret_content.get("username", "")
            password = secret_content.get("password", "")
            endpoint_data = indexer_relation_data.get("endpoints")
            endpoints = list(endpoint_data.split(",")) if endpoint_data else []
            args = {key.replace("-", "_"): value for key, value in charm.config.items()}
            # mypy doesn't like the str to Url casting
            valid_config = WazuhConfig(**args)  # type: ignore
            custom_config_ssh_key_content = None
            if valid_config.custom_config_ssh_key:
                try:
                    custom_config_ssh_key_secret = charm.model.get_secret(
                        id=valid_config.custom_config_ssh_key
                    )
                except ops.SecretNotFoundError as exc:
                    raise InvalidStateError("Repository secret not found.") from exc
                custom_config_ssh_key_content = custom_config_ssh_key_secret.get_content(
                    refresh=True
                ).get("value")
                if not custom_config_ssh_key_content:
                    raise InvalidStateError("Secret does not contain the expected key 'value'.")
            matching_certificates = [
                certificate
                for certificate in provider_certificates
                if (
                    certificate.csr.replace("\n", "")
                    == certitificate_signing_request.replace("\n", "")
                )
                and not certificate.revoked
            ]
            if matching_certificates:
                return cls(
                    indexer_ips=endpoints,
                    username=username,
                    password=password,
                    certificate=matching_certificates[0].certificate,
                    root_ca=matching_certificates[0].ca,
                    wazuh_config=valid_config,
                    custom_config_ssh_key=custom_config_ssh_key_content,
                )
            raise InvalidStateError("Certificate is empty.")
        except ValidationError as exc:
            error_fields = set(
                itertools.chain.from_iterable(error["loc"] for error in exc.errors())
            )
            error_field_str = " ".join(f"{f}" for f in error_fields)
            raise InvalidStateError(f"Invalid charm configuration {error_field_str}") from exc
