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


WAZUH_CLUSTER_KEY_SECRET_LABEL = "wazuh-cluster-key"  # nosec


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
        agent_password: the secret key corresponding to the agent secret.
        custom_config_repository: the git repository where the configuration is.
        custom_config_ssh_key: the secret key corresponding to the SSH key for the git repository.
    """

    agent_password: typing.Optional[str] = None
    custom_config_repository: typing.Optional[AnyUrl] = None
    custom_config_ssh_key: typing.Optional[str] = None


def _fetch_filebeat_configuration(
    model: ops.Model, indexer_relation_data: dict[str, str]
) -> tuple[str, str, list[str]]:
    """Fetch the filebeat configuration from the relation data.

    Args:
        model: the Juju model.
        indexer_relation_data: the Wazuh indexer app relation data.

    Returns: a tuple with the username, password and a list of endpoints.

    Raises:
        InvalidStateError: if the secret is invalid.
    """
    filebeat_secret_id = indexer_relation_data.get("secret-user")
    try:
        filebeat_secret_content = model.get_secret(id=filebeat_secret_id).get_content()
    except ops.SecretNotFoundError as exc:
        raise InvalidStateError("Indexer secret content not found.") from exc
    filebeat_username = filebeat_secret_content.get("username", "")
    filebeat_password = filebeat_secret_content.get("password", "")
    endpoint_data = indexer_relation_data.get("endpoints")
    endpoints = list(endpoint_data.split(",")) if endpoint_data else []
    return filebeat_username, filebeat_password, endpoints


def _fetch_matching_certificates(
    provider_certificates: list[certificates.ProviderCertificate],
    certitificate_signing_request: str,
) -> list[certificates.ProviderCertificate]:
    """Fetch the certificates matching the CSR from the relation data.

    Args:
        provider_certificates: the provider certificates.
        certitificate_signing_request: the certificate signing request.

    Returns:
        the certificates matching the CSR.
    """
    return [
        certificate
        for certificate in provider_certificates
        if certificate.csr.replace("\n", "") == certitificate_signing_request.replace("\n", "")
        and not certificate.revoked
    ]


def _fetch_ssh_repository_key(model: ops.Model, config: WazuhConfig) -> str | None:
    """Fetch the SSH key for the repository.

    Args:
        model: the Juju model.
        config: the charm configuration.

    Returns: the SSH key for the repository, if any.

    Raises:
        InvalidStateError: if the secret when the key should reside is invalid.
    """
    custom_config_ssh_key_content = None
    if config.custom_config_ssh_key:
        try:
            custom_config_ssh_key_secret = model.get_secret(id=config.custom_config_ssh_key)
        except ops.SecretNotFoundError as exc:
            raise InvalidStateError("Repository secret not found.") from exc
        custom_config_ssh_key_content = custom_config_ssh_key_secret.get_content(refresh=True).get(
            "value"
        )
        if not custom_config_ssh_key_content:
            raise InvalidStateError("Repository secret does not contain the expected key 'value'.")
    return custom_config_ssh_key_content


def _fetch_agent_password(model: ops.Model, config: WazuhConfig) -> str | None:
    """Fetch the password for the agent.

    Args:
        model: the Juju model.
        config: the charm configuration.

    Returns: the SSH key for the repository, if any.

    Raises:
        InvalidStateError: if the secret when the key should reside is invalid.
    """
    agent_password_content = None
    if config.agent_password:
        try:
            agent_password_secret = model.get_secret(id=config.agent_password)
        except ops.SecretNotFoundError as exc:
            raise InvalidStateError("Agent secret not found.") from exc
        agent_password_content = agent_password_secret.get_content(refresh=True).get("value")
        if not agent_password_content:
            raise InvalidStateError("Agent secret does not contain the expected key 'value'.")
    return agent_password_content


def _fetch_cluster_key(model: ops.Model) -> str:
    """Fetch the Wazuh cluster key.

    Args:
        model: the Juju model.

    Returns: the key for the cluster, if any.

    Raises:
        InvalidStateError: if the secret when the key should reside is invalid.
    """
    try:
        cluster_key_secret = model.get_secret(label=WAZUH_CLUSTER_KEY_SECRET_LABEL)
    except ops.SecretNotFoundError as exc:
        raise InvalidStateError("Cluster key secret.") from exc
    cluster_key_content = cluster_key_secret.get_content(refresh=True).get("value")
    if not cluster_key_content:
        raise InvalidStateError("Cluster key secret does not contain the expected key 'value'.")
    return cluster_key_content


class State(BaseModel):  # pylint: disable=too-few-public-methods
    """The Wazuh server charm state.

    Attributes:
        agent_password: the agent password.
        cluster_key: the cluster key.
        indexer_ips: list of Wazuh indexer IPs.
        filebeat_username: the filebeat username.
        filebeat_password: the filebeat password.
        certificate: the TLS certificate.
        root_ca: the CA certificate.
        custom_config_repository: the git repository where the configuration is.
        custom_config_ssh_key: the SSH key for the git repository.
        proxy: proxy configuration.
    """

    agent_password: typing.Optional[str] = None
    cluster_key: str = Field(min_length=16, max_length=16)
    indexer_ips: typing.Annotated[list[str], Field(min_length=1)]
    filebeat_username: str = Field(..., min_length=1)
    filebeat_password: str = Field(..., min_length=1)
    certificate: str = Field(..., min_length=1)
    root_ca: str = Field(..., min_length=1)
    custom_config_repository: typing.Optional[AnyUrl] = None
    custom_config_ssh_key: typing.Optional[str] = None

    def __init__(  # pylint: disable=too-many-arguments, too-many-positional-arguments
        self,
        agent_password: typing.Optional[str],
        cluster_key: str,
        indexer_ips: list[str],
        filebeat_username: str,
        filebeat_password: str,
        certificate: str,
        root_ca: str,
        wazuh_config: WazuhConfig,
        custom_config_ssh_key: typing.Optional[str],
    ):
        """Initialize a new instance of the CharmState class.

        Args:
            agent_password: the agent password.
            cluster_key: the cluster key.
            indexer_ips: list of Wazuh indexer IPs.
            filebeat_username: the filebeat username.
            filebeat_password: the filebeat password.
            certificate: the TLS certificate.
            root_ca: the CA certificate.
            wazuh_config: Wazuh configuration.
            custom_config_ssh_key: the SSH key for the git repository.
        """
        super().__init__(
            agent_password=agent_password,
            cluster_key=cluster_key,
            indexer_ips=indexer_ips,
            filebeat_username=filebeat_username,
            filebeat_password=filebeat_password,
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
    def from_charm(  # pylint: disable=too-many-locals
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
            filebeat_username, filebeat_password, endpoints = _fetch_filebeat_configuration(
                charm.model, indexer_relation_data
            )
            args = {key.replace("-", "_"): value for key, value in charm.config.items()}
            # mypy doesn't like the str to Url casting
            valid_config = WazuhConfig(**args)  # type: ignore
            custom_config_ssh_key = _fetch_ssh_repository_key(charm.model, valid_config)
            agent_password = _fetch_agent_password(charm.model, valid_config)
            cluster_key = _fetch_cluster_key(charm.model)
            matching_certificates = _fetch_matching_certificates(
                provider_certificates, certitificate_signing_request
            )
            if matching_certificates:
                return cls(
                    agent_password=agent_password,
                    cluster_key=cluster_key,
                    indexer_ips=endpoints,
                    filebeat_username=filebeat_username,
                    filebeat_password=filebeat_password,
                    certificate=matching_certificates[0].certificate,
                    root_ca=matching_certificates[0].ca,
                    wazuh_config=valid_config,
                    custom_config_ssh_key=custom_config_ssh_key,
                )
            raise InvalidStateError("Certificate is empty.")
        except ValidationError as exc:
            error_fields = set(
                itertools.chain.from_iterable(error["loc"] for error in exc.errors())
            )
            error_field_str = " ".join(f"{f}" for f in error_fields)
            raise InvalidStateError(f"Invalid charm configuration {error_field_str}") from exc
