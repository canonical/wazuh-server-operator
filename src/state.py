# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Wazuh Server charm state."""

import itertools
import logging
import os
import typing
from abc import ABC, abstractmethod
from collections import OrderedDict

import charms.tls_certificates_interface.v3.tls_certificates as certificates
import ops
from pydantic import AnyHttpUrl, AnyUrl, BaseModel, Field, ValidationError, parse_obj_as

logger = logging.getLogger(__name__)


# Bandit mistakenly thinks these are passwords
WAZUH_API_CREDENTIAL_SECRET_LABEL = "wazuh-api-credentials"  # nosec
WAZUH_CLUSTER_KEY_SECRET_LABEL = "wazuh-cluster-key"  # nosec
WAZUH_USERS = OrderedDict(
    {
        "wazuh": {
            "default_password": "wazuh",
        },
        "wazuh-wui": {
            "default_password": "wazuh-wui",
        },
        # This user will be created by the charm
        "prometheus": {
            "default_password": "",
        },
    }
)


class InvalidStateError(Exception):
    """Exception raised when a charm configuration is invalid and unrecoverable by the operator."""


class RecoverableStateError(Exception):
    """Exception raised when a charm configuration is invalid and recoverable by the operator."""


class IncompleteStateError(Exception):
    """Exception raised when a charm configuration is invalid and automatically recoverable."""


class ProxyConfig(BaseModel):  # pylint: disable=too-few-public-methods
    """Proxy configuration.

    Attributes:
        http_proxy: The http proxy URL.
        https_proxy: The https proxy URL.
        no_proxy: Comma separated list of hostnames to bypass proxy.
    """

    http_proxy: AnyHttpUrl | None
    https_proxy: AnyHttpUrl | None
    no_proxy: str | None


class WazuhConfig(BaseModel):  # pylint: disable=too-few-public-methods
    """The Wazuh Server charm configuration.

    Attributes:
        agent_password: the secret key corresponding to the agent secret.
        custom_config_repository: the git repository where the configuration is.
        custom_config_ssh_key: the secret key corresponding to the SSH key for the git repository.
        enable_vulnerability_detection: whether to enable Wazuh's vulnerability detection module.
        logs_ca_cert: the CA used to authenticate rsyslog clients.
    """

    agent_password: str | None = None
    custom_config_repository: AnyUrl | None = None
    custom_config_ssh_key: str | None = None
    enable_vulnerability_detection: bool = True
    logs_ca_cert: str


def _fetch_filebeat_configuration(
    model: ops.Model, indexer_relation_data: dict[str, str]
) -> tuple[str, str, list[str], str]:
    """Fetch the filebeat configuration from the relation data.

    Args:
        model: the Juju model.
        indexer_relation_data: the Wazuh indexer app relation data.

    Returns: a tuple with the username, password, list of endpoints, and CA cert.

    Raises:
        InvalidStateError: if the secret is invalid.
        IncompleteStateError: if the secret has not yet been passed.
    """
    user_secret_id = indexer_relation_data.get("secret-user")
    ca_secret_id = indexer_relation_data.get("secret-tls")
    if not user_secret_id or not ca_secret_id:
        raise IncompleteStateError("Indexer secret IDs not yet in relation.")
    try:
        user_secret_content = model.get_secret(id=user_secret_id).get_content()
        tls_secret_content = model.get_secret(id=ca_secret_id).get_content()
    except ops.SecretNotFoundError as exc:
        raise InvalidStateError("Indexer secret content not found") from exc
    except ops.model.ModelError as exc:
        raise InvalidStateError(
            "Received ops.model.ModelError while requesting Indexer secret content"
        ) from exc
    filebeat_username = user_secret_content.get("username", "")
    filebeat_password = user_secret_content.get("password", "")
    filebeat_ca = ""
    ca_cert_text = tls_secret_content.get("tls-ca", "")
    if len(certs := ca_cert_text.split("-----BEGIN CERTIFICATE-----")) > 1:
        # split will result in ['', first_cert, second_cert, ...], we want the last
        filebeat_ca = ("-----BEGIN CERTIFICATE-----" + certs[-1]).strip()

    endpoint_data = indexer_relation_data.get("endpoints")
    endpoints = list(endpoint_data.split(",")) if endpoint_data else []
    return filebeat_username, filebeat_password, endpoints, filebeat_ca


def _fetch_opencti_details(
    model: ops.Model,
    opencti_relation_data: dict[str, str],
) -> tuple[str, str] | tuple[None, None]:
    """Fetch the OpenCTI details from the relation data.

    Args:
        model: the Juju model.
        opencti_relation_data: the OpenCTI relation data.

    Returns: a tuple with the OpenCTI URL and token.
    """
    opencti_url = opencti_relation_data.get("opencti_url")
    opencti_token_id = opencti_relation_data.get("opencti_token")
    opencti_token = (
        model.get_secret(id=opencti_token_id).get_content().get("token")
        if opencti_token_id
        else None
    )
    if opencti_token is None or opencti_url is None:
        return (None, None)
    return (opencti_url, opencti_token)


def _fetch_matching_certificates(
    provider_certificates: list[certificates.ProviderCertificate],
    certificate_signing_request: str,
) -> list[certificates.ProviderCertificate]:
    """Fetch the certificates matching the CSR from the relation data.

    Args:
        provider_certificates: the provider certificates.
        certificate_signing_request: the certificate signing request.

    Returns:
        the certificates matching the CSR.
    """
    csr_to_match = certificate_signing_request.replace("\n", "")
    matching_certificates = [
        certificate
        for certificate in provider_certificates
        if certificate.csr.replace("\n", "") == csr_to_match and not certificate.revoked
    ]

    abbreviated_csr = f"{csr_to_match[:80]}..."
    if not matching_certificates:
        logger.debug("Could not find matching certificate for CSR %s", abbreviated_csr)
    else:
        logger.debug("Found matching certificate for CSR %s", abbreviated_csr)

    return matching_certificates


def _fetch_ssh_repository_key(model: ops.Model, config: WazuhConfig) -> str | None:
    """Fetch the SSH key for the repository.

    Args:
        model: the Juju model.
        config: the charm configuration.

    Returns: the SSH key for the repository, if any.

    Raises:
        RecoverableStateError: if the secret when the key should reside is invalid.
    """
    custom_config_ssh_key_content = None
    if config.custom_config_ssh_key:
        try:
            custom_config_ssh_key_secret = model.get_secret(id=config.custom_config_ssh_key)
        except ops.SecretNotFoundError as exc:
            raise RecoverableStateError("Repository secret not found.") from exc
        custom_config_ssh_key_content = custom_config_ssh_key_secret.get_content(refresh=True).get(
            "value"
        )
        if not custom_config_ssh_key_content:
            raise RecoverableStateError(
                "Repository secret does not contain the expected key 'value'."
            )
    return custom_config_ssh_key_content


def _fetch_password(model: ops.Model, secret_id: str | None) -> str | None:
    """Fetch the password for the a given secret ID.

    Args:
        model: the Juju model.
        secret_id: the secret ID.

    Returns: the password stored in the secret, if any.

    Raises:
        RecoverableStateError: if the secret when the key should reside is invalid.
    """
    agent_password_content = None
    if secret_id:
        try:
            agent_password_secret = model.get_secret(id=secret_id)
        except ops.SecretNotFoundError as exc:
            raise RecoverableStateError("Agent secret not found.") from exc
        agent_password_content = agent_password_secret.get_content(refresh=True).get("value")
        if not agent_password_content:
            raise RecoverableStateError("Agent secret does not contain the expected key 'value'.")
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
        raise InvalidStateError("Cluster key secret not found.") from exc
    cluster_key_content = cluster_key_secret.get_content(refresh=True).get("value")
    if not cluster_key_content:
        raise InvalidStateError("Cluster key secret does not contain the expected key 'value'.")
    return cluster_key_content


def _fetch_api_credentials(model: ops.Model) -> dict[str, str]:
    """Fetch the Wazuh API credentials.

    Args:
        model: the Juju model.

    Returns: a map containing the users and credentials for the API.

    Raises:
        InvalidStateError: if the secret when the key should reside is invalid.
    """
    default_credentials = {
        username: str(details["default_password"]) for username, details in WAZUH_USERS.items()
    }
    try:
        api_credentials_secret = model.get_secret(label=WAZUH_API_CREDENTIAL_SECRET_LABEL)
        api_credentials_content = api_credentials_secret.get_content(refresh=True)
        if not api_credentials_content:
            raise InvalidStateError("API credentials secret is empty.")
        return {**default_credentials, **api_credentials_content}
    except ops.SecretNotFoundError:
        logger.debug("Secret wazuh-api-credentials not found. Using default values.")
        return default_credentials


class State(BaseModel):  # pylint: disable=too-few-public-methods
    """The Wazuh Server charm state.

    Attributes:
        agent_password: the agent password.
        api_credentials: a map containing the API credentials.
        rsyslog_public_cert: the public TLS certificate for rsyslog.
        cluster_key: the Wazuh key for the cluster nodes.
        indexer_endpoints: list of Wazuh indexer endpoints.
        filebeat_username: the filebeat username.
        filebeat_password: the filebeat password.
        filebeat_ca: the CA certificate for filebeat.
        custom_config_repository: the git repository where the configuration is.
        custom_config_ssh_key: the SSH key for the git repository.
        enable_vulnerability_detection: whether to enable Wazuh's vulnerability detection module.
        proxy: proxy configuration.
        logs_ca_cert: the CA to authenticate rssyslog clients.
        opencti_token: the OpenCTI token.
        opencti_url: the OpenCTI URL.
    """

    agent_password: str | None = None
    api_credentials: dict[str, str]
    rsyslog_public_cert: str = Field(..., min_length=1)
    cluster_key: str = Field(min_length=32, max_length=32)
    indexer_endpoints: typing.Annotated[list[str], Field(min_length=1)]
    filebeat_username: str = Field(..., min_length=1)
    filebeat_password: str = Field(..., min_length=1)
    filebeat_ca: str = Field(..., min_length=1)
    custom_config_repository: AnyUrl | None = None
    custom_config_ssh_key: str | None = None
    enable_vulnerability_detection: bool = True
    logs_ca_cert: str | None = None
    opencti_token: str | None = None
    opencti_url: str | None = None

    def __init__(  # pylint: disable=too-many-arguments, too-many-positional-arguments
        self,
        agent_password: str | None,
        api_credentials: dict[str, str],
        rsyslog_public_cert: str,
        cluster_key: str,
        indexer_endpoints: list[str],
        filebeat_username: str,
        filebeat_password: str,
        filebeat_ca: str,
        wazuh_config: WazuhConfig,
        custom_config_ssh_key: str | None,
        opencti_token: str | None = None,
        opencti_url: str | None = None,
    ):
        """Initialize a new instance of the CharmState class.

        Args:
            agent_password: the agent password.
            api_credentials: a map ccontaining the API credentials.
            rsyslog_public_cert: the public TLS certificate for rsyslog.
            cluster_key: the Wazuh key for the cluster nodes.
            indexer_endpoints: list of Wazuh indexer endpoints.
            filebeat_username: the filebeat username.
            filebeat_password: the filebeat password.
            filebeat_ca: the CA certificate for filebeat.
            wazuh_config: Wazuh configuration.
            custom_config_ssh_key: the SSH key for the git repository.
            opencti_token: the OpenCTI token.
            opencti_url: the OpenCTI URL.
        """
        super().__init__(
            agent_password=agent_password,
            api_credentials=api_credentials,
            rsyslog_public_cert=rsyslog_public_cert,
            cluster_key=cluster_key,
            indexer_endpoints=indexer_endpoints,
            filebeat_username=filebeat_username,
            filebeat_password=filebeat_password,
            filebeat_ca=filebeat_ca,
            custom_config_repository=wazuh_config.custom_config_repository,
            custom_config_ssh_key=custom_config_ssh_key,
            enable_vulnerability_detection=wazuh_config.enable_vulnerability_detection,
            logs_ca_cert=wazuh_config.logs_ca_cert,
            opencti_token=opencti_token,
            opencti_url=opencti_url,
        )

    @property
    def proxy(self) -> "ProxyConfig":
        """Get charm proxy configuration from juju charm environment.

        Returns:
            charm proxy configuration in the form of ProxyConfig.

        Raises:
            RecoverableStateError: if the proxy configuration is invalid.
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
            raise RecoverableStateError("Invalid proxy configuration.") from exc

    @classmethod
    # pylint: disable=too-many-arguments,too-many-locals,too-many-positional-arguments
    def from_charm(
        cls,
        charm: ops.CharmBase,
        rsyslog_csr: str,
        indexer_relation_data: dict[str, str],
        opencti_relation_data: dict[str, str],
        provider_certificates: list[certificates.ProviderCertificate],
    ) -> "State":
        """Initialize the state from charm.

        Args:
            charm: the root charm.
            rsyslog_csr: the TLS certificate signing request.
            indexer_relation_data: the Wazuh indexer app relation data.
            opencti_relation_data: the OpenCTI relation data.
            provider_certificates: the provider certificates.

        Returns:
            Current state of the charm.

        Raises:
            InvalidStateError: if the state is invalid and unrecoverable.
            RecoverableStateError: if the state is invalid and recoverable.
        """
        filebeat_user, filebeat_password, endpoints, filebeat_ca = _fetch_filebeat_configuration(
            charm.model, indexer_relation_data
        )
        args = {key.replace("-", "_"): value for key, value in charm.config.items()}
        # mypy doesn't like the str to Url casting and validation is already performed by pydantic
        valid_config = None
        try:
            valid_config = WazuhConfig(**args)  # type: ignore
        except ValidationError as exc:
            error_fields = set(
                itertools.chain.from_iterable(error["loc"] for error in exc.errors())
            )
            error_field_str = " ".join(f"{f}" for f in error_fields)
            raise RecoverableStateError(f"Invalid charm configuration {error_field_str}") from exc
        custom_config_ssh_key = _fetch_ssh_repository_key(charm.model, valid_config)
        agent_password = _fetch_password(charm.model, valid_config.agent_password)
        api_credentials = _fetch_api_credentials(charm.model)
        cluster_key = _fetch_cluster_key(charm.model)
        matching_certificates = _fetch_matching_certificates(provider_certificates, rsyslog_csr)
        opencti_url, opencti_token = _fetch_opencti_details(charm.model, opencti_relation_data)
        try:
            if matching_certificates:
                return cls(
                    agent_password=agent_password,
                    api_credentials=api_credentials,
                    rsyslog_public_cert=matching_certificates[0].certificate,
                    cluster_key=cluster_key,
                    indexer_endpoints=endpoints,
                    filebeat_username=filebeat_user,
                    filebeat_password=filebeat_password,
                    filebeat_ca=filebeat_ca,
                    wazuh_config=valid_config,
                    custom_config_ssh_key=custom_config_ssh_key,
                    opencti_url=opencti_url,
                    opencti_token=opencti_token,
                )
            raise RecoverableStateError("Certificate is empty.")
        except ValidationError as exc:
            error_fields = set(
                itertools.chain.from_iterable(error["loc"] for error in exc.errors())
            )
            error_field_str = " ".join(f"{f}" for f in error_fields)
            raise InvalidStateError(f"Invalid charm configuration {error_field_str}") from exc


class CharmBaseWithState(ops.CharmBase, ABC):
    """CharmBase than can build a CharmState.

    Attrs:
        master_fqdn: the FQDN for unit 0.
        state: the charm state.
        units_fqdns: the charm units' FQDNs.
    """

    @abstractmethod
    def reconcile(self, _: ops.HookEvent) -> None:
        """Reconcile configuration."""

    @property
    @abstractmethod
    def state(self) -> State | None:
        """The charm state."""

    @property
    @abstractmethod
    def units_fqdns(self) -> list[str]:
        """Retrieve the FQDNs of the charm units.

        Returns: a list of FQDNs.
        """

    @property
    @abstractmethod
    def master_fqdn(self) -> list[str]:
        """Get the FQDN for the unit 0.

        Returns: the FQDN for the unit 0.
        """
