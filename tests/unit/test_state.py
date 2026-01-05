# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""State unit tests."""

import datetime
import random
import secrets
import unittest
import unittest.mock

import charms.tls_certificates_interface.v3.tls_certificates as certificates
import ops
import pytest
from pydantic import AnyUrl

import state


class UnitTestHelper:  # pylint: disable=too-many-instance-attributes
    """Helper object for unit tests.

    Generates a correct and randomized config + a get_secret mock to provide
    expected secret values. To test behavior when secrets don't exist or are
    formatted incorrectly, override the get_[secret_name]_secret methods.

    Attributes:
        charm: a charm object.
        opensearch_relation_data: opensearch_relation_data.
        opencti_relation_data: opencti_relation_data.
    """

    def __init__(self, repo=False, opencti=False, api_creds=False) -> None:
        """Create a unit test helper.

        Arguments:
            repo: whether to create custom_config_repo config settings.
            opencti: whether to generate opencti relation data.
            api_creds: whether to generate pre-existing API credentials.
        """
        self.indexer_ca: str = "\n".join(
            (
                "-----BEGIN CERTIFICATE-----",
                secrets.token_hex(),
                "-----END CERTIFICATE-----",
            )
        )
        self.logs_ca: str = "\n".join(
            (
                "-----BEGIN CERTIFICATE-----",
                secrets.token_hex(),
                "-----END CERTIFICATE-----",
            )
        )
        self.username: str = "user1"
        self.password: str = secrets.token_hex()
        self.agent_password: str = secrets.token_hex(16)
        self.repo = repo
        self.custom_config_repo: AnyUrl | None = (
            AnyUrl("git+ssh://user2@git.server/repo_name@main") if repo else None
        )
        self.ssh_key: str | None = (
            "\n".join(
                (
                    "-----BEGIN OPENSSH PRIVATE KEY-----",
                    secrets.token_hex(),
                    "-----END OPENSSH PRIVATE KEY-----",
                )
            )
            if repo
            else None
        )
        self.endpoints: list[str] = [
            f"10.0.0.{random.randint(0, 255)}",  # nosec  # not cryptographically sensitive
            f"10.0.0.{random.randint(0, 255)}",  # nosec  # not cryptographically sensitive
        ]
        self.rsyslog_public_cert = "\n".join(
            (
                "-----BEGIN CERTIFICATE-----",
                secrets.token_hex(),
                "-----END CERTIFICATE-----",
            )
        )
        self.rsyslog_ca = secrets.token_hex()
        self.certificates: list[certificates.ProviderCertificate] = [
            certificates.ProviderCertificate(
                relation_id=1,
                application_name="application",
                csr="1",
                certificate=self.rsyslog_public_cert,
                ca=self.rsyslog_ca,
                chain=[],
                revoked=False,
                expiry_time=datetime.datetime(day=1, month=1, year=datetime.MAXYEAR),
            )
        ]
        self.api_creds = (
            {
                "wazuh": secrets.token_hex(16),
                "wazuh-wui": secrets.token_hex(16),
                "prometheus": secrets.token_hex(16),
            }
            if api_creds
            else None
        )
        self.cluster_key: str = secrets.token_hex(16)  # resulting string will be 32 chars
        self.secret_user_secret_id = f"secret:{secrets.token_hex()}"
        self.secret_tls_secret_id = f"secret:{secrets.token_hex()}"
        self.agent_password_secret_id = f"secret:{secrets.token_hex()}"
        self.custom_config_ssh_key_secret_id = f"secret:{secrets.token_hex()}"
        self._charm: unittest.mock.Mock | None = None  # will be cached
        self.opencti = opencti
        self.opencti_url = f"http://{secrets.token_hex(16)}.local"
        self.opencti_token = secrets.token_hex(16)
        self.opencti_token_secret_id = f"secret:{secrets.token_hex()}"

    @property
    def opensearch_relation_data(self):
        """Return opensearch relation data."""
        return {
            "endpoints": ",".join(self.endpoints),
            "secret-user": self.secret_user_secret_id,
            "secret-tls": self.secret_tls_secret_id,
        }

    @property
    def opencti_relation_data(self):
        """Return opencti relation data."""
        if not self.opencti:
            return {}
        return {
            "opencti_url": self.opencti_url,
            "opencti_token": self.opencti_token_secret_id,
        }

    # R1710: inconsistent-return-statements
    # R0911: too many return statements
    # W0622: redefining built-in 'id'; necessary bc ops library will call function with 'id'
    def get_secret_handler(self, id=None, label=None):  # pylint: disable=R0911,R1710,W0622
        """Handle get_secret according to the id or label provided as an arg.

        Arguments:
            id (str): secret id.
            label (str): secret label.

        Returns:
            unittest.mock.Mock() | None
        """
        if id == self.secret_user_secret_id:
            return self.get_secret_user_secret()
        if id == self.secret_tls_secret_id:
            return self.get_secret_tls_secret()
        if id == self.agent_password_secret_id:
            return self.get_agent_password_secret()
        if id == self.custom_config_ssh_key_secret_id:
            return self.get_custom_config_ssh_key_secret()
        if label == state.WAZUH_CLUSTER_KEY_SECRET_LABEL:
            return self.get_cluster_key_secret()
        if label == state.WAZUH_API_CREDENTIAL_SECRET_LABEL:
            return self.get_wazuh_api_credentials_secret()
        if id == self.opencti_token_secret_id:
            return self.get_opencti_token_secret()

    def get_secret_user_secret(self):
        """Handle get_secret for the secret-user secret id.

        Returns:
            unittest.mock.Mock()
        """
        mock = unittest.mock.Mock()
        mock.get_content.return_value = {
            "username": self.username,
            "password": self.password,
        }
        return mock

    def get_secret_tls_secret(self):
        """Handle get_secret for the secret-user secret id.

        Returns:
            unittest.mock.Mock()
        """
        mock = unittest.mock.Mock()
        mock.get_content.return_value = {"tls-ca": "\n".join((self.indexer_ca, self.indexer_ca))}
        return mock

    def get_agent_password_secret(self):
        """Handle get_secret for the secret-tls secret id.

        Returns:
            unittest.mock.Mock()
        """
        mock = unittest.mock.Mock()
        mock.get_content.return_value = {"value": self.agent_password}
        return mock

    def get_custom_config_ssh_key_secret(self):
        """Handle get_secret for the custom-config-ssh-key secret id.

        Returns:
            unittest.mock.Mock()
        """
        mock = unittest.mock.Mock()
        mock.get_content.return_value = {"value": self.ssh_key}
        return mock

    def get_cluster_key_secret(self):
        """Handle get_secret for the cluster key secret label.

        Returns:
            unittest.mock.Mock()
        """
        mock = unittest.mock.Mock()
        mock.get_content.return_value = {"value": self.cluster_key}
        return mock

    def get_wazuh_api_credentials_secret(self):
        """Handle get_secret for the wazuh-api-credentials secret label.

        Returns:
            unittest.mock.Mock()

        Raises:
            SecretNotFoundError: if Wazuh API credentials have not been generated.
        """
        if not self.api_creds:
            raise ops.SecretNotFoundError
        mock = unittest.mock.Mock()
        mock.get_content.return_value = self.api_creds
        return mock

    def get_opencti_token_secret(self):
        """Handle get_secret for the opencti-token secret id.

        Returns:
            unittest.mock.Mock()

        Raises:
            SecretNotFoundError: if OpenCTI relation data has not been generated.
        """
        if not self.opencti:
            raise ops.SecretNotFoundError
        mock = unittest.mock.Mock()
        mock.get_content.return_value = {"token": self.opencti_token}
        return mock

    @property
    def charm(self):
        """Return a charm object.

        Returns:
            unittest.mock.MagicMock
        """
        if self._charm:
            return self._charm

        mock = unittest.mock.MagicMock(spec=ops.CharmBase)
        tuples = (
            ("logs-ca-cert", self.logs_ca, True),
            ("agent-password", self.agent_password_secret_id, True),
            ("custom-config-repository", self.custom_config_repo, self.repo),
            ("custom-config-ssh-key", self.custom_config_ssh_key_secret_id, self.repo),
        )
        mock.config = {k: v for k, v, b in tuples if b}
        mock.model.get_secret.side_effect = self.get_secret_handler

        self._charm = mock
        return mock

    def get_state(  # pylint: disable=too-many-arguments,too-many-positional-arguments
        self,
        charm=None,
        rsyslog_csr=None,
        opensearch_data=None,
        opencti_data=None,
        provider_certificates=None,
    ) -> state.State:
        """Generate charm state.

        Arguments:
            charm: the charm.
            rsyslog_csr: the csr.
            opensearch_data: the opensearch_relation_data.
            opencti_data: the opencti_data.
            provider_certificates: the provider_certificates.

        Returns:
            state.State
        """
        return state.State.from_charm(
            charm=(charm if charm is not None else self.charm),
            rsyslog_csr=(rsyslog_csr if rsyslog_csr is not None else "1"),
            indexer_relation_data=(
                opensearch_data if opensearch_data is not None else self.opensearch_relation_data
            ),
            opencti_relation_data=(
                opencti_data if opencti_data is not None else self.opencti_relation_data
            ),
            provider_certificates=(
                provider_certificates if provider_certificates is not None else self.certificates
            ),
        )


def test_state_with_basic_config():
    """
    arrange: given a basic config and valid config/secret values.
    act: initialize charm state.
    assert: always-required state variables are correct.
    """
    helper = UnitTestHelper()
    charm_state = helper.get_state()

    assert charm_state.agent_password is not None
    assert charm_state.agent_password == helper.agent_password
    assert charm_state.logs_ca_cert is not None
    assert charm_state.logs_ca_cert == helper.logs_ca
    assert charm_state.cluster_key is not None
    assert charm_state.cluster_key == helper.cluster_key
    assert charm_state.indexer_endpoints is not None
    assert charm_state.indexer_endpoints == helper.endpoints
    assert charm_state.filebeat_username is not None
    assert charm_state.filebeat_username == helper.username
    assert charm_state.filebeat_password is not None
    assert charm_state.filebeat_password == helper.password
    assert charm_state.rsyslog_public_cert is not None
    assert charm_state.rsyslog_public_cert == helper.rsyslog_public_cert
    assert charm_state.filebeat_ca is not None
    assert charm_state.filebeat_ca == helper.indexer_ca

    default_creds = {k: v["default_password"] for k, v in state.WAZUH_USERS.items()}
    assert charm_state.api_credentials == default_creds
    assert charm_state.custom_config_repository is None
    assert charm_state.custom_config_ssh_key is None
    assert charm_state.opencti_url is None
    assert charm_state.opencti_token is None
    assert charm_state.proxy.http_proxy is None
    assert charm_state.proxy.https_proxy is None
    assert charm_state.proxy.no_proxy is None


def test_state_with_proxy(monkeypatch: pytest.MonkeyPatch):
    """
    arrange: given valid relation data and proxy env variables.
    act: when state is initialized through from_charm method.
    assert: the state contains the proxy values.
    """
    monkeypatch.setenv("JUJU_CHARM_HTTP_PROXY", "http://squid.proxy:3228/")
    monkeypatch.setenv("JUJU_CHARM_HTTPS_PROXY", "https://squid.proxy:3228/")
    monkeypatch.setenv("JUJU_CHARM_NO_PROXY", "localhost")

    helper = UnitTestHelper()
    charm_state = helper.get_state()

    assert str(charm_state.proxy.http_proxy) == "http://squid.proxy:3228/"
    assert str(charm_state.proxy.https_proxy) == "https://squid.proxy:3228/"
    assert charm_state.proxy.no_proxy == "localhost"


def test_state_with_api_credentials():
    """
    arrange: given valid charm config, relations, and pre-existing api creds.
    act: when state is initialized through from_charm method.
    assert: the state contains the api credentials.
    """
    helper = UnitTestHelper(api_creds=True)
    charm_state = helper.get_state()
    assert charm_state.api_credentials is not None
    wazuh_password = charm_state.api_credentials.get("wazuh", None)
    assert wazuh_password is not None
    assert isinstance(helper.api_creds, dict)
    assert wazuh_password == helper.api_creds.get("wazuh", None)


def test_state_with_valid_repo_config():
    """
    arrange: given a secret for the repositorywith valid content.
    act: when charm state is initialized.
    assert: the state contains the secret value.
    """
    helper = UnitTestHelper(repo=True)
    charm_state = helper.get_state()

    assert charm_state.custom_config_repository is not None
    assert charm_state.custom_config_repository == helper.custom_config_repo
    assert charm_state.custom_config_ssh_key is not None
    assert charm_state.custom_config_ssh_key == helper.ssh_key


def test_state_with_valid_opencti_relation_data():
    """
    arrange: given valid OpenCTI relation data.
    act: when state is initialized through from_charm method.
    assert: the state contains the OpenCTI relation data.
    """
    helper = UnitTestHelper(opencti=True)
    charm_state = helper.get_state()

    assert charm_state.opencti_url is not None
    assert charm_state.opencti_url == helper.opencti_url
    assert charm_state.opencti_token is not None
    assert charm_state.opencti_token == helper.opencti_token


def test_state_invalid_indexer_relation_data():
    """
    arrange: given an invalid opensearch relation data.
    act: when state is initialized through from_charm method.
    assert: a InvalidStateError is raised.
    """
    helper = UnitTestHelper()

    with pytest.raises(state.RecoverableStateError):
        helper.get_state(provider_certificates=[])

    relation_data = helper.opensearch_relation_data
    relation_data.pop("endpoints", None)
    with pytest.raises(state.InvalidStateError):
        helper.get_state(opensearch_data=relation_data)


def test_proxyconfig_invalid(monkeypatch: pytest.MonkeyPatch):
    """
    arrange: given a monkeypatched os.environ mapping that contains invalid proxy values.
    act: when charm state is initialized.
    assert: RecoverableStateError is raised.
    """
    monkeypatch.setenv("JUJU_CHARM_HTTP_PROXY", "INVALID_URL")

    helper = UnitTestHelper()
    charm_state = helper.get_state()

    with pytest.raises(state.RecoverableStateError):
        charm_state.proxy  # pylint: disable=pointless-statement


def test_state_when_repository_secret_not_found():
    """
    arrange: given a secret_id for the repository non matching a secret.
    act: when charm state is initialized.
    assert: RecoverableStateError is raised.
    """
    helper = UnitTestHelper(repo=True)

    def secret_missing():  # noqa: DCO010
        raise ops.SecretNotFoundError

    helper.get_custom_config_ssh_key_secret = secret_missing  # type: ignore[method-assign]

    with pytest.raises(state.RecoverableStateError):
        helper.get_state()


def test_state_when_agent_password_secret_not_found():
    """
    arrange: given a secret_id for the agent password non matching a secret.
    act: when charm state is initialized.
    assert: RecoverableStateError is raised.
    """
    helper = UnitTestHelper()

    def secret_missing():  # noqa: DCO010
        raise ops.SecretNotFoundError

    helper.get_agent_password_secret = secret_missing  # type: ignore[method-assign]

    with pytest.raises(state.RecoverableStateError):
        helper.get_state()


def test_state_when_repository_secret_invalid():
    """
    arrange: given a secret for the repository ssh key with invalid content.
    act: when charm state is initialized.
    assert: RecoverableStateError is raised.
    """
    helper = UnitTestHelper(repo=True)
    empty_secret_mock = unittest.mock.Mock()
    empty_secret_mock.get_content.return_value = {}
    helper.get_custom_config_ssh_key_secret = (  # type: ignore[method-assign]
        lambda: empty_secret_mock
    )

    with pytest.raises(state.RecoverableStateError):
        helper.get_state()


def test_state_when_agent_secret_invalid():
    """
    arrange: given a secret for the agent password with invalid content.
    act: when charm state is initialized.
    assert: RecoverableStateError is raised.
    """
    helper = UnitTestHelper()
    empty_secret_mock = unittest.mock.Mock()
    empty_secret_mock.get_content.return_value = {}
    helper.get_agent_password_secret = lambda: empty_secret_mock  # type: ignore[method-assign]

    with pytest.raises(state.RecoverableStateError):
        helper.get_state()


def test_state_without_logs_ca_cert():
    """
    arrange: given relation data without logs_ca_cert.
    act: when state is initialized through from_charm method.
    assert: a RecoverableStateError is raised.
    """
    helper = UnitTestHelper()
    helper.charm.config.pop("logs-ca-cert", None)

    with pytest.raises(state.RecoverableStateError) as exc:
        helper.get_state()

    assert str(exc.value) == str(
        state.RecoverableStateError("Invalid charm configuration logs_ca_cert")
    )
