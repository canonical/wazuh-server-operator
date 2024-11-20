# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""State unit tests."""

import datetime
import secrets
import unittest

import charms.tls_certificates_interface.v3.tls_certificates as certificates
import ops
import pytest

import state


@pytest.mark.parametrize(
    "opensearch_relation_data",
    [
        ({}),
        ({}),
        ({"endpoints": "10.0.0.1"}),
    ],
)
def test_state_invalid_relation_data(opensearch_relation_data):
    """
    arrange: given an empty relation data.
    act: when state is initialized through from_charm method.
    assert: a InvalidStateError is raised.
    """
    mock_charm = unittest.mock.MagicMock(spec=ops.CharmBase)
    secret_id = f"secret:{secrets.token_hex()}"
    mock_charm.config = {"api-password": secret_id}
    provider_certificates = [
        certificates.ProviderCertificate(
            relation_id="certificates-provider/1",
            application_name="application",
            csr="1",
            certificate="somecert",
            ca="rootca",
            chain=[],
            revoked=False,
            expiry_time=datetime.datetime(day=1, month=1, year=datetime.MAXYEAR),
        )
    ]

    with pytest.raises(state.InvalidStateError):
        state.State.from_charm(mock_charm, opensearch_relation_data, provider_certificates, "1")
    with pytest.raises(state.RecoverableStateError):
        state.State.from_charm(mock_charm, opensearch_relation_data, [], "1")


def test_state_without_proxy():
    """
    arrange: given valid relation data.
    act: when state is initialized through from_charm method.
    assert: the state contains the endpoints.
    """
    mock_charm = unittest.mock.MagicMock(spec=ops.CharmBase)
    secret_id = f"secret:{secrets.token_hex()}"
    mock_charm.config = {"api-password": secret_id}
    endpoints = ["10.0.0.1", "10.0.0.2"]
    username = "user1"
    password = secrets.token_hex()
    opensearch_relation_data = {"endpoints": ",".join(endpoints)}
    certificate = "somecert"
    root_ca = "someca"
    secret_id = f"secret:{secrets.token_hex()}"
    value = secrets.token_hex(16)
    mock_charm.model.get_secret(id=secret_id).get_content.return_value = {
        "username": username,
        "password": password,
        "value": value,
    }
    csr = "1"
    provider_certificates = [
        certificates.ProviderCertificate(
            relation_id="certificates-provider/1",
            application_name="application",
            csr=csr,
            certificate=certificate,
            ca=root_ca,
            chain=[],
            revoked=False,
            expiry_time=datetime.datetime(day=1, month=1, year=datetime.MAXYEAR),
        )
    ]
    charm_state = state.State.from_charm(
        mock_charm, opensearch_relation_data, provider_certificates, csr
    )

    assert charm_state.api_password == value
    assert charm_state.cluster_key == value
    assert charm_state.indexer_ips == endpoints
    assert charm_state.filebeat_username == username
    assert charm_state.filebeat_password == password
    assert charm_state.certificate == certificate
    assert charm_state.root_ca == root_ca
    assert charm_state.custom_config_repository is None
    assert charm_state.custom_config_ssh_key is None
    assert charm_state.proxy.http_proxy is None
    assert charm_state.proxy.https_proxy is None
    assert charm_state.proxy.no_proxy is None


def test_state_with_proxy(monkeypatch: pytest.MonkeyPatch):
    """
    arrange: given valid relation data.
    act: when state is initialized through from_charm method.
    assert: the state contains the endpoints.
    """
    mock_charm = unittest.mock.MagicMock(spec=ops.CharmBase)
    secret_id = f"secret:{secrets.token_hex()}"
    mock_charm.config = {"api-password": secret_id}
    endpoints = ["10.0.0.1", "10.0.0.2"]
    username = "user1"
    password = secrets.token_hex()
    opensearch_relation_data = {"endpoints": ",".join(endpoints)}
    certificate = "somecert"
    root_ca = "someca"
    secret_id = f"secret:{secrets.token_hex()}"
    value = secrets.token_hex(16)
    mock_charm.model.get_secret(id=secret_id).get_content.return_value = {
        "username": username,
        "password": password,
        "value": value,
    }
    csr = "1"
    provider_certificates = [
        certificates.ProviderCertificate(
            relation_id="certificates-provider/1",
            application_name="application",
            csr=csr,
            certificate=certificate,
            ca=root_ca,
            chain=[],
            revoked=False,
            expiry_time=datetime.datetime(day=1, month=1, year=datetime.MAXYEAR),
        )
    ]
    monkeypatch.setenv("JUJU_CHARM_HTTP_PROXY", "http://squid.proxy:3228/")
    monkeypatch.setenv("JUJU_CHARM_HTTPS_PROXY", "https://squid.proxy:3228/")
    monkeypatch.setenv("JUJU_CHARM_NO_PROXY", "localhost")

    charm_state = state.State.from_charm(
        mock_charm, opensearch_relation_data, provider_certificates, csr
    )
    assert charm_state.api_password == value
    assert charm_state.cluster_key == value
    assert charm_state.indexer_ips == endpoints
    assert charm_state.certificate == certificate
    assert charm_state.root_ca == root_ca
    assert charm_state.filebeat_username == username
    assert charm_state.filebeat_password == password
    assert charm_state.custom_config_repository is None
    assert charm_state.custom_config_ssh_key is None
    assert str(charm_state.proxy.http_proxy) == "http://squid.proxy:3228/"
    assert str(charm_state.proxy.https_proxy) == "https://squid.proxy:3228/"
    assert charm_state.proxy.no_proxy == "localhost"


def test_proxyconfig_invalid(monkeypatch: pytest.MonkeyPatch):
    """
    arrange: given a monkeypatched os.environ mapping that contains invalid proxy values.
    act: when charm state is initialized.
    assert: RecoverableStateError is raised.
    """
    monkeypatch.setenv("JUJU_CHARM_HTTP_PROXY", "INVALID_URL")
    mock_charm = unittest.mock.MagicMock(spec=ops.CharmBase)
    secret_id = f"secret:{secrets.token_hex()}"
    mock_charm.config = {"api-password": secret_id}

    endpoints = ["10.0.0.1", "10.0.0.2"]
    username = "user1"
    password = secrets.token_hex()
    opensearch_relation_data = {"endpoints": ",".join(endpoints)}
    certificate = "somecert"
    root_ca = "someca"
    secret_id = f"secret:{secrets.token_hex()}"
    value = secrets.token_hex(16)
    mock_charm.model.get_secret(id=secret_id).get_content.return_value = {
        "username": username,
        "password": password,
        "value": value,
    }
    csr = "1"
    provider_certificates = [
        certificates.ProviderCertificate(
            relation_id="certificates-provider/1",
            application_name="application",
            csr=csr,
            certificate=certificate,
            ca=root_ca,
            chain=[],
            revoked=False,
            expiry_time=datetime.datetime(day=1, month=1, year=datetime.MAXYEAR),
        )
    ]
    charm_state = state.State.from_charm(
        mock_charm, opensearch_relation_data, provider_certificates, csr
    )
    with pytest.raises(state.RecoverableStateError):
        charm_state.proxy  # pylint: disable=pointless-statement


def test_state_when_repository_secret_not_found(monkeypatch: pytest.MonkeyPatch):
    """
    arrange: given a secret_id for the repository non matching a secret.
    act: when charm state is initialized.
    assert: RecoverableStateError is raised.
    """
    mock_charm = unittest.mock.MagicMock(spec=ops.CharmBase)
    repository_secret_id = f"secret:{secrets.token_hex()}"
    mock_charm.model.get_secret(id=repository_secret_id).side_effect = ops.SecretNotFoundError
    secret_id = f"secret:{secrets.token_hex()}"
    monkeypatch.setattr(
        mock_charm,
        "config",
        {
            "api-password": secret_id,
            "custom-config-repository": "git+ssh://user1@git.server/repo_name@main",
            "custom-config-ssh-key": repository_secret_id,
        },
    )

    endpoints = ["10.0.0.1", "10.0.0.2"]
    username = "user1"
    password = secrets.token_hex()
    opensearch_relation_data = {"endpoints": ",".join(endpoints)}
    certificate = "somecert"
    root_ca = "someca"
    mock_charm.model.get_secret(id=secret_id).get_content.return_value = {
        "username": username,
        "password": password,
    }
    csr = "1"
    provider_certificates = [
        certificates.ProviderCertificate(
            relation_id="certificates-provider/1",
            application_name="application",
            csr=csr,
            certificate=certificate,
            ca=root_ca,
            chain=[],
            revoked=False,
            expiry_time=datetime.datetime(day=1, month=1, year=datetime.MAXYEAR),
        )
    ]
    with pytest.raises(state.RecoverableStateError):
        state.State.from_charm(mock_charm, opensearch_relation_data, provider_certificates, csr)


def test_state_when_agent_password_secret_not_found(monkeypatch: pytest.MonkeyPatch):
    """
    arrange: given a secret_id for the agent password non matching a secret.
    act: when charm state is initialized.
    assert: RecoverableStateError is raised.
    """
    mock_charm = unittest.mock.MagicMock(spec=ops.CharmBase)
    secret_id = f"secret:{secrets.token_hex()}"
    mock_charm.model.get_secret(id=secret_id).side_effect = ops.SecretNotFoundError
    monkeypatch.setattr(
        mock_charm,
        "config",
        {
            "agent-password": secret_id,
            "api-password": secret_id,
        },
    )

    endpoints = ["10.0.0.1", "10.0.0.2"]
    username = "user1"
    password = secrets.token_hex()
    opensearch_relation_data = {"endpoints": ",".join(endpoints)}
    certificate = "somecert"
    root_ca = "someca"
    secret_id = f"secret:{secrets.token_hex()}"
    mock_charm.model.get_secret(id=secret_id).get_content.return_value = {
        "username": username,
        "password": password,
    }
    csr = "1"
    provider_certificates = [
        certificates.ProviderCertificate(
            relation_id="certificates-provider/1",
            application_name="application",
            csr=csr,
            certificate=certificate,
            ca=root_ca,
            chain=[],
            revoked=False,
            expiry_time=datetime.datetime(day=1, month=1, year=datetime.MAXYEAR),
        )
    ]
    with pytest.raises(state.RecoverableStateError):
        state.State.from_charm(mock_charm, opensearch_relation_data, provider_certificates, csr)


def test_state_when_repository_secret_invalid(monkeypatch: pytest.MonkeyPatch):
    """
    arrange: given a secret for the repository with invalid content.
    act: when charm state is initialized.
    assert: RecoverableStateError is raised.
    """
    mock_charm = unittest.mock.MagicMock(spec=ops.CharmBase)
    repository_secret_id = f"secret:{secrets.token_hex()}"
    mock_charm.model.get_secret(id=repository_secret_id).return_value.get_content.return_value = {}
    secret_id = f"secret:{secrets.token_hex()}"
    monkeypatch.setattr(
        mock_charm,
        "config",
        {
            "api-password": secret_id,
            "custom-config-repository": "git+ssh://user1@git.server/repo_name@main",
            "custom-config-ssh-key": repository_secret_id,
        },
    )

    endpoints = ["10.0.0.1", "10.0.0.2"]
    username = "user1"
    password = secrets.token_hex()
    opensearch_relation_data = {"endpoints": ",".join(endpoints)}
    certificate = "somecert"
    root_ca = "someca"
    mock_charm.model.get_secret(id=secret_id).get_content.return_value = {
        "username": username,
        "password": password,
    }
    csr = "1"
    provider_certificates = [
        certificates.ProviderCertificate(
            relation_id="certificates-provider/1",
            application_name="application",
            csr=csr,
            certificate=certificate,
            ca=root_ca,
            chain=[],
            revoked=False,
            expiry_time=datetime.datetime(day=1, month=1, year=datetime.MAXYEAR),
        )
    ]

    with pytest.raises(state.RecoverableStateError):
        state.State.from_charm(mock_charm, opensearch_relation_data, provider_certificates, csr)


def test_state_when_agent_secret_invalid(monkeypatch: pytest.MonkeyPatch):
    """
    arrange: given a secret for the agent password with invalid content.
    act: when charm state is initialized.
    assert: RecoverableStateError is raised.
    """
    mock_charm = unittest.mock.MagicMock(spec=ops.CharmBase)
    secret_id = f"secret:{secrets.token_hex()}"
    mock_charm.model.get_secret(id=secret_id).return_value.get_content.return_value = {}
    monkeypatch.setattr(
        mock_charm,
        "config",
        {
            "agent-password": secret_id,
            "api-password": secret_id,
        },
    )

    endpoints = ["10.0.0.1", "10.0.0.2"]
    username = "user1"
    password = secrets.token_hex()
    opensearch_relation_data = {"endpoints": ",".join(endpoints)}
    certificate = "somecert"
    root_ca = "someca"
    secret_id = f"secret:{secrets.token_hex()}"
    mock_charm.model.get_secret(id=secret_id).get_content.return_value = {
        "username": username,
        "password": password,
    }
    csr = "1"
    provider_certificates = [
        certificates.ProviderCertificate(
            relation_id="certificates-provider/1",
            application_name="application",
            csr=csr,
            certificate=certificate,
            ca=root_ca,
            chain=[],
            revoked=False,
            expiry_time=datetime.datetime(day=1, month=1, year=datetime.MAXYEAR),
        )
    ]

    with pytest.raises(state.RecoverableStateError):
        state.State.from_charm(mock_charm, opensearch_relation_data, provider_certificates, csr)


def test_state_when_repository_secret_valid(monkeypatch: pytest.MonkeyPatch):
    """
    arrange: given a secret for the repositorywith valid content.
    act: when charm state is initialized.
    assert: the state contains the secret value.
    """
    custom_config_repository = "git+ssh://user1@git.server/repo_name@main"
    mock_charm = unittest.mock.MagicMock(spec=ops.CharmBase)
    repository_secret_id = f"secret:{secrets.token_hex()}"
    secret_id = f"secret:{secrets.token_hex()}"
    value = secrets.token_hex(16)
    monkeypatch.setattr(
        mock_charm,
        "config",
        {
            "api-password": value,
            "custom-config-repository": custom_config_repository,
            "custom-config-ssh-key": repository_secret_id,
        },
    )

    endpoints = ["10.0.0.1", "10.0.0.2"]
    username = "user1"
    password = secrets.token_hex()
    opensearch_relation_data = {"endpoints": ",".join(endpoints)}
    certificate = "somecert"
    root_ca = "someca"
    secret_id = f"secret:{secrets.token_hex()}"
    value = secrets.token_hex(16)
    mock_charm.model.get_secret(id=secret_id).get_content.return_value = {
        "username": username,
        "password": password,
        "value": value,
    }
    csr = "1"
    provider_certificates = [
        certificates.ProviderCertificate(
            relation_id="certificates-provider/1",
            application_name="application",
            csr=csr,
            certificate=certificate,
            ca=root_ca,
            chain=[],
            revoked=False,
            expiry_time=datetime.datetime(day=1, month=1, year=datetime.MAXYEAR),
        )
    ]
    charm_state = state.State.from_charm(
        mock_charm, opensearch_relation_data, provider_certificates, csr
    )

    assert charm_state.cluster_key == value
    assert charm_state.indexer_ips == endpoints
    assert charm_state.filebeat_username == username
    assert charm_state.filebeat_password == password
    assert charm_state.certificate == certificate
    assert charm_state.root_ca == root_ca
    assert str(charm_state.custom_config_repository) == custom_config_repository
    assert charm_state.custom_config_ssh_key == value
    assert charm_state.proxy.http_proxy is None
    assert charm_state.proxy.https_proxy is None
    assert charm_state.proxy.no_proxy is None


def test_state_when_agent_password_secret_valid(monkeypatch: pytest.MonkeyPatch):
    """
    arrange: given a secret for the agent password valid content.
    act: when charm state is initialized.
    assert: the state contains the secret value.
    """
    mock_charm = unittest.mock.MagicMock(spec=ops.CharmBase)
    secret_id = f"secret:{secrets.token_hex()}"
    monkeypatch.setattr(
        mock_charm,
        "config",
        {
            "agent-password": secret_id,
            "api-password": secret_id,
        },
    )

    endpoints = ["10.0.0.1", "10.0.0.2"]
    username = "user1"
    password = secrets.token_hex()
    value = secrets.token_hex(16)
    opensearch_relation_data = {"endpoints": ",".join(endpoints)}
    certificate = "somecert"
    root_ca = "someca"
    secret_id = f"secret:{secrets.token_hex()}"
    mock_charm.model.get_secret(id=secret_id).get_content.return_value = {
        "username": username,
        "password": password,
        "value": value,
    }
    csr = "1"
    provider_certificates = [
        certificates.ProviderCertificate(
            relation_id="certificates-provider/1",
            application_name="application",
            csr=csr,
            certificate=certificate,
            ca=root_ca,
            chain=[],
            revoked=False,
            expiry_time=datetime.datetime(day=1, month=1, year=datetime.MAXYEAR),
        )
    ]
    charm_state = state.State.from_charm(
        mock_charm, opensearch_relation_data, provider_certificates, csr
    )

    assert charm_state.cluster_key == value
    assert charm_state.indexer_ips == endpoints
    assert charm_state.filebeat_username == username
    assert charm_state.filebeat_password == password
    assert charm_state.certificate == certificate
    assert charm_state.root_ca == root_ca
    assert charm_state.agent_password == value
    assert charm_state.custom_config_repository is None
    assert charm_state.custom_config_ssh_key is None
    assert charm_state.proxy.http_proxy is None
    assert charm_state.proxy.https_proxy is None
    assert charm_state.proxy.no_proxy is None
