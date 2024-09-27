# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""State unit tests."""

import json
import unittest

import ops
import pytest

import state


@pytest.mark.parametrize(
    "opensearch_relation_data,certificates_relation_data",
    [({}, {}), ({}, {"certificates": '[{"certificate": ""}]'}), ({"endpoints": "10.0.0.1"}, {})],
)
def test_state_invalid_relation_data(opensearch_relation_data, certificates_relation_data):
    """
    arrange: given an empty relation data.
    act: when state is initialized through from_charm method.
    assert: a InvalidStateError is raised.
    """
    mock_charm = unittest.mock.MagicMock(spec=ops.CharmBase)

    with pytest.raises(state.InvalidStateError):
        state.State.from_charm(mock_charm, opensearch_relation_data, certificates_relation_data)


def test_state_without_proxy():
    """
    arrange: given valid relation data.
    act: when state is initialized through from_charm method.
    assert: the state contains the endpoints.
    """
    mock_charm = unittest.mock.MagicMock(spec=ops.CharmBase)
    endpoints = ["10.0.0.1", "10.0.0.2"]
    opensearch_relation_data = {"endpoints": ",".join(endpoints)}
    certificate = "somecert"
    certificates_relation_data = {"certificates": json.dumps([{"certificate": certificate}])}

    charm_state = state.State.from_charm(
        mock_charm, opensearch_relation_data, certificates_relation_data
    )
    assert charm_state.indexer_ips == endpoints
    assert charm_state.certificate == certificate
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
    endpoints = ["10.0.0.1", "10.0.0.2"]
    opensearch_relation_data = {"endpoints": ",".join(endpoints)}
    certificate = "somecert"
    certificates_relation_data = {"certificates": json.dumps([{"certificate": certificate}])}
    monkeypatch.setenv("JUJU_CHARM_HTTP_PROXY", "http://squid.proxy:3228/")
    monkeypatch.setenv("JUJU_CHARM_HTTPS_PROXY", "https://squid.proxy:3228/")
    monkeypatch.setenv("JUJU_CHARM_NO_PROXY", "localhost")

    charm_state = state.State.from_charm(
        mock_charm, opensearch_relation_data, certificates_relation_data
    )
    assert charm_state.indexer_ips == endpoints
    assert charm_state.certificate == certificate
    assert charm_state.custom_config_repository is None
    assert charm_state.custom_config_ssh_key is None
    assert str(charm_state.proxy.http_proxy) == "http://squid.proxy:3228/"
    assert str(charm_state.proxy.https_proxy) == "https://squid.proxy:3228/"
    assert charm_state.proxy.no_proxy == "localhost"


def test_proxyconfig_invalid(monkeypatch: pytest.MonkeyPatch):
    """
    arrange: given a monkeypatched os.environ mapping that contains invalid proxy values.
    act: when charm state is initialized.
    assert: InvalidStateError is raised.
    """
    monkeypatch.setenv("JUJU_CHARM_HTTP_PROXY", "INVALID_URL")
    mock_charm = unittest.mock.MagicMock(spec=ops.CharmBase)
    mock_charm.config = {}

    endpoints = ["10.0.0.1", "10.0.0.2"]
    opensearch_relation_data = {"endpoints": ",".join(endpoints)}
    certificate = "somecert"
    certificates_relation_data = {"certificates": json.dumps([{"certificate": certificate}])}
    charm_state = state.State.from_charm(
        mock_charm, opensearch_relation_data, certificates_relation_data
    )
    with pytest.raises(state.InvalidStateError):
        charm_state.proxy  # pylint: disable=pointless-statement


def test_state_when_secret_not_found(monkeypatch: pytest.MonkeyPatch):
    """
    arrange: given a secret_id non matching a secret.
    act: when charm state is initialized.
    assert: InvalidStateError is raised.
    """
    mock_charm = unittest.mock.MagicMock(spec=ops.CharmBase)
    mock_charm.model.get_secret.side_effect = ops.SecretNotFoundError
    monkeypatch.setattr(
        mock_charm,
        "config",
        {
            "custom-config-repository": "git+ssh://user1@git.server/repo_name@main",
            "custom-config-ssh-key": "secret:123213123123123123123",  # nosec
        },
    )

    endpoints = ["10.0.0.1", "10.0.0.2"]
    opensearch_relation_data = {"endpoints": ",".join(endpoints)}
    certificate = "somecert"
    certificates_relation_data = {"certificates": json.dumps([{"certificate": certificate}])}
    with pytest.raises(state.InvalidStateError):
        state.State.from_charm(mock_charm, opensearch_relation_data, certificates_relation_data)


def test_state_when_secret_invalid(monkeypatch: pytest.MonkeyPatch):
    """
    arrange: given a secret with invalid content.
    act: when charm state is initialized.
    assert: InvalidStateError is raised.
    """
    mock_charm = unittest.mock.MagicMock(spec=ops.CharmBase)
    mock_charm.model.get_secret.return_value.get_content.return_value = {}
    monkeypatch.setattr(
        mock_charm,
        "config",
        {
            "custom-config-repository": "git+ssh://user1@git.server/repo_name@main",
            "custom-config-ssh-key": "secret:123213123123123123123",  # nosec
        },
    )

    endpoints = ["10.0.0.1", "10.0.0.2"]
    opensearch_relation_data = {"endpoints": ",".join(endpoints)}
    certificate = "somecert"
    certificates_relation_data = {"certificates": json.dumps([{"certificate": certificate}])}
    with pytest.raises(state.InvalidStateError):
        state.State.from_charm(mock_charm, opensearch_relation_data, certificates_relation_data)


def test_state_when_secret_valid(monkeypatch: pytest.MonkeyPatch):
    """
    arrange: given a secret with valid content.
    act: when charm state is initialized.
    assert: the state contains the secret value.
    """
    custom_config_repository = "git+ssh://user1@git.server/repo_name@main"
    mock_charm = unittest.mock.MagicMock(spec=ops.CharmBase)
    mock_charm.model.get_secret.return_value.get_content.return_value = {"value": "ssh-key"}
    monkeypatch.setattr(
        mock_charm,
        "config",
        {
            "custom-config-repository": custom_config_repository,
            "custom-config-ssh-key": "secret:123213123123123123123",  # nosec
        },
    )

    endpoints = ["10.0.0.1", "10.0.0.2"]
    opensearch_relation_data = {"endpoints": ",".join(endpoints)}
    certificate = "somecert"
    certificates_relation_data = {"certificates": json.dumps([{"certificate": certificate}])}
    charm_state = state.State.from_charm(
        mock_charm, opensearch_relation_data, certificates_relation_data
    )
    assert charm_state.indexer_ips == endpoints
    assert charm_state.certificate == certificate
    assert str(charm_state.custom_config_repository) == custom_config_repository
    assert charm_state.custom_config_ssh_key == "ssh-key"
    assert charm_state.proxy.http_proxy is None
    assert charm_state.proxy.https_proxy is None
    assert charm_state.proxy.no_proxy is None
