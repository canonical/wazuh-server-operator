# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charm unit tests."""
import secrets
from unittest.mock import ANY, patch

import ops
import pytest
from ops.testing import Harness

import wazuh
from charm import WazuhServerCharm
from state import InvalidStateError, RecoverableStateError, State, WazuhConfig


@patch.object(State, "from_charm")
def test_invalid_state_reaches_error_status(state_from_charm_mock):
    """
    arrange: mock State.from_charm so that it raises and InvalidStateError.
    act: instantiate a charm.
    assert: the charm reaches error status when the state is fetched.
    """
    state_from_charm_mock.side_effect = InvalidStateError()

    harness = Harness(WazuhServerCharm)
    harness.begin()

    with pytest.raises(InvalidStateError):
        harness.charm.state  # pylint: disable=pointless-statement


@patch.object(State, "from_charm")
def test_invalid_state_reaches_blocked_status(state_from_charm_mock):
    """
    arrange: mock State.from_charm so that it raises and RecoverableStateError.
    act: instantiate a charm.
    assert: the charm reaches blocked status when the state is fetched.
    """
    state_from_charm_mock.side_effect = RecoverableStateError()

    harness = Harness(WazuhServerCharm)
    harness.begin()

    assert harness.charm.state is None
    assert harness.model.unit.status.name == ops.BlockedStatus().name


# pylint: disable=too-many-arguments, too-many-locals, too-many-positional-arguments
@patch.object(State, "from_charm")
@patch.object(wazuh, "configure_git")
@patch.object(wazuh, "pull_configuration_files")
@patch.object(wazuh, "update_configuration")
@patch.object(wazuh, "configure_agent_password")
@patch.object(wazuh, "install_certificates")
@patch.object(wazuh, "configure_filebeat_user")
@patch.object(wazuh, "change_api_password")
def test_reconcile_reaches_active_status_when_repository_and_password_configured(
    change_api_password_mock,
    configure_filebeat_user_mock,
    wazuh_install_certificates_mock,
    wazuh_configure_agent_password_mock,
    wazuh_update_configuration_mock,
    pull_configuration_files_mock,
    configure_git_mock,
    state_from_charm_mock,
):
    """
    arrange: mock system calls and charm state.
    act: call reconcile.
    assert: the charm reaches active status and configs are applied.
    """
    custom_config_repository = "git+ssh://user1@git.server/repo_name@main"
    secret_id = f"secret:{secrets.token_hex(21)}"
    api_password = secrets.token_hex()
    wazuh_config = WazuhConfig(
        api_password=api_password,
        custom_config_repository=custom_config_repository,
        custom_config_ssh_key=secret_id,
    )
    password = secrets.token_hex()
    agent_password = secrets.token_hex()
    cluster_key = secrets.token_hex(16)
    state_from_charm_mock.return_value = State(
        agent_password=agent_password,
        api_password=api_password,
        cluster_key=cluster_key,
        certificate="somecert",
        root_ca="root_ca",
        indexer_ips=["10.0.0.1"],
        filebeat_username="user1",
        filebeat_password=password,
        wazuh_config=wazuh_config,
        custom_config_ssh_key="somekey",
    )
    harness = Harness(WazuhServerCharm)
    harness.begin()
    container = harness.model.unit.containers.get("wazuh-server")
    assert container
    harness.set_can_connect(container, True)

    harness.charm.reconcile(None)

    wazuh_install_certificates_mock.assert_called_with(
        container=container, private_key=ANY, public_key="somecert", root_ca="root_ca"
    )
    wazuh_update_configuration_mock.assert_called_with(
        container,
        ["10.0.0.1"],
        ["wazuh-server-0.wazuh-server-endpoints"],
        "wazuh-server/0",
        cluster_key,
    )
    configure_git_mock.assert_called_with(
        container, str(wazuh_config.custom_config_repository), "somekey"
    )
    configure_filebeat_user_mock.assert_called_with(container, "user1", password)
    wazuh_configure_agent_password_mock.assert_called_with(
        container=container, password=agent_password
    )
    pull_configuration_files_mock.assert_called_with(container)
    change_api_password_mock.assert_any_call("wazuh", "wazuh", api_password)
    change_api_password_mock.assert_any_call("wazuh-wui", "wazuh-wui", api_password)
    assert harness.model.unit.status.name == ops.ActiveStatus().name


# pylint: disable=too-many-arguments, too-many-positional-arguments
@patch.object(State, "from_charm")
@patch.object(wazuh, "configure_git")
@patch.object(wazuh, "pull_configuration_files")
@patch.object(wazuh, "update_configuration")
@patch.object(wazuh, "configure_agent_password")
@patch.object(wazuh, "install_certificates")
@patch.object(wazuh, "configure_filebeat_user")
@patch.object(wazuh, "change_api_password")
def test_reconcile_reaches_active_status_when_repository_and_password_not_configured(
    change_api_password_mock,
    configure_filebeat_user_mock,
    wazuh_install_certificates_mock,
    wazuh_configure_agent_password_mock,
    wazuh_update_configuration_mock,
    pull_configuration_files_mock,
    configure_git_mock,
    state_from_charm_mock,
):
    """
    arrange: mock system calls and charm state.
    act: call reconcile.
    assert: the charm reaches active status and configs are applied.
    """
    password = secrets.token_hex()
    api_password = secrets.token_hex()
    cluster_key = secrets.token_hex(16)
    state_from_charm_mock.return_value = State(
        agent_password=None,
        api_password=api_password,
        cluster_key=cluster_key,
        certificate="somecert",
        root_ca="root_ca",
        indexer_ips=["10.0.0.1"],
        filebeat_username="user1",
        filebeat_password=password,
        wazuh_config=WazuhConfig(
            api_password=api_password, custom_config_repository=None, custom_config_ssh_key=None
        ),
        custom_config_ssh_key=None,
    )
    harness = Harness(WazuhServerCharm)
    harness.begin()
    container = harness.model.unit.containers.get("wazuh-server")
    assert container
    harness.set_can_connect(container, True)

    harness.charm.reconcile(None)

    wazuh_install_certificates_mock.assert_called_with(
        container=container, private_key=ANY, public_key="somecert", root_ca="root_ca"
    )
    configure_git_mock.assert_called_with(container, None, None)
    configure_filebeat_user_mock.assert_called_with(container, "user1", password)
    wazuh_configure_agent_password_mock.assert_not_called()
    pull_configuration_files_mock.assert_not_called()
    wazuh_update_configuration_mock.assert_called_with(
        container,
        ["10.0.0.1"],
        ["wazuh-server-0.wazuh-server-endpoints"],
        "wazuh-server/0",
        cluster_key,
    )
    change_api_password_mock.assert_any_call("wazuh", "wazuh", api_password)
    change_api_password_mock.assert_any_call("wazuh-wui", "wazuh-wui", api_password)
    assert harness.model.unit.status.name == ops.ActiveStatus().name


def test_reconcile_reaches_waiting_status_when_cant_connect():
    """
    arrange: do nothing.
    act: call reconcile.
    assert: the charm reaches waiting status.
    """
    harness = Harness(WazuhServerCharm)
    harness.begin()
    container = harness.model.unit.containers.get("wazuh-server")
    assert container
    harness.set_can_connect(container, False)

    harness.charm.reconcile(None)

    assert harness.model.unit.status.name == ops.WaitingStatus().name


@patch.object(State, "from_charm")
def test_reconcile_reaches_error_status_when_no_state(state_from_charm_mock):
    """
    arrange: mock the state to raise an exception.
    act: call reconcile.
    assert: the charm reaches error status.
    """
    state_from_charm_mock.side_effect = InvalidStateError()
    harness = Harness(WazuhServerCharm)
    harness.begin()
    container = harness.model.unit.containers.get("wazuh-server")
    assert container
    harness.set_can_connect(container, True)

    with pytest.raises(InvalidStateError):
        harness.charm.reconcile(None)
