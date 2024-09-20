# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charm unit tests."""
from unittest.mock import ANY, patch

import ops
from ops.testing import Harness

import wazuh
from charm import WazuhServerCharm
from state import InvalidStateError, State, WazuhConfig


@patch.object(State, "from_charm")
def test_invalid_state_reaches_blocked_status(state_from_charm_mock):
    """
    arrange: mock State.from_charm so that it raises and InvalidStateError.
    act: instantiate a charm.
    assert: the charm reaches blocked status when the state is fetched.
    """
    state_from_charm_mock.side_effect = InvalidStateError()

    harness = Harness(WazuhServerCharm)
    harness.begin()

    assert harness.charm.state is None
    assert harness.model.unit.status.name == ops.BlockedStatus().name


@patch.object(State, "from_charm")
@patch.object(wazuh, "configure_git")
@patch.object(wazuh, "update_configuration")
@patch.object(wazuh, "install_certificates")
def test_reconcile_reaches_active_status_when_repository_configured(
    wazuh_install_certificates_mock,
    wazuh_update_configuration_mock,
    configure_git_mock,
    state_from_charm_mock,
):
    """
    arrange: mock system calls and charm state.
    act: call reconcile.
    assert: the charm reaches active status and configs are applied.
    """
    git_repository = "git+ssh://user1@git.server/repo_name@main"
    state_from_charm_mock.return_value = State(
        certificate="somecert",
        indexer_ips=["10.0.0.1"],
        wazuh_config=WazuhConfig(git_repository=git_repository, git_ssh_key="secret_id"),
        git_ssh_key="somekey",
    )
    harness = Harness(WazuhServerCharm)
    harness.begin()
    container = harness.model.unit.containers.get("wazuh-server")
    assert container
    harness.set_can_connect(container, True)

    harness.charm.reconcile()

    wazuh_install_certificates_mock.assert_called_with(container, ANY, "somecert")
    wazuh_update_configuration_mock.assert_called_with(container, ["10.0.0.1"])
    configure_git_mock.assert_called_with(container, git_repository, "somekey")
    assert harness.model.unit.status.name == ops.ActiveStatus().name


@patch.object(State, "from_charm")
@patch.object(wazuh, "configure_git")
@patch.object(wazuh, "update_configuration")
@patch.object(wazuh, "install_certificates")
def test_reconcile_reaches_active_status_when_repository_not_configured(
    wazuh_install_certificates_mock,
    wazuh_update_configuration_mock,
    configure_git_mock,
    state_from_charm_mock,
):
    """
    arrange: mock system calls and charm state.
    act: call reconcile.
    assert: the charm reaches active status and configs are applied.
    """
    state_from_charm_mock.return_value = State(
        certificate="somecert",
        indexer_ips=["10.0.0.1"],
        wazuh_config=WazuhConfig(git_repository=None, git_ssh_key=None),
        git_ssh_key=None,
    )
    harness = Harness(WazuhServerCharm)
    harness.begin()
    container = harness.model.unit.containers.get("wazuh-server")
    assert container
    harness.set_can_connect(container, True)

    harness.charm.reconcile()

    wazuh_install_certificates_mock.assert_called_with(container, ANY, "somecert")
    wazuh_update_configuration_mock.assert_called_with(container, ["10.0.0.1"])
    configure_git_mock.assert_not_called()
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

    harness.charm.reconcile()

    assert harness.model.unit.status.name == ops.WaitingStatus().name


@patch.object(State, "from_charm")
def test_reconcile_reaches_blocked_status_when_no_state(state_from_charm_mock):
    """
    arrange: mock the state to raise an exception.
    act: call reconcile.
    assert: the charm reaches blocked status.
    """
    state_from_charm_mock.side_effect = InvalidStateError()
    harness = Harness(WazuhServerCharm)
    harness.begin()
    container = harness.model.unit.containers.get("wazuh-server")
    assert container
    harness.set_can_connect(container, True)

    harness.charm.reconcile()

    assert harness.model.unit.status.name == ops.BlockedStatus().name


@patch.object(WazuhServerCharm, "reconcile")
def test_pebble_ready_reaches_blocked_status_when_no_state(reconcile_mock):
    """
    arrange: mock the reconcile method.
    act: trigger a pebble ready event reconcile.
    assert: reconcile is called.
    """
    harness = Harness(WazuhServerCharm)
    harness.begin()
    harness.container_pebble_ready("wazuh-server")

    harness.charm.reconcile()

    reconcile_mock.assert_called()
