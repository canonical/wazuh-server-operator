# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charm unit tests."""
from unittest.mock import ANY, patch

import ops
import pytest
from ops.testing import Harness

import certificates_observer
import opensearch_observer
import wazuh
from charm import WazuhServerCharm
from state import InvalidStateError, State


@patch.object(State, "from_charm")
def test_invalid_state_reaches_blocked_status(state_from_charm_mock):
    """
    arrange: mock State.from_charm so that it raises and InvalidStateError.
    act: set up a charm with a missing relation.
    assert: the charm reaches blocked status.
    """
    state_from_charm_mock.side_effect = InvalidStateError()
    harness = Harness(WazuhServerCharm)
    harness.begin()

    assert harness.model.unit.status.name == ops.BlockedStatus().name


@pytest.mark.skip
@patch.object(wazuh, "update_configuration")
@patch.object(wazuh, "install_certificates")
def test_pebble_ready_reaches_active_status(
    wazuh_update_configuration_mock, wazuh_install_certificates_mock
):
    """
    arrange: mock system calls.
    act: set up a charm with a missing relation.
    assert: the charm reaches blocked status.
    """
    harness = Harness(WazuhServerCharm)
    harness.begin()
    harness.add_relation(
        opensearch_observer.RELATION_NAME, "opensearch", app_data={"endpoints": "10.0.0.1"}
    )
    harness.add_relation(
        certificates_observer.RELATION_NAME, "certificates", app_data={"certificates": "somecert"}
    )

    harness.container_pebble_ready("wazuh-server")
    container = harness.model.unit.containers.get("wazuh-server")
    wazuh_install_certificates_mock.assert_called_with(container, ANY, "somecert")
    wazuh_update_configuration_mock.assert_called_with(container, ["10.0.0.1"])
    assert harness.model.unit.status.name == ops.ActiveStatus().name
