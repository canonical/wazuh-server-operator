# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charm unit tests."""
from unittest.mock import patch

import ops
from charms.operator_libs_linux.v0 import apt
from ops.testing import Harness

from charm import OPENSEARCH_RELATION_NAME, WazuhServerCharm
from state import InvalidStateError, State


@patch.object(apt, "add_package")
def test_libs_installed(apt_add_package_mock):
    """
    arrange: set up a charm.
    act: trigger the install event.
    assert: the charm installs required packages.
    """
    harness = Harness(WazuhServerCharm)
    harness.begin()
    # First confirm no packages have been installed.
    apt_add_package_mock.assert_not_called()
    harness.charm.on.install.emit()
    # And now confirm we've installed the required packages.
    apt_add_package_mock.assert_called_once_with(
        ["libssl-dev", "libxml2", "libxslt1-dev"], update_cache=True
    )


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


# @patch.object(apt, "add_package")
# def test_pebble_ready_reaches_active_status(_):
#     """
#     arrange: mock State.from_charm so that it raises and InvalidStateError.
#     act: set up a charm with a missing relation.
#     assert: the charm reaches blocked status.
#     """
#     harness = Harness(WazuhServerCharm)
#     harness.add_relation(OPENSEARCH_RELATION_NAME, "opensearch", app_data={
#         "endpoints": "10.0.0.1"
#     })
#     harness.begin_with_initial_hooks()
#     assert harness.model.unit.status.name == ops.ActiveStatus().name
