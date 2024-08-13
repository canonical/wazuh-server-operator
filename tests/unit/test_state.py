# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""State unit tests."""

from unittest.mock import MagicMock

import ops
import pytest

import state


def test_state_invalid_relation_data():
    """
    arrange: given an empty relation data.
    act: when state is initialized through from_charm method.
    assert: a InvalidStateError is raised.
    """
    mock_charm = MagicMock(spec=ops.CharmBase)

    with pytest.raises(state.InvalidStateError):
        state.State.from_charm(mock_charm, {})


def test_state():
    """
    arrange: given valid relation data.
    act: when state is initialized through from_charm method.
    assert: the state contains the endpoints.
    """
    mock_charm = MagicMock(spec=ops.CharmBase)
    endpoints = ["10.0.0.1", "10.0.0.2"]
    relation_data = {"endpoints": ",".join(endpoints)}

    charm_state = state.State.from_charm(mock_charm, relation_data)
    assert charm_state.indexer_ips == endpoints
