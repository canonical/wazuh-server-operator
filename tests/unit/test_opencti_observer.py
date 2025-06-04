# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenCTI observer unit tests."""

import ops
from ops.testing import Harness

from opencti_connector_observer import CONNECTOR_TYPE, RELATION_NAME, OpenCTIObserver

REQUIRER_METADATA = """
name: observer-charm
requires:
  opencti-connector:
    interface: opencti-connectors
"""


class ObservedCharm(ops.CharmBase):
    """Class for requirer charm testing."""

    def __init__(self, *args):
        """Construct.

        Args:
            args: Variable list of positional arguments passed to the parent constructor.
        """
        super().__init__(*args)
        self.observer = OpenCTIObserver(self)
        self.count = 0

    def reconcile(self, _: ops.HookEvent) -> None:
        """Reconcile the configuration with charm state."""
        self.count = self.count + 1


def test_relation_joined_sets_data() -> None:
    """
    arrange: instantiate a charm implementing the OpenCTI connector relation.
    act: add a relation and a leader unit to the OpenCTI connector.
    assert: the relation data is set with the connector charm name and type.
    """
    harness = Harness(ObservedCharm, meta=REQUIRER_METADATA)
    harness.begin_with_initial_hooks()
    harness.set_leader(True)
    rel_id = harness.add_relation(RELATION_NAME, "opencti-connector")
    harness.add_relation_unit(rel_id, "opencti-connector/0")

    app_data = harness.get_relation_data(rel_id, harness.charm.app.name)
    assert app_data["connector_charm_name"] == harness.charm.meta.name
    assert app_data["connector_type"] == CONNECTOR_TYPE


def test_relation_joined_does_nothing_if_not_leader() -> None:
    """
    arrange: instantiate a charm implementing the OpenCTI connector relation.
    act: add a relation and a non-leader unit to the OpenCTI connector.
    assert: the relation data is not set.
    """
    harness = Harness(ObservedCharm, meta=REQUIRER_METADATA)
    harness.begin_with_initial_hooks()
    harness.set_leader(False)
    rel_id = harness.add_relation(RELATION_NAME, "opencti-connector")
    harness.add_relation_unit(rel_id, "opencti-connector/0")

    app_data = harness.get_relation_data(rel_id, harness.charm.app.name)
    assert "connector_charm_name" not in app_data
    assert "connector_type" not in app_data


def test_relation_changed_calls_reconcile() -> None:
    """
    arrange: instantiate a charm implementing the OpenCTI connector relation.
    act: add a relation and update its data.
    assert: the reconcile method is called once.
    """
    harness = Harness(ObservedCharm, meta=REQUIRER_METADATA)
    harness.begin_with_initial_hooks()
    rel_id = harness.add_relation(RELATION_NAME, "opencti-connector")
    harness.update_relation_data(rel_id, "opencti-connector", {"dummy": "value"})

    assert harness.charm.count == 1
