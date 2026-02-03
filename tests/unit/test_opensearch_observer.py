# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Certificates observer unit tests."""

import ops
from ops.testing import Harness

import opensearch_observer

REQUIRER_METADATA = """
name: observer-charm
requires:
  opensearch-client:
    interface: opensearch_client
"""


class ObservedCharm(ops.CharmBase):
    """Class for requirer charm testing."""

    def __init__(self, *args):
        """Construct.

        Args:
            args: Variable list of positional arguments passed to the parent constructor.
        """
        super().__init__(*args)
        self.opensearch = opensearch_observer.OpenSearchObserver(self)
        self.count = 0

    def reconcile(self, _: ops.HookEvent) -> None:
        """Reconcile the configuration with charm state."""
        self.count = self.count + 1


def test_on_opensearch_client_relation_changed() -> None:
    """
    arrange: instantiate a charm implementing the opensearch client relation.
    act: integrate the charm leveraging the opensearch client integration.
    assert: the reconcile method is called.
    """
    harness = Harness(ObservedCharm, meta=REQUIRER_METADATA)
    harness.begin_with_initial_hooks()
    rel_id = harness.add_relation(opensearch_observer.RELATION_NAME, "opensearch-client-provider")
    harness.add_relation_unit(rel_id, "opensearch-client-provider/0")
    # Update relation data to trigger the relation-changed event
    harness.update_relation_data(rel_id, "opensearch-client-provider", {"test": "data"})

    assert harness.charm.count == 1
