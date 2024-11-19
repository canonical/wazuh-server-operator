# Copyright 2024 Canonical Ltd.
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
    harness.add_relation(opensearch_observer.RELATION_NAME, "opensearch-client-provider")
    relation = harness.charm.framework.model.get_relation(opensearch_observer.RELATION_NAME, 0)

    harness.charm.on.opensearch_client_relation_changed.emit(relation)

    assert harness.charm.count == 1
