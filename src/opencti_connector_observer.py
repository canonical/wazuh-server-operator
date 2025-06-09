# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""The Certificates relation observer."""

import logging

import ops
from ops.framework import Object

from state import CharmBaseWithState

logger = logging.getLogger(__name__)

RELATION_NAME = "opencti-connector"
CONNECTOR_TYPE = "EXTERNAL_IMPORT"


class OpenCTIObserver(Object):
    """The OpenCTI relation observer."""

    def __init__(self, charm: CharmBaseWithState):
        """Initialize the observer and register event handlers.

        Args:
            charm: The parent charm to attach the observer to.
        """
        super().__init__(charm, RELATION_NAME)
        self._charm = charm
        self.framework.observe(
            self._charm.on.opencti_connector_relation_joined, self._on_opencti_relation_joined
        )
        self.framework.observe(
            self._charm.on.opencti_connector_relation_changed, self._charm.reconcile
        )

    def _on_opencti_relation_joined(self, event: ops.RelationJoinedEvent) -> None:
        """Handle OpenCTI relation joined event.

        Args:
            event: The relation joined event.
        """
        if not self._charm.unit.is_leader():
            return
        relation = event.relation
        app_data = relation.data[self._charm.app]
        app_data["connector_charm_name"] = self._charm.meta.name
        app_data["connector_type"] = CONNECTOR_TYPE
