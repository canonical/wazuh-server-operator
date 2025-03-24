# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""The Certificates relation observer."""

import logging

from charms.data_platform_libs.v0.data_interfaces import OpenSearchRequires
from ops.framework import Object

from state import CharmBaseWithState

logger = logging.getLogger(__name__)
RELATION_NAME = "opensearch-client"


class OpenSearchObserver(Object):
    """The Opensearch relation observer."""

    def __init__(self, charm: CharmBaseWithState):
        """Initialize the observer and register event handlers.

        Args:
            charm: The parent charm to attach the observer to.
        """
        super().__init__(charm, RELATION_NAME)
        self._charm = charm
        self.opensearch = OpenSearchRequires(
            charm, RELATION_NAME, "placeholder", extra_user_roles="admin"
        )

        self.framework.observe(
            self._charm.on.opensearch_client_relation_changed, self._charm.reconcile
        )
