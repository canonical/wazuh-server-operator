# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""The Traefik route relation observer."""

import logging

import ops
from charms.traefik_route_k8s.v0.traefik_route import (
    TraefikRouteRequirer,
    TraefikRouteRequirerReadyEvent,
)
from ops.framework import Object

logger = logging.getLogger(__name__)
RELATION_NAME = "traefik-route"


class TraefikRouteObserver(Object):
    """The Traefik route relation observer."""

    def __init__(self, charm: ops.CharmBase):
        """Initialize the observer and register event handlers.

        Args:
            charm: The parent charm to attach the observer to.
        """
        super().__init__(charm, RELATION_NAME)
        self._charm = charm
        self.traefik_route = TraefikRouteRequirer(
            charm, self.model.relations.get(RELATION_NAME), RELATION_NAME
        )
        self.framework.observe(self.traefik_route.on.ready, self._on_traefik_route_requirer_ready)

    def _configure_traefik_route(self) -> None:
        """Build a raw ingress configuration for Traefik."""
        if not self._charm.unit.is_leader():
            return
        entry_points = {}
        # Ports for agent communication, agent enrollment and API, respectively
        for port in ["1514", "1515", "55000"]:
            entry_points["tcp"] = {"address": f":{port}"}
        self.traefik_route.submit_to_traefik(config={"entryPoints": entry_points})

    def _on_traefik_route_requirer_ready(self, _: TraefikRouteRequirerReadyEvent) -> None:
        """Relation joined handler for the traefik route requirer ready event."""
        self._configure_traefik_route()
