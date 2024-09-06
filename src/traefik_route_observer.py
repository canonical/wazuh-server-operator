# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""The Traefik route relation observer."""

import logging
import typing

import ops
from charms.traefik_route_k8s.v0.traefik_route import TraefikRouteRequirer
from ops.framework import Object

logger = logging.getLogger(__name__)
RELATION_NAME = "traefik-route"


PORTS: dict[str, int] = {
    "conn_tcp": 1514,
    "enrole_tcp": 1515,
}


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
            charm, self.model.get_relation(RELATION_NAME), RELATION_NAME
        )
        if self.traefik_route.is_ready():
            self._configure_traefik_route()

    @property
    def _ingress_config(self) -> dict[str, dict[str, dict[str, typing.Any]]]:
        """Build a raw ingress configuration for Traefik.

        Returns:
            the ingress configuration for Traefik.
        """
        routers = {}
        services = {}
        entry_points = {}
        for protocol, port in PORTS.items():
            sanitized_protocol = protocol.replace("_", "-")
            entry_points[sanitized_protocol] = {"address": f":{port}"}
            service_name = (
                f"juju-{self.model.name}-{self.model.app.name}-service-{sanitized_protocol}"
            )
            routers[f"juju-{self.model.name}-{self.model.app.name}-{sanitized_protocol}"] = {
                "entryPoints": [sanitized_protocol],
                "service": service_name,
                "rule": "ClientIP(`0.0.0.0/0`)",
            }
            # TODO use the proper hostname  # pylint: disable=W0511
            services[service_name] = {
                "loadBalancer": {"servers": [{"address": f"{self.traefik_route.external_host}"}]}
            }
        return {
            "tcp": {
                "entryPoints": entry_points,
                "routers": routers,
                "services": services,
            },
        }

    def _configure_traefik_route(self) -> None:
        """Build a raw ingress configuration for Traefik."""
        if not self._charm.unit.is_leader() or not self.traefik_route.is_ready():
            return
        self.traefik_route.submit_to_traefik(self._ingress_config)
