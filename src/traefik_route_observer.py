# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""The Traefik route relation observer."""

import logging
import typing

from charms.traefik_k8s.v0.traefik_route import TraefikRouteRequirer
from ops.framework import Object

import wazuh
from state import CharmBaseWithState

logger = logging.getLogger(__name__)
RELATION_NAME = "ingress"


PORTS: dict[str, int] = {
    "syslog_tcp": 6514,
    "conn_tcp": 1514,
    "enrole_tcp": 1515,
    "api_tcp": wazuh.API_PORT,
}


class TraefikRouteObserver(Object):
    """The Traefik route relation observer."""

    def __init__(self, charm: CharmBaseWithState):
        """Initialize the observer and register event handlers.

        Args:
            charm: The parent charm to attach the observer to.
        """
        super().__init__(charm, RELATION_NAME)
        self._charm = charm
        self.traefik_route = TraefikRouteRequirer(
            charm, self.model.get_relation(RELATION_NAME), RELATION_NAME, raw=True
        )
        self.reconcile()

    @property
    def _static_ingress_config(self) -> dict[str, dict[str, dict[str, str]]]:
        """Build a raw ingress static configuration for Traefik.

        Returns:
            the ingress static configuration for Traefik.
        """
        entry_points = {}
        for protocol, port in PORTS.items():
            sanitized_protocol = protocol.replace("_", "-")
            entry_points[sanitized_protocol] = {"address": f":{port}"}
        return {
            "entryPoints": entry_points,
        }

    @property
    def _ingress_config(self) -> dict[str, dict[str, dict[str, typing.Any]]]:
        """Build a raw ingress configuration for Traefik.

        Returns:
            the ingress configuration for Traefik.
        """
        routers: dict[str, typing.Any] = {}
        services = {}
        for protocol, port in PORTS.items():
            sanitized_protocol = protocol.replace("_", "-")
            router_name = f"juju-{self.model.name}-{self.model.app.name}-{sanitized_protocol}"
            service_name = (
                f"juju-{self.model.name}-{self.model.app.name}-service-{sanitized_protocol}"
            )
            routers[router_name] = {
                "entryPoints": [sanitized_protocol],
                "service": service_name,
                "rule": "ClientIP(`0.0.0.0/0`)",
            }
            services[service_name] = {
                "loadBalancer": {
                    "servers": [
                        {"address": f"{fqdn}:{port}"} for fqdn in self._charm.state.units_fqdns
                    ],
                    "terminationDelay": -1,
                }
            }
        return {
            "tcp": {
                "routers": routers,
                "services": services,
            },
        }

    def reconcile(self) -> None:
        """Build a raw ingress configuration for Traefik."""
        if not self._charm.unit.is_leader() or not self.traefik_route.is_ready():
            return
        _ = self._charm.state  # Ensure the state is valid
        self.traefik_route.submit_to_traefik(
            self._ingress_config, static=self._static_ingress_config
        )
