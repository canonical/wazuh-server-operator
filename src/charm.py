#!/usr/bin/env python3

# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Wazuh server charm."""

import logging
import typing

import ops
from charms.data_platform_libs.v0.data_interfaces import OpenSearchRequires
from ops import pebble

import wazuh
from certificates_observer import CertificatesObserver
from state import CharmBaseWithState, InvalidStateError, State
from traefik_route_observer import TraefikRouteObserver

logger = logging.getLogger(__name__)


OPENSEARCH_RELATION_NAME = "opensearch-client"


class WazuhServerCharm(CharmBaseWithState):
    """Charm the service."""

    def __init__(self, *args: typing.Any):
        """Construct.

        Args:
            args: Arguments passed to the CharmBase parent constructor.
        """
        super().__init__(*args)
        self.certificates = CertificatesObserver(self)
        self.traefik_route = TraefikRouteObserver(self)
        self.opensearch = OpenSearchRequires(self, OPENSEARCH_RELATION_NAME, "placeholder")
        try:
            opensearch_relation = self.model.get_relation(OPENSEARCH_RELATION_NAME)
            opensearch_relation_data = (
                opensearch_relation.data[opensearch_relation.app] if opensearch_relation else {}
            )
            self.state = State.from_charm(self, opensearch_relation_data)
        except InvalidStateError:
            self.unit.status = ops.BlockedStatus("Charm state is invalid")
            return
        self.framework.observe(
            self.on.opensearch_client_relation_changed, self._on_opensearch_client_relation_changed
        )
        self.framework.observe(
            self.on.wazuh_server_pebble_ready, self._on_wazuh_server_pebble_ready
        )

    def _on_wazuh_server_pebble_ready(self, _: ops.PebbleReadyEvent) -> None:
        """Pebble ready handler for the wazuh-server container."""
        self.reconcile()

    def _on_opensearch_client_relation_changed(self, _: ops.RelationJoinedEvent) -> None:
        """Pebble ready handler for the wazuh-indexer relation changed event."""
        self.reconcile()

    def reconcile(self) -> None:
        """Reconcile Wazuh configuration with charm state.

        This is the main entry for changes that require a restart.
        """
        container = self.unit.get_container("wazuh-server")
        if not container.can_connect():
            logger.warning(
                "Unable to connect to container during reconcile. "
                "Waiting for future events which will trigger another reconcile."
            )
            return
        wazuh.update_configuration(container, self.state.indexer_ips)
        container.add_layer("wazuh-server", self._pebble_layer, combine=True)
        container.replan()
        self.unit.status = ops.ActiveStatus()

    @property
    def _pebble_layer(self) -> pebble.LayerDict:
        """Return a dictionary representing a Pebble layer."""
        return {
            "summary": "wazuh server layer",
            "description": "pebble config layer for wazuh-manager",
            "services": {
                "wazuh-server": {
                    "override": "replace",
                    "summary": "wazuh server",
                    "command": "systemctl start wazuh-manager",
                    "startup": "enabled",
                },
            },
            "checks": {
                "wazuh-server-ready": {
                    "override": "replace",
                    "level": "ready",
                    "http": {"url": "http://localhost:55000/"},
                },
            },
        }


if __name__ == "__main__":  # pragma: nocover
    ops.main.main(WazuhServerCharm)
