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
from state import InvalidStateError, State
from traefik_route_observer import TraefikRouteObserver

logger = logging.getLogger(__name__)


OPENSEARCH_RELATION_NAME = "opensearch-client"


class WazuhServerCharm(ops.CharmBase):
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
            self.unit.status = ops.BlockedStatus()
            return
        self.framework.observe(
            self.on.opensearch_client_relation_changed, self._on_opensearch_client_relation_changed
        )
        self.framework.observe(
            self.on.wazuh_server_pebble_ready, self._on_wazuh_server_pebble_ready
        )

    def _on_wazuh_server_pebble_ready(self, _: ops.PebbleReadyEvent) -> None:
        """Peeble ready handler for the wazuh-server container."""
        self._reconcile()

    def _on_opensearch_client_relation_changed(self, _: ops.RelationJoinedEvent) -> None:
        """Peeble ready handler for the wazuh-indexer relation changed event."""
        self._reconcile()

    def _reconcile(self) -> None:
        """Reconcile Wazuh configuration with charm state.

        This is the main entry for changes that require a restart.
        """
        container = self.unit.get_container("wazuh-server")
        wazuh.update_configuration(container, self.state.indexer_ips)
        container.add_layer("wazuh", self._pebble_layer, combine=True)
        container.replan()
        self.unit.status = ops.ActiveStatus()

    @property
    def _pebble_layer(self) -> pebble.LayerDict:
        """Return a dictionary representing a Pebble layer."""
        return {
            "summary": "wazuh manager layer",
            "description": "pebble config layer for wazuh-manager",
            "services": {
                "wazuh": {
                    "override": "replace",
                    "summary": "wazuh manager",
                    "command": "systemctl start wazuh-manager",
                    "startup": "enabled",
                },
            },
            "checks": {
                "wazuh-ready": {
                    "override": "replace",
                    "level": "ready",
                    "http": {"url": "http://localhost:55000/"},
                },
            },
        }


if __name__ == "__main__":  # pragma: nocover
    ops.main.main(WazuhServerCharm)
