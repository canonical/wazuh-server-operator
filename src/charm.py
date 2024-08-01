#!/usr/bin/env python3

# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Wazhub server charm."""

import logging
import typing

import ops
from ops import pebble

import wazuh
from certificates_observer import CertificatesObserver
from state import InvalidStateError, State

logger = logging.getLogger(__name__)


class WazhubServerCharm(ops.CharmBase):
    """Charm the service."""

    def __init__(self, *args: typing.Any):
        """Construct.

        Args:
            args: Arguments passed to the CharmBase parent constructor.
        """
        super().__init__(*args)

        self.wazuh_indexer = self.model.get_relation("wazuh-indexer")
        self.certificates = CertificatesObserver(self)
        try:
            self.state = State.from_charm(self, self.wazuh_indexer)
        except InvalidStateError as exc:
            self.unit.status = ops.BlockedStatus(exc.msg)
            return
        self.framework.observe(
            self.on.wazuh_indexer_relation_changed, self._on_wazuh_indexer_relation_changed
        )
        self.framework.observe(
            self.on.wazuh_server_pebble_ready, self._on_wazuh_server_pebble_ready
        )

    def _on_wazuh_server_pebble_ready(self, _: ops.PebbleReadyEvent) -> None:
        """Peeble ready habndler for the wazuh-server container."""
        self._reconcile()

    def _on_wazuh_indexer_relation_changed(self, _: ops.RelationJoinedEvent) -> None:
        """Peeble ready habndler for the wazuh-indexer relation changed event."""
        self._reconcile()

    def _reconcile(self) -> None:
        """Reconcile Wazuh configuration with charm state.

        This is the main entry for changes that require a restart.
        """
        container = self.unit.get_container("wazuh-server")
        wazuh.update_configuration(container, self.state.indexer_ips)
        container.add_layer("wazuh", self._pebble_layer, combine=True)
        container.replan()

    @property
    def _pebble_layer(self) -> pebble.LayerDict:
        """Return a dictionary representing a Pebble layer."""
        return {
            "summary": "wazuh manager layer",
            "description": "pebble config layer for wazuh-manager",
            "services": {
                "httpbin": {
                    "override": "replace",
                    "summary": "wazuh manager",
                    "command": "systemctl start wazuh-manager",
                    "startup": "enabled",
                }
            },
        }


if __name__ == "__main__":  # pragma: nocover
    ops.main.main(WazhubServerCharm)
