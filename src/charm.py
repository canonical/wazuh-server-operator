#!/usr/bin/env python3

# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Wazuh server charm."""

import logging
import typing

import ops
from charms.data_platform_libs.v0.data_interfaces import OpenSearchRequires
from charms.operator_libs_linux.v0 import apt
from ops import pebble

import wazuh
from certificates_observer import CertificatesObserver
from state import InvalidStateError, State

logger = logging.getLogger(__name__)


class WazuhServerCharm(ops.CharmBase):
    """Charm the service."""

    def __init__(self, *args: typing.Any):
        """Construct.

        Args:
            args: Arguments passed to the CharmBase parent constructor.
        """
        super().__init__(*args)
        self.framework.observe(self.on.install, self._on_install)
        self.certificates = CertificatesObserver(self)
        self.opensearch = OpenSearchRequires(self, "opensearch-client", "dummy")
        try:
            self.state = State.from_charm(self, self.opensearch)
        except InvalidStateError:
            self.unit.status = ops.BlockedStatus()
            return
        self.framework.observe(
            self.on.wazuh_indexer_relation_changed, self._on_wazuh_indexer_relation_changed
        )
        self.framework.observe(
            self.on.wazuh_server_pebble_ready, self._on_wazuh_server_pebble_ready
        )

    def _on_install(self, _: ops.InstallEvent) -> None:
        """Install needed apt packages."""
        self.unit.status = ops.MaintenanceStatus("Installing packages")
        apt.add_package(["libssl-dev", "libxml2", "libxslt1-dev"], update_cache=True)
        self.unit.status = ops.ActiveStatus()

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
    ops.main.main(WazuhServerCharm)
