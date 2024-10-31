#!/usr/bin/env python3

# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Wazuh server charm."""

import logging
import typing

import ops
from ops import pebble

import certificates_observer
import opensearch_observer
import traefik_route_observer
import wazuh
from state import CharmBaseWithState, InvalidStateError, State

logger = logging.getLogger(__name__)


class WazuhServerCharm(CharmBaseWithState):
    """Charm the service.

    Attributes:
        state: the charm state.
    """

    def __init__(self, *args: typing.Any):
        """Construct.

        Args:
            args: Arguments passed to the CharmBase parent constructor.
        """
        super().__init__(*args)
        self.certificates = certificates_observer.CertificatesObserver(self)
        self.traefik_route = traefik_route_observer.TraefikRouteObserver(self)
        self.opensearch = opensearch_observer.OpenSearchObserver(self)

        self.framework.observe(
            self.on.wazuh_server_pebble_ready, self._on_wazuh_server_pebble_ready
        )
        self.framework.observe(self.on.config_changed, self._on_config_changed)

    def _on_wazuh_server_pebble_ready(self, _: ops.PebbleReadyEvent) -> None:
        """Pebble ready handler."""
        self.reconcile()

    def _on_config_changed(self, _: ops.ConfigChangedEvent) -> None:
        """Config changed handler."""
        self.reconcile()

    @property
    def state(self) -> State | None:
        """The charm state."""
        try:
            opensearch_relation = self.model.get_relation(opensearch_observer.RELATION_NAME)
            opensearch_relation_data = (
                opensearch_relation.data[opensearch_relation.app] if opensearch_relation else {}
            )
            certificates = self.certificates.certificates.get_provider_certificates()
            return State.from_charm(
                self, opensearch_relation_data, certificates, self.certificates.csr.decode("utf-8")
            )
        except InvalidStateError as exc:
            logger.error("Invalid charm configuration, %s", exc)
            self.unit.status = ops.BlockedStatus("Charm state is invalid")
            return None

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
            self.unit.status = ops.WaitingStatus("Waiting for pebble.")
            return
        if not self.state:
            return
        wazuh.install_certificates(
            container=self.unit.containers.get("wazuh-server"),
            private_key=self.certificates.private_key,
            public_key=self.state.certificate,
            root_ca=self.state.root_ca,
        )
        wazuh.configure_git(
            container,
            (
                str(self.state.custom_config_repository)
                if self.state.custom_config_repository
                else None
            ),
            self.state.custom_config_ssh_key,
        )
        wazuh.configure_filebeat_user(
            container, self.state.filebeat_username, self.state.filebeat_password
        )
        if self.state.agent_password:
            wazuh.configure_agent_password(
                container=self.unit.containers.get("wazuh-server"),
                password=self.state.agent_password,
            )
        if self.state.custom_config_repository:
            wazuh.pull_configuration_files(container)
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
                    "command": "/var/ossec/bin/wazuh-control start",
                    "startup": "enabled",
                    "on-success": "ignore",
                },
                "filebeat": {
                    "override": "replace",
                    "summary": "filebear",
                    "command": (
                        "/usr/share/filebeat/bin/filebeat -c /etc/filebeat/filebeat.yml "
                        "--path.home /usr/share/filebeat --path.config /etc/filebeat "
                        "--path.data /var/lib/filebeat --path.logs /var/log/filebeat"
                    ),
                    "startup": "enabled",
                },
            },
        }


if __name__ == "__main__":  # pragma: nocover
    ops.main.main(WazuhServerCharm)
