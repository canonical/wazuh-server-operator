#!/usr/bin/env python3

# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Wazuh server charm."""

import logging
import secrets
import typing

import ops
from ops import pebble

import certificates_observer
import opensearch_observer
import traefik_route_observer
import wazuh
from state import (
    WAZUH_API_CREDENTIALS,
    WAZUH_CLUSTER_KEY_SECRET_LABEL,
    WAZUH_DEFAULT_API_CREDENTIALS,
    CharmBaseWithState,
    InvalidStateError,
    RecoverableStateError,
    State,
)

logger = logging.getLogger(__name__)


WAZUH_PEER_RELATION_NAME = "wazuh-peers"


class WazuhServerCharm(CharmBaseWithState):
    """Charm the service.

    Attributes:
        fqdns: the unit FQDNs.
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

        self.framework.observe(self.on.install, self._on_install)
        self.framework.observe(self.on.wazuh_server_pebble_ready, self.reconcile)
        self.framework.observe(self.on.config_changed, self.reconcile)
        self.framework.observe(self.on[WAZUH_PEER_RELATION_NAME].relation_joined, self.reconcile)
        self.framework.observe(self.on[WAZUH_PEER_RELATION_NAME].relation_changed, self.reconcile)

    def _on_install(self, _: ops.InstallEvent) -> None:
        """Install event handler."""
        if self.unit.is_leader():
            try:
                self.model.get_secret(label=WAZUH_CLUSTER_KEY_SECRET_LABEL)
            except ops.SecretNotFoundError:
                logger.debug(
                    "Secret with label %s not found. Creating one.", WAZUH_CLUSTER_KEY_SECRET_LABEL
                )
                self.app.add_secret(
                    {"value": secrets.token_hex(16)}, label=WAZUH_CLUSTER_KEY_SECRET_LABEL
                )

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
            raise exc
        except RecoverableStateError as exc:
            logger.error("Invalid charm configuration, %s", exc)
            self.unit.status = ops.BlockedStatus("Charm state is invalid")
            return None

    def reconcile(self, _: ops.HookEvent) -> None:
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
        wazuh.update_configuration(
            container, self.state.indexer_ips, self.fqdns, self.unit.name, self.state.cluster_key
        )
        container.add_layer("wazuh", self._pebble_layer, combine=True)
        container.replan()

        if self.state.is_default_api_password:
            credentials = wazuh.generate_api_credentials()
            for username, password in credentials.items():
                wazuh.change_api_password(
                    username, WAZUH_DEFAULT_API_CREDENTIALS[username], password
                )
            self.app.add_secret(credentials, label=WAZUH_API_CREDENTIALS)
        self.unit.set_workload_version(wazuh.get_version(container))
        self.unit.status = ops.ActiveStatus()

    @property
    def _pebble_layer(self) -> pebble.LayerDict:
        """Return a dictionary representing a Pebble layer."""
        environment = {}
        # self.state will never be None at this point
        proxy = self.state.proxy  # type: ignore
        if proxy.http_proxy:
            environment["HTTP_PROXY"] = str(proxy.http_proxy)
        if proxy.https_proxy:
            environment["HTTPS_PROXY"] = str(proxy.https_proxy)
        if proxy.no_proxy:
            environment["NO_PROXY"] = proxy.no_proxy
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
                    "environment": environment,
                },
                "filebeat": {
                    "override": "replace",
                    "summary": "filebeat",
                    "command": (
                        "/usr/share/filebeat/bin/filebeat -c /etc/filebeat/filebeat.yml "
                        "--path.home /usr/share/filebeat --path.config /etc/filebeat "
                        "--path.data /var/lib/filebeat --path.logs /var/log/filebeat"
                    ),
                    "startup": "enabled",
                },
            },
            "checks": {
                "wazuh-alive": {
                    "override": "replace",
                    "level": "alive",
                    "tcp": {"port": 55000},
                },
                "filebeat-alive": {
                    "override": "replace",
                    "level": "alive",
                    "exec": {"command": "filebeat test output"},
                },
            },
        }

    @property
    def fqdns(self) -> list[str]:
        """Get the FQDNS for the charm units.

        Returns: the list of FQDNs for the charm units.
        """
        unit_name = self.unit.name.replace("/", "-")
        app_name = self.app.name
        addresses = [f"{unit_name}.{app_name}-endpoints"]
        peer_relation = self.model.relations[WAZUH_PEER_RELATION_NAME]
        if peer_relation:
            relation = peer_relation[0]
            # relation.units will contain all the units after the relation-joined event
            # since a relation-changed is emitted for every relation-joined event.
            for u in relation.units:
                # FQDNs have the form
                # <unit-name>.<app-name>-endpoints.<model-name>.svc.cluster.local
                unit_name = u.name.replace("/", "-")
                address = f"{unit_name}.{app_name}-endpoints"
                addresses.append(address)
        return addresses


if __name__ == "__main__":  # pragma: nocover
    ops.main.main(WazuhServerCharm)
