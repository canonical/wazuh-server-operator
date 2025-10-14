#!/usr/bin/env python3

# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Wazuh Server charm."""

import logging
import secrets
import time
import typing
from socket import getfqdn

import ops
import pydantic
from charms.wazuh_server.v0 import wazuh_api
from ops import pebble

import certificates_observer
import observability
import opencti_connector_observer
import opensearch_observer
import state
import traefik_route_observer
import wazuh
from state import (
    WAZUH_CLUSTER_KEY_SECRET_LABEL,
    CharmBaseWithState,
    IncompleteStateError,
    InvalidStateError,
    RecoverableStateError,
    State,
)

logger = logging.getLogger(__name__)

WAZUH_PEER_RELATION_NAME = "wazuh-peers"
WAZUH_SERVICE_NAME = "wazuh"
FILEBEAT_SERVICE_NAME = "filebeat"
RSYSLOG_SERVICE_NAME = "rsyslog"


class WazuhServerCharm(CharmBaseWithState):
    """Charm the service.

    Attributes:
        external_hostname: the external hostname.
        master_fqdn: the FQDN for unit 0.
        state: the charm state.
        units_fqdns: the charm units' FQDNs.
    """

    def __init__(self, *args: typing.Any):
        """Construct.

        Args:
            args: Arguments passed to the CharmBase parent constructor.
        """
        super().__init__(*args)
        self.certificates = certificates_observer.CertificatesObserver(self)
        self.traefik_route_observer = traefik_route_observer.TraefikRouteObserver(self)
        self.opensearch = opensearch_observer.OpenSearchObserver(self)
        self._observability = observability.Observability(self)
        self._wazuh_api = wazuh_api.WazuhApiProvides(self)
        self._opencti_observer = opencti_connector_observer.OpenCTIObserver(self)
        self._cached_state = None

        self.framework.observe(self.on.install, self._on_install)
        self.framework.observe(self.on.wazuh_server_pebble_ready, self.reconcile)
        self.framework.observe(self.on.config_changed, self.reconcile)
        self.framework.observe(self.on[WAZUH_PEER_RELATION_NAME].relation_joined, self.reconcile)
        self.framework.observe(self.on[WAZUH_PEER_RELATION_NAME].relation_changed, self.reconcile)
        self.framework.observe(self.on[WAZUH_PEER_RELATION_NAME].relation_departed, self.reconcile)
        self.framework.observe(self.on[wazuh_api.RELATION_NAME].relation_changed, self.reconcile)
        self.framework.observe(self.on[wazuh_api.RELATION_NAME].relation_broken, self.reconcile)

    @property
    def units_fqdns(self) -> list[str]:
        """Retrieve the FQDNs of the charm units.

        Returns: a list of FQDNs.
        """
        peer_relation = self.model.get_relation(WAZUH_PEER_RELATION_NAME)
        if not peer_relation:
            return [getfqdn()]
        return [
            f"{unit.name.replace('/', '-')}.{self.app.name}-endpoints"
            for unit in peer_relation.units
        ] + [getfqdn()]

    def _on_install(self, _: ops.InstallEvent) -> None:
        """Install event handler."""
        if self.unit.is_leader():
            try:
                self.model.get_secret(label=WAZUH_CLUSTER_KEY_SECRET_LABEL)
            except ops.SecretNotFoundError:
                logger.info(
                    "Secret with label %s not found. Creating one.", WAZUH_CLUSTER_KEY_SECRET_LABEL
                )
                self.app.add_secret(
                    {"value": secrets.token_hex(16)}, label=WAZUH_CLUSTER_KEY_SECRET_LABEL
                )

    def _populate_wazuh_api_relation_data(self) -> None:
        """Wazuh client API relation created event handler.

        Raises:
            InvalidStateError: if the secret doesn't exist.
        """
        _ = self.state  # Ensure the state is valid
        if self.unit.is_leader():
            try:
                secret = self.model.get_secret(label=wazuh_api.WAZUH_API_KEY_SECRET_LABEL)
                relation_data = wazuh_api.WazuhApiRelationData(
                    endpoint=pydantic.AnyHttpUrl(
                        f"https://{self.external_hostname}:{wazuh.API_PORT}"
                    ),
                    user="wazuh-wui",
                    password=self.state.api_credentials["wazuh-wui"],
                    user_credentials_secret=secret.get_info().id,
                )
                relation = self.model.get_relation(wazuh_api.RELATION_NAME)
                if relation:
                    self._wazuh_api.update_relation_data(relation, relation_data)
                    secret.grant(relation)
            except ops.SecretNotFoundError as exc:
                raise InvalidStateError from exc

    @property
    def state(self) -> State:
        """The charm state."""
        if self._cached_state is None:
            opensearch_relation = self.model.get_relation(opensearch_observer.RELATION_NAME)
            opensearch_relation_data = (
                opensearch_relation.data[opensearch_relation.app] if opensearch_relation else {}
            )
            opencti_relation = self.model.get_relation(opencti_connector_observer.RELATION_NAME)
            opencti_relation_data = (
                opencti_relation.data[opencti_relation.app] if opencti_relation else {}
            )
            certificates = self.certificates.certificates.get_provider_certificates()
            self._cached_state = State.from_charm(
                self,
                certificate_signing_request=self.certificates.get_csr().decode("utf-8"),
                indexer_relation_data=opensearch_relation_data,
                opencti_relation_data=opencti_relation_data,
                provider_certificates=certificates,
            )
        return self._cached_state

    @property
    def external_hostname(self) -> str | None:
        """The external hostname."""
        traefik_route_relation = self.model.get_relation(traefik_route_observer.RELATION_NAME)
        traefik_route_relation_data = (
            traefik_route_relation.data[traefik_route_relation.app]
            if traefik_route_relation
            else {}
        )
        return traefik_route_relation_data.get("external_host")

    def _restart_service(
        self, container: ops.Container, service_name: str, force: bool = False
    ) -> None:
        """Restart a pebble service.

        Args:
            container (ops.Container): the container on which to restart the service.
            service_name (str): the service to restart.
            force (bool): restart the service even if it is not running.
        """
        if service_name not in container.get_services().keys():
            logger.warning('service "%s" cannot be restarted, it does not exist', service_name)
            return
        if container.get_service(service_name).is_running() or force:
            logger.info('restarting service "%s"', service_name)
            container.restart(service_name)
        else:
            logger.info('not restarting service "%s" (it is not running)', service_name)

    def _reconcile_filebeat(self, container: ops.Container) -> None:
        """Reconcile the filebeat configuration.

        Args:
            container: the container to configure Wazuh for.
        """
        changed_certs: bool = wazuh.sync_certificates(
            container=container,
            path=wazuh.FILEBEAT_CERTIFICATES_PATH,
            private_key=self.certificates.get_private_key(),
            public_key=self.state.certificate,
            root_ca=self.state.root_ca,
            user=wazuh.FILEBEAT_USER,
            group=wazuh.FILEBEAT_USER,
        )
        changed_user = wazuh.sync_filebeat_user(
            container, self.state.filebeat_username, self.state.filebeat_password
        )
        changed_config = wazuh.sync_filebeat_config(container, self.state.indexer_endpoints)
        if any((changed_certs, changed_user, changed_config)):
            self._restart_service(container, FILEBEAT_SERVICE_NAME)

    def _reconcile_rsyslog(self, container: ops.Container) -> None:
        """Reconcile the rsyslog configuration.

        Args:
            container: the container to configure Wazuh for.

        Raises:
            WazuhConfigurationError: if no rsyslog CA certificate has been configured.
        """
        if not self.state.logs_ca_cert:
            raise wazuh.WazuhConfigurationError(
                "Invalid charm configuration: 'logs-ca-cert' is missing."
            )
        updated_config: bool = False
        if self.state.custom_config_repository is not None:
            updated_config = wazuh.sync_rsyslog_config_files(container)

        changed_certs: bool = wazuh.sync_certificates(
            container=container,
            path=wazuh.SYSLOG_CERTIFICATES_PATH,
            private_key=self.certificates.get_private_key(),
            public_key=self.state.certificate,
            root_ca=self.state.logs_ca_cert,
            user=wazuh.SYSLOG_USER,
            group=wazuh.SYSLOG_USER,
        )
        changed_filesystem = wazuh.ensure_rsyslog_output_dir(container)
        if any((updated_config, changed_certs, changed_filesystem)):
            self._restart_service(container, RSYSLOG_SERVICE_NAME)

    def _reconcile_wazuh(self, container: ops.Container) -> None:
        """Reconcile the Wazuh installation.

        Args:
            container: the container to configure Wazuh for.
        """
        updated_config: bool = False
        if self.state.custom_config_repository is not None:
            updated_config = wazuh.sync_wazuh_config_files(container)
        changed_password = False
        if self.state.agent_password:
            changed_password = wazuh.sync_agent_password(
                container=container,
                password=self.state.agent_password,
            )
        changed_ossec_conf: bool = wazuh.sync_ossec_conf(
            container,
            self.state.indexer_endpoints,
            self.master_fqdn,
            self.unit.name,
            self.state.cluster_key,
            opencti_token=self.state.opencti_token,
            opencti_url=self.state.opencti_url,
        )
        if any((updated_config, changed_password, changed_ossec_conf)):
            self._restart_service(container, WAZUH_SERVICE_NAME, force=True)

    # It doesn't make sense to split the logic further
    # Ignoring method too complex error from pflake8
    def _configure_users(self) -> None:  # noqa: C901
        """Configure Wazuh users."""
        # The prometheus exporter requires the users to be set up
        if not self.state:
            return
        for username, details in state.WAZUH_USERS.items():
            token = None
            # The user has already been created when installing
            credentials = self.state.api_credentials
            if details["default"]:
                logger.debug("Configuring default user %s", username)
                try:
                    token = wazuh.authenticate_user(username, details["default_password"])
                    password = (
                        wazuh.generate_api_password()
                        if credentials[username] == details["default_password"]
                        else credentials[username]
                    )
                    wazuh.change_api_password(username, password, token)
                    credentials[username] = password
                    logger.debug("Changed password for API user %s", username)
                except wazuh.WazuhAuthenticationError:
                    logger.debug("Could not authenticate user %s with default password.", username)
            else:
                logger.debug("Configuring non-default user %s", username)
                token = wazuh.authenticate_user("wazuh", credentials["wazuh"])
                password = credentials[username]
                if not password:
                    password = wazuh.generate_api_password()
                wazuh.create_readonly_api_user(username, password, token)
                credentials[username] = password
                logger.debug("Created API user %s", username)
            # Store the new credentials alongside the existing ones
            try:
                secret = self.model.get_secret(label=state.WAZUH_API_CREDENTIALS)
                if dict(secret.get_content(refresh=True)) != credentials:
                    secret.set_content(credentials)
                logger.debug("Updated secret %s with credentials", secret.id)
            except ops.SecretNotFoundError:
                if self.unit.is_leader():
                    secret = self.app.add_secret(credentials, label=state.WAZUH_API_CREDENTIALS)
                    logger.debug("Added secret %s with credentials", secret.id)
        api_key_secret_content = {
            "user": "wazuh-wui",
            "password": self.state.api_credentials["wazuh-wui"],
        }
        try:
            secret = self.model.get_secret(label=wazuh_api.WAZUH_API_KEY_SECRET_LABEL)
            if dict(secret.get_content(refresh=True)) != api_key_secret_content:
                secret.set_content(api_key_secret_content)
            logger.debug("Updated secret %s with API credentials", secret.id)
        except ops.SecretNotFoundError:
            if self.unit.is_leader():
                secret = self.app.add_secret(
                    api_key_secret_content, label=wazuh_api.WAZUH_API_KEY_SECRET_LABEL
                )
                logger.debug("Added secret %s with API credentials", secret.id)

    def reconcile(self, _: ops.HookEvent) -> None:  # noqa: C901
        """Reconcile Wazuh configuration with charm state.

        This is the main entry for changes that require a restart.

        Raises:
            InvalidStateError: if the charm configuration is invalid.
        """
        reconcile_start_time = time.perf_counter()
        container: ops.Container = self.unit.get_container(wazuh.CONTAINER_NAME)
        if not container.can_connect():
            logger.warning("Cannot connect to container during reconcile. Waiting for new events.")
            self.unit.status = ops.WaitingStatus("Waiting for pebble.")
            return
        try:
            _ = self.state  # Ensure the state is valid

            wazuh.sync_config_repo(
                container,
                repository=self.state.custom_config_repository,
                repo_ssh_key=self.state.custom_config_ssh_key,
            )

            self._reconcile_filebeat(container)
            self._reconcile_rsyslog(container)
            self._reconcile_wazuh(container)
            container.add_layer("wazuh", self._wazuh_pebble_layer, combine=True)
            container.replan()

            self._configure_users()
            self._populate_wazuh_api_relation_data()
            # Fetch the new wazuh layer, which has different env vars
            logger.debug("Reconfiguring pebble layers")
            container.add_layer("wazuh", self._wazuh_pebble_layer, combine=True)
            container.add_layer("prometheus", self._prometheus_pebble_layer, combine=True)
            container.replan()

            self.unit.set_workload_version(wazuh.get_version(container))
            self.unit.status = ops.ActiveStatus()
        except wazuh.WazuhNotReadyError:
            self.unit.status = ops.MaintenanceStatus("Waiting for Wazuh to be ready")
        except wazuh.WazuhConfigurationError as exc:
            self.unit.status = ops.BlockedStatus(str(exc))
        except RecoverableStateError as exc:
            logger.error("Invalid charm configuration, %s", exc)
            self.unit.status = ops.BlockedStatus("Charm state is invalid")
        except IncompleteStateError as exc:
            logger.error("Charm configuration not ready, %s", exc)
            self.unit.status = ops.WaitingStatus("Charm state is not yet ready")
        except InvalidStateError as exc:
            logger.error("Invalid charm configuration, %s", exc)
            raise InvalidStateError from exc
        except ops.pebble.APIError as exc:
            logger.warning("Pebble/API not available during reconcile: %s", exc)
            self.unit.status = ops.WaitingStatus("Waiting for pebble.")
            return
        elapsed = time.perf_counter() - reconcile_start_time
        logger.debug("reconciled charm in %s seconds", elapsed)

    @property
    def _wazuh_pebble_layer(self) -> pebble.LayerDict:
        """Return a dictionary representing a Pebble layer for Wazuh."""
        environment = {}
        # self.state will never be None at this point
        proxy = self.state.proxy  # type: ignore
        if proxy.http_proxy:
            environment["HTTP_PROXY"] = str(proxy.http_proxy)
        if proxy.https_proxy:
            environment["HTTPS_PROXY"] = str(proxy.https_proxy)
        if proxy.no_proxy:
            environment["NO_PROXY"] = proxy.no_proxy
        if not self.state:
            return {}
        return {
            "summary": "wazuh manager layer",
            "description": "pebble config layer for wazuh-manager",
            "services": {
                WAZUH_SERVICE_NAME: {
                    "override": "replace",
                    "summary": "wazuh manager",
                    "command": "sh -c 'sleep 1; /var/ossec/bin/wazuh-control reload'",
                    "startup": "enabled",
                    "on-success": "ignore",
                    "environment": environment,
                },
                FILEBEAT_SERVICE_NAME: {
                    "override": "replace",
                    "summary": "filebeat",
                    "command": f"sh -c 'sleep 1; {' '.join(wazuh.FILEBEAT_CMD)}'",
                    "startup": "enabled",
                },
                RSYSLOG_SERVICE_NAME: {
                    "override": "replace",
                    "summary": "rsyslog",
                    "command": "rsyslogd -n -f /etc/rsyslog.conf",
                    "startup": "enabled",
                },
            },
            "checks": {
                "wazuh-alive": {
                    "override": "replace",
                    "level": "alive",
                    "threshold": 10,
                    "tcp": {"port": wazuh.API_PORT},
                },
            },
        }

    @property
    def _prometheus_pebble_layer(self) -> pebble.LayerDict:
        """Return a dictionary representing a Pebble layer for the Prometheus exporter."""
        if not self.state:
            return {}
        return {
            "summary": "wazuh exporter layer",
            "description": "pebble config layer for wazuh-exporter",
            "services": {
                "prometheus-exporter": {
                    "override": "replace",
                    "summary": "prometheus exporter",
                    "command": (
                        "sh -c 'sleep 1; /usr/bin/python3 /srv/prometheus/prometheus_exporter.py'"
                    ),
                    "startup": "enabled",
                    "user": "prometheus",
                    "after": ["wazuh"],
                    "requires": ["wazuh"],
                    "on-failure": "restart",
                    "environment": {
                        "WAZUH_API_HOST": "localhost",
                        "WAZUH_API_PORT": f"{wazuh.API_PORT}",
                        "WAZUH_API_USERNAME": "prometheus",
                        "WAZUH_API_PASSWORD": self.state.api_credentials["prometheus"],
                    },
                }
            },
            "checks": {
                "wazuh-exporter-alive": {
                    "override": "replace",
                    "level": "alive",
                    "threshold": 10,
                    "tcp": {"port": observability.PROMETHEUS_PORT},
                },
            },
        }

    @property
    def master_fqdn(self) -> str:
        """Get the FQDN for the unit 0.

        Returns: the FQDN for the unit 0.
        """
        unit_name = f"{self.unit.name.split('/')[0]}-0"
        app_name = self.app.name
        return f"{unit_name}.{app_name}-endpoints"


if __name__ == "__main__":  # pragma: nocover
    ops.main.main(WazuhServerCharm)
