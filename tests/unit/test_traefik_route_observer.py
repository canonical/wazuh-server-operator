# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

# pylint detects the patches states as duplicate code
# pylint: disable=duplicate-code

"""Traefik route observer unit tests."""

import secrets
import unittest

import ops
import pytest
from ops.testing import Harness

import state
import traefik_route_observer
import wazuh

REQUIRER_METADATA = """
name: observer-charm
requires:
  ingress:
    interface: traefik_route
"""


class ObservedCharm(state.CharmBaseWithState):
    """Class for requirer charm testing.

    Attrs:
        state: the charm state.
        units_fqdns: the charm units' FQDNs.
    """

    def __init__(self, *args):
        """Construct.

        Args:
            args: Variable list of positional arguments passed to the parent constructor.
        """
        super().__init__(*args)
        self.traefik_route = traefik_route_observer.TraefikRouteObserver(self)
        self.count = 0

    def reconcile(self, _: ops.HookEvent) -> None:
        """Reconcile the configuration with charm state."""
        self.count = self.count + 1

    @property
    def units_fqdns(self) -> list[str]:
        """Retrieve the FQDNs of the charm units.

        Returns: a list of FQDNs.
        """
        return ["host1.example", "host2.example"]

    @property
    def state(self) -> state.State | None:
        """The charm state."""
        password = secrets.token_hex()
        api_credentials = {
            "wazuh": secrets.token_hex(),
            "wazuh-wui": secrets.token_hex(),
            "prometheus": secrets.token_hex(),
        }
        cluster_key = secrets.token_hex(16)
        return state.State(
            agent_password=None,
            api_credentials=api_credentials,
            certificate="certificate",
            cluster_key=cluster_key,
            indexer_endpoints=["10.0.0.1"],
            filebeat_username="user1",
            filebeat_password=password,
            root_ca="root_ca",
            wazuh_config=state.WazuhConfig(
                api_credentials=api_credentials,
                custom_config_repository=None,
                custom_config_ssh_key=None,
                logs_ca_cert="fakeca",
            ),
            custom_config_ssh_key=None,
        )


def test_on_traefik_route_relation_joined_when_leader(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    arrange: instantiate a charm with leadership implementing the ingress relation.
    act: integrate the charm leveraging the ingress integration.
    assert: the ingress is configured with the appropriate values.
    """
    harness = Harness(ObservedCharm, meta=REQUIRER_METADATA)
    harness.set_model_name("testing")
    harness.begin_with_initial_hooks()
    harness.set_leader(True)
    harness.add_relation(traefik_route_observer.RELATION_NAME, "ingress-provider")

    requirer_mock = unittest.mock.MagicMock()
    requirer_mock.is_ready.return_value = True
    monkeypatch.setattr(harness.charm.traefik_route, "traefik_route", requirer_mock)

    harness.charm.traefik_route.reconcile()

    requirer_mock.submit_to_traefik.assert_called_once_with(
        {
            "tcp": {
                "routers": {
                    "juju-testing-observer-charm-syslog-tcp": {
                        "entryPoints": ["syslog-tcp"],
                        "service": "juju-testing-observer-charm-service-syslog-tcp",
                        "rule": "ClientIP(`0.0.0.0/0`)",
                    },
                    "juju-testing-observer-charm-conn-tcp": {
                        "entryPoints": ["conn-tcp"],
                        "service": "juju-testing-observer-charm-service-conn-tcp",
                        "rule": "ClientIP(`0.0.0.0/0`)",
                    },
                    "juju-testing-observer-charm-enrole-tcp": {
                        "entryPoints": ["enrole-tcp"],
                        "service": "juju-testing-observer-charm-service-enrole-tcp",
                        "rule": "ClientIP(`0.0.0.0/0`)",
                    },
                    "juju-testing-observer-charm-api-tcp": {
                        "entryPoints": ["api-tcp"],
                        "service": "juju-testing-observer-charm-service-api-tcp",
                        "rule": "ClientIP(`0.0.0.0/0`)",
                    },
                },
                "services": {
                    "juju-testing-observer-charm-service-syslog-tcp": {
                        "loadBalancer": {
                            "servers": [
                                {"address": "host1.example:6514"},
                                {"address": "host2.example:6514"},
                            ],
                            "terminationDelay": -1,
                        }
                    },
                    "juju-testing-observer-charm-service-conn-tcp": {
                        "loadBalancer": {
                            "servers": [
                                {"address": "host1.example:1514"},
                                {"address": "host2.example:1514"},
                            ],
                            "terminationDelay": -1,
                        }
                    },
                    "juju-testing-observer-charm-service-enrole-tcp": {
                        "loadBalancer": {
                            "servers": [
                                {"address": "host1.example:1515"},
                                {"address": "host2.example:1515"},
                            ],
                            "terminationDelay": -1,
                        }
                    },
                    "juju-testing-observer-charm-service-api-tcp": {
                        "loadBalancer": {
                            "servers": [
                                {"address": f"host1.example:{wazuh.API_PORT}"},
                                {"address": f"host2.example:{wazuh.API_PORT}"},
                            ],
                            "terminationDelay": -1,
                        }
                    },
                },
            },
        },
        static={
            "entryPoints": {
                "syslog-tcp": {"address": ":6514"},
                "conn-tcp": {"address": ":1514"},
                "enrole-tcp": {"address": ":1515"},
                "api-tcp": {"address": f":{wazuh.API_PORT}"},
            }
        },
    )


def test_on_traefik_route_relation_joined_when_not_leader(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    arrange: instantiate a charm without leadership implementing the ingress relation.
    act: integrate the charm leveraging the ingress integration.
    assert: the ingress configuration is not changed.
    """
    harness = Harness(ObservedCharm, meta=REQUIRER_METADATA)
    harness.begin_with_initial_hooks()
    harness.set_leader(False)
    harness.add_relation(traefik_route_observer.RELATION_NAME, "ingress-provider")
    mock = unittest.mock.Mock()
    monkeypatch.setattr(harness.charm.traefik_route.traefik_route, "submit_to_traefik", mock)

    harness.charm.traefik_route.reconcile()

    mock.assert_not_called()
