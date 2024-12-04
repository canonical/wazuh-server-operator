# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Traefik route observer unit tests."""

import socket
import unittest

import ops
import pytest
from ops.testing import Harness

import traefik_route_observer

REQUIRER_METADATA = """
name: observer-charm
requires:
  ingress:
    interface: traefik_route
"""


class ObservedCharm(ops.CharmBase):
    """Class for requirer charm testing."""

    def __init__(self, *args):
        """Construct.

        Args:
            args: Variable list of positional arguments passed to the parent constructor.
        """
        super().__init__(*args)
        self.traefik_route = traefik_route_observer.TraefikRouteObserver(self)


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
    monkeypatch.setattr(socket, "getfqdn", lambda: "wazuh-server.local")

    harness.charm.traefik_route._configure_traefik_route()  # pylint: disable=W0212

    requirer_mock.submit_to_traefik.assert_called_once_with(
        {
            "tcp": {
                "routers": {
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
                },
                "services": {
                    "juju-testing-observer-charm-service-conn-tcp": {
                        "loadBalancer": {
                            "servers": [{"address": "wazuh-server.local:1514"}],
                            "terminationDelay": 1000,
                        }
                    },
                    "juju-testing-observer-charm-service-enrole-tcp": {
                        "loadBalancer": {
                            "servers": [{"address": "wazuh-server.local:1515"}],
                            "terminationDelay": 1000,
                        }
                    },
                },
            },
        },
        static={
            "entryPoints": {
                "conn-tcp": {"address": ":1514"},
                "enrole-tcp": {"address": ":1515"},
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

    harness.charm.traefik_route._configure_traefik_route()  # pylint: disable=W0212

    mock.assert_not_called()
