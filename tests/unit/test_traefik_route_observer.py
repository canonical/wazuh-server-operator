# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Traefik route observer unit tests."""

import unittest

import ops
import pytest
from ops.testing import Harness

import traefik_route_observer

REQUIRER_METADATA = """
name: observer-charm
requires:
  traefik-route:
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
    arrange: instantiate a charm with leadership implementing the traefik-route relation.
    act: integrate the charm leveraging the traefik-route integration.
    assert: the ingress is configured with the appropriate values.
    """
    harness = Harness(ObservedCharm, meta=REQUIRER_METADATA)
    harness.begin_with_initial_hooks()
    harness.set_leader(True)
    harness.add_relation(traefik_route_observer.RELATION_NAME, "traefik-route-provider")
    mock = unittest.mock.Mock()
    monkeypatch.setattr(harness.charm.traefik_route.traefik_route, "submit_to_traefik", mock)

    harness.charm.traefik_route._configure_traefik_route()  # pylint: disable=W0212

    # XXX: This is likely wrong, should be three ports. # pylint: disable=W0511
    mock.assert_called_once_with(config={"entryPoints": {"tcp": {"address": ":55000"}}})


def test_on_traefik_route_relation_joined_when_not_leader(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    arrange: instantiate a charm without leadership implementing the traefik-route relation.
    act: integrate the charm leveraging the traefik-route integration.
    assert: the ingress configuration is not changed.
    """
    harness = Harness(ObservedCharm, meta=REQUIRER_METADATA)
    harness.begin_with_initial_hooks()
    harness.set_leader(False)
    harness.add_relation(traefik_route_observer.RELATION_NAME, "traefik-route-provider")
    mock = unittest.mock.Mock()
    monkeypatch.setattr(harness.charm.traefik_route.traefik_route, "submit_to_traefik", mock)

    harness.charm.traefik_route._configure_traefik_route()  # pylint: disable=W0212

    mock.assert_not_called()
