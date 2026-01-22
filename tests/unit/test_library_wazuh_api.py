# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Wazuh API library unit tests"""

import secrets

import ops
from charms.wazuh_server.v0 import wazuh_api
from ops.testing import Harness

import wazuh

REQUIRER_METADATA = """
name: wazuh-api-consumer
requires:
  wazuh-api:
    interface: wazuh_api_client
"""

PROVIDER_METADATA = """
name: wazuh-api-producer
provides:
  wazuh-api:
    interface: wazuh_api_client
"""

TOKEN = secrets.token_hex(8)
SAMPLE_RELATION_DATA = {
    "endpoint": f"https://example.wazuh:{wazuh.API_PORT}/",
    "user_credentials_secret": f"secret://59060ecc-0495-4a80-8006-5f1fc13fd783/{TOKEN}",
}


class WazuhApiRequirerCharm(ops.CharmBase):
    """Class for requirer charm testing."""

    def __init__(self, *args):
        """Init method for the class.

        Args:
            args: Variable list of positional arguments passed to the parent constructor.
        """
        super().__init__(*args)
        self.wazuh_api = wazuh_api.WazuhApiRequires(self)
        self.events = []
        self.framework.observe(self.on.wazuh_api_relation_changed, self._record_event)

    def _record_event(self, event: ops.EventBase) -> None:
        """Record emitted event in the event list.

        Args:
            event: event.
        """
        self.events.append(event)


class WazuhApiProviderCharm(ops.CharmBase):
    """Class for provider charm testing."""

    def __init__(self, *args):
        """Init method for the class.

        Args:
            args: Variable list of positional arguments passed to the parent constructor.
        """
        super().__init__(*args)
        self.wazuh_api = wazuh_api.WazuhApiProvides(self)
        self.events = []
        self.framework.observe(self.on.wazuh_api_relation_changed, self._record_event)

    def _record_event(self, event: ops.EventBase) -> None:
        """Record emitted event in the event list.

        Args:
            event: event.
        """
        self.events.append(event)


def test_wazuh_api_provider_update_relation_data():
    """
    arrange: instantiate a WazuhApiProviderCharm object and add an wazuh-api relation.
    act: update the relation data.
    assert: the relation data is updated.
    """
    harness = Harness(WazuhApiProviderCharm, meta=PROVIDER_METADATA)
    harness.begin()
    harness.set_leader(True)
    harness.add_relation("wazuh-api", "wazuh-api-provider")
    relation = harness.model.get_relation("wazuh-api")

    relation_data = wazuh_api.WazuhApiRelationData(
        endpoint=SAMPLE_RELATION_DATA["endpoint"],
        user_credentials_secret=SAMPLE_RELATION_DATA["user_credentials_secret"],
        user="wazuh-wui",
        password=secrets.token_hex(),
    )
    harness.charm.wazuh_api.update_relation_data(relation, relation_data)

    assert relation
    data = relation.data[harness.model.app]
    assert data["endpoint"] == str(relation_data.endpoint)
    assert data["user_credentials_secret"] == relation_data.user_credentials_secret
    assert "user" not in data
    assert "password" not in data


def test_wazuh_api_relation_data_to_relation_data():
    """
    arrange: instantiate a WazuhApiRelationData object.
    act: obtain the relation representation.
    assert: the relation representation is correct.
    """
    relation_data = wazuh_api.WazuhApiRelationData(
        endpoint=SAMPLE_RELATION_DATA["endpoint"],
        user_credentials_secret=SAMPLE_RELATION_DATA["user_credentials_secret"],
        user="wazuh-wui",
        password=secrets.token_hex(),
    )
    relation_data = relation_data.to_relation_data()

    assert relation_data == SAMPLE_RELATION_DATA


def test_requirer_charm_with_valid_relation_data_emits_event():
    """
    arrange: set up a charm.
    act: add an wazuh-api relation.
    assert: an WazuhApiDataAvailable event containing the relation data is emitted.
    """
    harness = Harness(WazuhApiRequirerCharm, meta=REQUIRER_METADATA)
    harness.begin()

    password = secrets.token_hex()
    secret_id = harness.add_user_secret({"user": "wazuh-wui", "password": password})
    harness.grant_secret(secret_id, "wazuh-api-consumer")
    SAMPLE_RELATION_DATA["user_credentials_secret"] = secret_id
    harness.add_relation("wazuh-api", "wazuh-api-provider", app_data=SAMPLE_RELATION_DATA)
    relation_data = harness.charm.wazuh_api.get_relation_data()

    assert relation_data
    assert str(relation_data.endpoint) == SAMPLE_RELATION_DATA["endpoint"]
    assert relation_data.user_credentials_secret == SAMPLE_RELATION_DATA["user_credentials_secret"]
    assert relation_data.user == "wazuh-wui"
    assert relation_data.password == password


def test_requirer_charm_with_invalid_relation_data_doesnt_emit_event():
    """
    arrange: set up a charm.
    act: add an wazuh-api relation changed event with invalid data.
    assert: an WazuhApiDataAvailable event is not emitted.
    """
    harness = Harness(WazuhApiRequirerCharm, meta=REQUIRER_METADATA)
    harness.begin()
    harness.add_relation("wazuh-api", "wazuh-api-provider", app_data={})

    assert len(harness.charm.events) == 0


def test_requirer_charm_get_relation_data_without_relation_data():
    """
    arrange: set up a charm with wazuh-api relation without any relation data.
    act: call get_relation_data function.
    assert: get_relation_data should return None.
    """
    harness = Harness(WazuhApiRequirerCharm, meta=REQUIRER_METADATA)
    harness.begin()
    harness.set_leader(True)
    harness.add_relation("wazuh-api", "wazuh-api-provider", app_data={})

    assert harness.charm.wazuh_api.get_relation_data() is None
