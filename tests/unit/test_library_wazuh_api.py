# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Wazuh API library tests using real relation data and secret revisions."""

from collections.abc import Iterator
from unittest.mock import patch

import ops
import pytest
from charms.wazuh_server.v0 import wazuh_api
from ops.testing import Harness

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

ENDPOINT = "https://example.wazuh:55000/"
PROVIDER = "wazuh-api-provider"
INITIAL_CONTENT = {"user": "api-user", "password": "initial-password"}
ROTATED_CONTENT = {"user": "rotated-user", "password": "rotated-password"}


class WazuhApiRequirerCharm(ops.CharmBase):
    """Record the library's custom events, not raw relation events."""

    def __init__(self, framework: ops.Framework) -> None:
        super().__init__(framework)
        self.wazuh_api = wazuh_api.WazuhApiRequires(self)
        self.events: list[wazuh_api.WazuhApiDataAvailableEvent] = []
        self.framework.observe(self.wazuh_api.on.wazuh_api_data_available, self._record_event)

    def _record_event(self, event: wazuh_api.WazuhApiDataAvailableEvent) -> None:
        self.events.append(event)


class WazuhApiProviderCharm(ops.CharmBase):
    def __init__(self, framework: ops.Framework) -> None:
        super().__init__(framework)
        self.wazuh_api = wazuh_api.WazuhApiProvides(self)


@pytest.fixture
def requirer() -> Iterator[Harness[WazuhApiRequirerCharm]]:
    harness = Harness(WazuhApiRequirerCharm, meta=REQUIRER_METADATA)
    harness.begin()
    yield harness
    harness.cleanup()


@pytest.fixture
def provider() -> Iterator[Harness[WazuhApiProviderCharm]]:
    harness = Harness(WazuhApiProviderCharm, meta=PROVIDER_METADATA)
    harness.begin()
    harness.set_leader(True)
    yield harness
    harness.cleanup()


def publish_credentials(
    harness: Harness[WazuhApiRequirerCharm],
    content: dict[str, str] | None = None,
) -> tuple[int, str]:
    relation_id = harness.add_relation("wazuh-api", PROVIDER)
    secret_id = harness.add_model_secret(PROVIDER, INITIAL_CONTENT if content is None else content)
    harness.grant_secret(secret_id, harness.model.app)
    harness.update_relation_data(
        relation_id, PROVIDER, {"endpoint": ENDPOINT, "user_credentials_secret": secret_id}
    )
    return relation_id, secret_id


def test_wazuh_api_provider_update_relation_data(
    provider: Harness[WazuhApiProviderCharm],
) -> None:
    relation_id = provider.add_relation("wazuh-api", "wazuh-api-consumer")
    relation = provider.model.get_relation("wazuh-api", relation_id)
    assert relation is not None
    secret_id = provider.charm.app.add_secret(INITIAL_CONTENT).id
    assert secret_id is not None
    data = wazuh_api.WazuhApiRelationData(
        endpoint=ENDPOINT,
        user_credentials_secret=secret_id,
        **INITIAL_CONTENT,
    )
    provider.charm.wazuh_api.update_relation_data(relation, data)
    assert dict(relation.data[provider.model.app]) == {
        "endpoint": ENDPOINT,
        "user_credentials_secret": secret_id,
    }
    assert data.to_relation_data() == dict(relation.data[provider.model.app])


def test_wazuh_api_valid_data_emits_custom_event(
    requirer: Harness[WazuhApiRequirerCharm],
) -> None:
    _, secret_id = publish_credentials(requirer)
    assert len(requirer.charm.events) == 1
    event = requirer.charm.events[0]
    assert str(event.endpoint) == ENDPOINT
    assert event.user == INITIAL_CONTENT["user"]
    assert event.password == INITIAL_CONTENT["password"]
    data = requirer.charm.wazuh_api.get_relation_data()
    assert data is not None
    assert data.user_credentials_secret == secret_id
    assert data.user == INITIAL_CONTENT["user"]
    assert data.password == INITIAL_CONTENT["password"]


@pytest.mark.parametrize("accessor", ["getter", "event"])
def test_wazuh_api_reads_latest_secret_revision(
    requirer: Harness[WazuhApiRequirerCharm], accessor: str
) -> None:
    _, secret_id = publish_credentials(requirer)
    requirer.set_secret_content(secret_id, ROTATED_CONTENT)
    if accessor == "getter":
        data = requirer.charm.wazuh_api.get_relation_data()
        assert data is not None
        credentials = (data.user, data.password)
    else:
        event = requirer.charm.events[0]
        credentials = (event.user, event.password)
    assert credentials == (ROTATED_CONTENT["user"], ROTATED_CONTENT["password"])
    assert requirer.model.get_secret(id=secret_id).get_content() == ROTATED_CONTENT


@pytest.mark.parametrize("accessor", ["getter", "event"])
def test_wazuh_api_reads_one_content_snapshot(
    requirer: Harness[WazuhApiRequirerCharm], accessor: str
) -> None:
    publish_credentials(requirer)
    with patch.object(ops.Secret, "get_content", return_value=ROTATED_CONTENT) as get_content:
        if accessor == "getter":
            data = requirer.charm.wazuh_api.get_relation_data()
            assert data is not None
            credentials = (data.user, data.password)
        else:
            credentials = requirer.charm.events[0]._credentials
    assert credentials == (ROTATED_CONTENT["user"], ROTATED_CONTENT["password"])
    get_content.assert_called_once_with(refresh=True)


@pytest.mark.parametrize(
    "relation_data",
    [
        {},
        {"endpoint": ENDPOINT},
        {"user_credentials_secret": "secret:missing"},
        {"endpoint": ENDPOINT, "user_credentials_secret": "secret:missing"},
    ],
)
def test_wazuh_api_unavailable_data_does_not_emit_event(
    requirer: Harness[WazuhApiRequirerCharm], relation_data: dict[str, str]
) -> None:
    requirer.add_relation("wazuh-api", PROVIDER, app_data=relation_data)
    assert requirer.charm.events == []
    assert requirer.charm.wazuh_api.get_relation_data() is None


def test_wazuh_api_without_relation_returns_none(
    requirer: Harness[WazuhApiRequirerCharm],
) -> None:
    assert requirer.charm.wazuh_api.get_relation_data() is None


def test_wazuh_api_ungranted_secret_recovers(
    requirer: Harness[WazuhApiRequirerCharm], caplog: pytest.LogCaptureFixture
) -> None:
    relation_id = requirer.add_relation("wazuh-api", PROVIDER)
    secret_id = requirer.add_model_secret(PROVIDER, INITIAL_CONTENT)
    relation_data = {"endpoint": ENDPOINT, "user_credentials_secret": secret_id}
    requirer.update_relation_data(relation_id, PROVIDER, relation_data)
    assert requirer.charm.events == []
    assert requirer.charm.wazuh_api.get_relation_data() is None
    assert "credentials" in caplog.text
    assert INITIAL_CONTENT["password"] not in caplog.text

    requirer.grant_secret(secret_id, requirer.model.app)
    requirer.charm.on.wazuh_api_relation_changed.emit(
        requirer.model.get_relation("wazuh-api", relation_id), app=requirer.model.get_app(PROVIDER)
    )
    assert len(requirer.charm.events) == 1
    data = requirer.charm.wazuh_api.get_relation_data()
    assert data is not None
    assert data.password == INITIAL_CONTENT["password"]


@pytest.mark.parametrize("content", [{"user": "api-user"}, {"password": "invalid-secret-value"}])
def test_wazuh_api_invalid_credentials_are_not_published(
    requirer: Harness[WazuhApiRequirerCharm],
    content: dict[str, str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    publish_credentials(requirer, content)
    assert requirer.charm.events == []
    assert requirer.charm.wazuh_api.get_relation_data() is None
    for value in content.values():
        assert value not in caplog.text


def test_wazuh_api_invalid_endpoint_is_safe_on_direct_read(
    requirer: Harness[WazuhApiRequirerCharm], caplog: pytest.LogCaptureFixture
) -> None:
    relation_id, _ = publish_credentials(requirer)
    requirer.charm.events.clear()
    requirer.update_relation_data(relation_id, PROVIDER, {"endpoint": "not-a-url"})
    assert requirer.charm.events == []
    assert requirer.charm.wazuh_api.get_relation_data() is None
    assert "endpoint" in caplog.text
    assert "not-a-url" not in caplog.text


def test_wazuh_api_event_reports_secret_error_with_cause(
    requirer: Harness[WazuhApiRequirerCharm],
) -> None:
    _, secret_id = publish_credentials(requirer)
    event = requirer.charm.events[0]
    requirer.revoke_secret(secret_id, requirer.model.app)
    with pytest.raises(wazuh_api.SecretError) as error:
        _ = event.password
    assert isinstance(error.value.__cause__, ops.ModelError)


def test_wazuh_api_event_rejects_invalid_credentials(
    requirer: Harness[WazuhApiRequirerCharm],
) -> None:
    _, secret_id = publish_credentials(requirer)
    event = requirer.charm.events[0]
    requirer.set_secret_content(secret_id, {"unexpected": "invalid-secret-value"})
    with pytest.raises(wazuh_api.SecretError):
        _ = event.user
