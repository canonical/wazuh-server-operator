# Copyright 2025 Canonical Ltd.
# Licensed under the Apache2.0. See LICENSE file in charm source for details.

"""Library to manage the integration with the Wazuh Server charm.

This library contains the Requires and Provides classes for handling the integration
between an application and a charm providing the `wazuh-apli-client` integration.
This library also contains a `WazuhApiRelationData` class to wrap the data that will
be shared via the integration.

### Requirer Charm

```python

from charms.wazuh_server.v0.wazuh_api import WazuhApiDataAvailableEvent, WazuhApiRequires

class WazuhApiRequirerCharm(ops.CharmBase):
    def __init__(self, *args):
        super().__init__(*args)
        self.wazuh_api = wazuh_api.WazuhApiRequires(self)
        self.framework.observe(self.wazuh_api.on.wazuh_api_data_available, self._handler)
        ...

    def _handler(self, events: WazuhApiDataAvailableEvent) -> None:
        ...

```

As shown above, the library provides a custom event to handle the scenario in
which new Wazuh API data has been added or updated.

### Provider Charm

Following the previous example, this is an example of the provider charm.

```python
from charms.wazuh_server.v0.wazuh_api import import WazuhApiProvides

class WazuhApiProviderCharm(ops.CharmBase):
    def __init__(self, *args):
        super().__init__(*args)
        self.wazuh_api = WazuhApiProvides(self)
        ...

```
The WazuhApiProvides object wraps the list of relations into a `relations` property
and provides an `update_relation_data` method to update the relation data by passing
a `WazuhApiRelationData` data object.

```python
class WazuhApiProviderCharm(ops.CharmBase):
    ...

    def _on_config_changed(self, _) -> None:
        for relation in self.model.relations[self.wazuh_api.relation_name]:
            self.wazuh_api.update_relation_data(relation, self._get_wazuh_api_data())

```
"""

# The unique Charmhub library identifier, never change it
LIBID = "f0b9836db9604a9491247244109c24e6"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 3

PYDEPS = ["pydantic>=2"]

# pylint: disable=wrong-import-position
import itertools
import logging
import typing
from typing import Dict, Optional

import ops
from pydantic import AnyHttpUrl, BaseModel, ValidationError

# The wazuh dashboard charm dependencies require pydantic<2
# Disable used-before-assignment as parse_obj_as will not be recognized pylint
# pylint: disable=used-before-assignment
try:
    from pydantic import TypeAdapter
except ImportError:
    from pydantic import parse_obj_as

logger = logging.getLogger(__name__)

RELATION_NAME = "wazuh-api"
WAZUH_API_KEY_SECRET_LABEL = "wazuh-api-remote-credentials"


class SecretError(Exception):
    """Common ancestor for Secrets related exceptions."""


class WazuhApiRelationData(BaseModel):
    """Represent the relation data.

    Attributes:
        endpoint: The API endpoint.
        user: The user to authenticate against the API.
        password: TThe password to authenticate against the API.
        user_credentials_secret: The secret ID containing the API credentials.
    """

    endpoint: AnyHttpUrl
    user: str
    password: str
    user_credentials_secret: str

    def to_relation_data(self) -> Dict[str, str]:
        """Convert an instance of WazuhApiRelationData to the relation representation.

        Returns:
            Dict containing the representation.
        """
        return {
            "endpoint": str(self.endpoint),
            "user_credentials_secret": self.user_credentials_secret,
        }


class WazuhApiDataAvailableEvent(ops.RelationEvent):
    """Event emitted when relation data has changed.

    Attributes:
        endpoint: The API endpoint.
        user: The user to authenticate against the API.
        password: TThe password to authenticate against the API.
    """

    @property
    def endpoint(self) -> AnyHttpUrl:
        """Fetch the endpoint from the relation."""
        assert self.relation.app
        url = typing.cast(str, self.relation.data[self.relation.app].get("endpoint"))
        try:
            return TypeAdapter(AnyHttpUrl).validate_python(url)
        except NameError:
            return parse_obj_as(AnyHttpUrl, url)

    @property
    def _credentials(self) -> tuple[str, str]:
        """Fetch the API credentials from the relation."""
        assert self.relation.app
        relation_data = self.relation.data[self.relation.app]
        try:
            credentials = self.framework.model.get_secret(
                id=relation_data.get("user_credentials_secret")
            )
            user = typing.cast(str, credentials.get_content().get("user"))
            password = typing.cast(str, credentials.get_content().get("password"))
            return (user, password)
        except ops.SecretNotFoundError as exc:
            raise SecretError(
                f'Could not consume secret {relation_data.get("user_credentials_secret")}'
            ) from exc

    @property
    def user(self) -> str:
        """Fetch the user from the relation."""
        assert self.relation.app
        return self._credentials[0]

    @property
    def password(self) -> str:
        """Fetch the password from the relation."""
        assert self.relation.app
        return self._credentials[1]


class WazuhApiRequiresEvents(ops.CharmEvents):
    """Wazuh API events.

    This class defines the events that a requirer can emit.

    Attributes:
        wazuh_api_data_available: the WazuhApiDataAvailableEvent.
    """

    wazuh_api_data_available = ops.EventSource(WazuhApiDataAvailableEvent)


class WazuhApiRequires(ops.Object):
    """Requirer side of the Wazuh API client relation.

    Attributes:
        on: events the provider can emit.
    """

    on = WazuhApiRequiresEvents()

    def __init__(self, charm: ops.CharmBase, relation_name: str = RELATION_NAME) -> None:
        """Construct.

        Args:
            charm: the provider charm.
            relation_name: the relation name.
        """
        super().__init__(charm, relation_name)
        self.charm = charm
        self.relation_name = relation_name
        self.framework.observe(charm.on[relation_name].relation_changed, self._on_relation_changed)

    def get_relation_data(self) -> Optional[WazuhApiRelationData]:
        """Retrieve the relation data.

        Returns:
            WazuhApiRelationData: the relation data.
        """
        relation = self.model.get_relation(self.relation_name)
        return self._get_relation_data_from_relation(relation) if relation else None

    def _get_relation_data_from_relation(
        self, relation: ops.Relation
    ) -> WazuhApiRelationData | None:
        """Retrieve the relation data.

        Args:
            relation: the relation to retrieve the data from.

        Returns:
            WazuhApiRelationData: the relation data if found.
        """
        assert relation.app
        relation_data = relation.data[relation.app]
        if not relation_data:
            return None

        secret_id = typing.cast(str, relation_data.get("user_credentials_secret"))
        try:
            credentials = self.model.get_secret(id=secret_id)
            user = typing.cast(str, credentials.get_content().get("user"))
            password = typing.cast(str, credentials.get_content().get("password"))
            url = typing.cast(str, relation_data.get("endpoint"))
            try:
                endpoint = TypeAdapter(AnyHttpUrl).validate_python(url)
            except NameError:
                endpoint = parse_obj_as(AnyHttpUrl, url)
            return WazuhApiRelationData(
                endpoint=endpoint,
                user_credentials_secret=secret_id,
                user=user,
                password=password,
            )
        except ops.model.ModelError:
            logger.debug("Could not fetch secret %s", relation_data.get("user_credentials_secret"))
            return None

    def _is_relation_data_valid(self, relation: ops.Relation) -> bool:
        """Validate the relation data.

        Args:
            relation: the relation to validate.

        Returns:
            true: if the relation data is valid.
        """
        try:
            _ = self._get_relation_data_from_relation(relation)
            return True
        except ValidationError as ex:
            error_fields = set(
                itertools.chain.from_iterable(error["loc"] for error in ex.errors())
            )
            error_field_str = " ".join(f"{f}" for f in error_fields)
            logger.warning("Error validation the relation data %s", error_field_str)
            return False

    def _on_relation_changed(self, event: ops.RelationChangedEvent) -> None:
        """Event emitted when the relation has changed.

        Args:
            event: event triggering this handler.
        """
        assert event.relation.app
        relation_data = event.relation.data[event.relation.app]
        if relation_data:
            if self._is_relation_data_valid(event.relation):
                self.on.wazuh_api_data_available.emit(
                    event.relation, app=event.app, unit=event.unit
                )


class WazuhApiProvides(ops.Object):
    """Provider side of the Wazuh API relation."""

    def __init__(self, charm: ops.CharmBase, relation_name: str = RELATION_NAME) -> None:
        """Construct.

        Args:
            charm: the provider charm.
            relation_name: the relation name.
        """
        super().__init__(charm, relation_name)
        self.charm = charm
        self.relation_name = relation_name

    def update_relation_data(
        self, relation: ops.Relation, wazuh_api_data: WazuhApiRelationData
    ) -> None:
        """Update the relation data.

        Args:
            relation: the relation for which to update the data.
            wazuh_api_data: a WazuhApiRelationData instance wrapping the data to be updated.
        """
        relation_data = wazuh_api_data.to_relation_data()
        relation.data[self.charm.model.app].update(relation_data)
