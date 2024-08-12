# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Wazuh server charm state."""

import logging

import ops
from pydantic import BaseModel, Field, ValidationError

logger = logging.getLogger(__name__)


class InvalidStateError(Exception):
    """Exception raised when a charm configuration is found to be invalid."""


class State(BaseModel):  # pylint: disable=too-few-public-methods
    """The Wazuh server charm state.

    Attributes:
        indexer_ips: list of Wazhug indexer IPs.
    """

    indexer_ips: list[str] = Field(min_length=1)

    # pylint: disable=unused-argument
    @classmethod
    def from_charm(
        cls,
        charm: ops.CharmBase,
        indexer_relation_data: ops.RelationData,
    ) -> "State":
        """Initialize the state from charm.

        Args:
            charm: the root charm.
            indexer_relation_data: the Wazuh indexer relation data.

        Returns:
            Current state of the charm.

        Raises:
            InvalidStateError: if the state is invalid.
        """
        try:
            endpoint_data = indexer_relation_data[charm.app]["endpoints"]
            endpoints = list(endpoint_data.split(",")) if endpoint_data else []
            return cls(indexer_ips=endpoints)
        except ValidationError as exc:
            logger.error("Invalid charm configuration, %s", exc)
            raise InvalidStateError("Invalid charm configuration.") from exc
