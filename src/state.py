# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Wazuh server charm state."""

import dataclasses
import logging

import ops
from pydantic import BaseModel, Field, IPvAnyAddress, ValidationError

logger = logging.getLogger(__name__)


class InvalidStateError(Exception):
    """Exception raised when a charm configuration is found to be invalid."""


@dataclasses.dataclass()
class State(BaseModel):  # pylint: disable=too-few-public-methods
    """The Wazuh server charm state.

    Attributes:
        indexer_ips: list of Wazhug indexer IPs.
    """

    indexer_ips: list[IPvAnyAddress] = Field(min_length=1)

    # pylint: disable=unused-argument
    @classmethod
    def from_charm(
        cls,
        charm: ops.CharmBase,
        wazuh_indexer_relation: ops.Relation,
    ) -> "State":
        """Initialize the state from charm.

        Args:
            charm: the root charm.
            wazuh_indexer_relation: the Wazhub indexer relation.

        Returns:
            Current state of the charm.

        Raises:
            InvalidStateError: if the state is invalid.
        """
        try:
            indexer_ips = [unit.public_address for unit in wazuh_indexer_relation.units]
            return cls(indexer_ips=indexer_ips)
        except ValidationError as exc:
            logger.error("Invalid juju model proxy configuration, %s", exc)
            raise InvalidStateError("Invalid model proxy configuration.") from exc
