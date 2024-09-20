# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Wazuh server charm state."""

import json
import logging
import os
import typing
from abc import ABC, abstractmethod

import ops
from pydantic import AnyHttpUrl, BaseModel, Field, ValidationError, parse_obj_as

logger = logging.getLogger(__name__)


class CharmBaseWithState(ops.CharmBase, ABC):
    """CharmBase than can build a CharmState."""

    @abstractmethod
    def reconcile(self) -> None:
        """Reconcile Synapse configuration."""


class InvalidStateError(Exception):
    """Exception raised when a charm configuration is found to be invalid."""


class ProxyConfig(BaseModel):  # pylint: disable=too-few-public-methods
    """Configuration for accessing Synapse through proxy.

    Attributes:
        http_proxy: The http proxy URL.
        https_proxy: The https proxy URL.
        no_proxy: Comma separated list of hostnames to bypass proxy.
    """

    http_proxy: typing.Optional[AnyHttpUrl]
    https_proxy: typing.Optional[AnyHttpUrl]
    no_proxy: typing.Optional[str]


class State(BaseModel):  # pylint: disable=too-few-public-methods
    """The Wazuh server charm state.

    Attributes:
        indexer_ips: list of Wazuh indexer IPs.
        certificate: the TLs certificate.
        proxy: proxy configuration.
    """

    indexer_ips: typing.Annotated[list[str], Field(min_length=1)]
    certificate: str = Field(..., min_length=1)

    @property
    def proxy(self) -> "ProxyConfig":
        """Get charm proxy configuration from juju charm environment.

        Returns:
            charm proxy configuration in the form of ProxyConfig.
        """
        http_proxy = os.environ.get("JUJU_CHARM_HTTP_PROXY")
        https_proxy = os.environ.get("JUJU_CHARM_HTTPS_PROXY")
        no_proxy = os.environ.get("JUJU_CHARM_NO_PROXY")
        return ProxyConfig(
            http_proxy=parse_obj_as(AnyHttpUrl, http_proxy) if http_proxy else None,
            https_proxy=parse_obj_as(AnyHttpUrl, https_proxy) if https_proxy else None,
            no_proxy=no_proxy,
        )

    # pylint: disable=unused-argument
    @classmethod
    def from_charm(
        cls,
        charm: ops.CharmBase,
        indexer_relation_data: dict[str, str],
        certificates_relation_data: dict[str, str],
    ) -> "State":
        """Initialize the state from charm.

        Args:
            charm: the root charm.
            indexer_relation_data: the Wazuh indexer app relation data.
            certificates_relation_data: the certificates relation data.

        Returns:
            Current state of the charm.

        Raises:
            InvalidStateError: if the state is invalid.
        """
        try:
            endpoint_data = indexer_relation_data.get("endpoints")
            endpoints = list(endpoint_data.split(",")) if endpoint_data else []
            certificates_json = (
                certificates_relation_data.get("certificates", "[]")
                if certificates_relation_data
                else "[]"
            )
            certificates = json.loads(certificates_json)
            if certificates:
                return cls(indexer_ips=endpoints, certificate=certificates[0].get("certificate"))
            raise InvalidStateError("Certificate is empty.")
        except ValidationError as exc:
            logger.error("Invalid charm configuration, %s", exc)
            raise InvalidStateError("Invalid charm configuration.") from exc
