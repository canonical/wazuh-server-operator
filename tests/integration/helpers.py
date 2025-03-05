# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Integration test helpers."""

import logging

import sh
from juju.model import Model

logger = logging.getLogger(__name__)


async def get_k8s_service_address(model: Model, service_name: str) -> str:
    """Get the address of a LoadBalancer Kubernetes service using kubectl.

    Args:
        model: the Juju model.
        service_name: The name of the Kubernetes service.

    Returns:
        The LoadBalancer service address as a string.
    """
    # sh.kubectl.get.service actually exists
    return sh.kubectl.get.service(  # pylint: disable=no-member
        service_name, namespace=model.name, o="jsonpath={.status.loadBalancer.ingress[0].ip}"
    )
