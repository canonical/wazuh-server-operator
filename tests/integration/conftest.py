# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""General configuration module for integration tests."""

import logging
import os.path
import secrets
import typing

import pytest
import pytest_asyncio
from juju.application import Application
from juju.model import Controller, Model
from pytest_operator.plugin import OpsTest

logger = logging.getLogger(__name__)

MACHINE_MODEL_CONFIG = {
    "logging-config": "<root>=INFO;unit=DEBUG",
    "update-status-hook-interval": "5m",
    "cloudinit-userdata": """postruncmd:
        - [ 'sysctl', '-w', 'vm.max_map_count=262144' ]
        - [ 'sysctl', '-w', 'fs.file-max=1048576' ]
        - [ 'sysctl', '-w', 'vm.swappiness=0' ]
        - [ 'sysctl', '-w', 'net.ipv4.tcp_retries2=5' ]
    """,
}


@pytest_asyncio.fixture(scope="module", name="model")
async def model_fixture(ops_test: OpsTest) -> Model:
    """The current test model."""
    assert ops_test.model
    return ops_test.model


@pytest_asyncio.fixture(scope="module", name="machine_controller")
async def machine_controller_fixture() -> typing.AsyncGenerator[Controller, None]:
    """The lxd controller."""
    controller = Controller()
    await controller.connect_controller("localhost")
    yield controller
    await controller.disconnect()


@pytest_asyncio.fixture(scope="module", name="machine_model")
async def machine_model_fixture(
    machine_controller: Controller,
) -> typing.AsyncGenerator[Model, None]:
    """The machine model for OpenSearch charm."""
    machine_model_name = f"machine-{secrets.token_hex(2)}"
    model = await machine_controller.add_model(machine_model_name)
    await model.connect(f"localhost:admin/{model.name}")
    await model.set_config(MACHINE_MODEL_CONFIG)
    yield model
    await model.disconnect()


@pytest_asyncio.fixture(scope="module", name="traefik")
async def traefik_fixture(model: Model) -> typing.AsyncGenerator[Application, None]:
    """Deploy the traefik charm."""
    application = await model.deploy(
        "traefik-k8s",
        application_name="traefik-k8s",
        channel="latest/stable",
        trust=True,
        config={"external_hostname": "wazuh-server.local"},
    )
    await model.wait_for_idle(apps=[application.name], status="active", timeout=1000)
    yield application


@pytest_asyncio.fixture(scope="module", name="self_signed_certificates")
async def self_signed_certificates_fixture(
    machine_model: Model,
) -> typing.AsyncGenerator[Application, None]:
    """Deploy the self signed certificates charm."""
    application = await machine_model.deploy(
        "self-signed-certificates",
        application_name="self-signed-certificates",
        channel="latest/stable",
        config={"ca-common-name": "Test CA"},
    )
    await machine_model.create_offer(f"{application.name}:certificates", application.name)
    await machine_model.wait_for_idle(apps=[application.name], status="active", timeout=1000)
    yield application


@pytest_asyncio.fixture(scope="module", name="opensearch_provider")
async def opensearch_provider_fixture(
    machine_model: Model,
    self_signed_certificates: Application,
) -> typing.AsyncGenerator[Application, None]:
    """Deploy the opensearch charm."""
    application = await machine_model.deploy(
        "wazuh-indexer", application_name="wazuh-indexer", channel="latest/edge", num_units=2
    )
    await machine_model.integrate(self_signed_certificates.name, application.name)
    await machine_model.create_offer(f"{application.name}:opensearch-client", application.name)
    await machine_model.wait_for_idle(apps=[application.name], status="active", timeout=1400)
    yield application


@pytest_asyncio.fixture(scope="module", name="charm")
async def charm_fixture(pytestconfig: pytest.Config) -> str:
    """Get value from parameter charm-file."""
    charm = pytestconfig.getoption("--charm-file")
    assert charm, "--charm-file must be set"
    if not os.path.exists(charm):
        logger.info("Using parent directory for charm file")
        charm = os.path.join("..", charm)
    return charm


# pylint: disable=too-many-arguments, too-many-positional-arguments
@pytest_asyncio.fixture(scope="module", name="application")
async def application_fixture(
    charm: str,
    model: Model,
    self_signed_certificates: Application,
    opensearch_provider: Application,
    pytestconfig: pytest.Config,
    traefik: Application,
) -> typing.AsyncGenerator[Application, None]:
    """Deploy the charm."""
    # Deploy the charm and wait for active/idle status
    resources = {
        "wazuh-server-image": pytestconfig.getoption("--wazuh-server-image"),
    }
    application = await model.deploy(f"./{charm}", resources=resources, trust=True)
    await model.integrate(
        f"localhost:admin/{opensearch_provider.model.name}.{opensearch_provider.name}",
        application.name,
    )
    await model.integrate(
        f"localhost:admin/{self_signed_certificates.model.name}.{self_signed_certificates.name}",
        application.name,
    )
    await model.integrate(traefik.name, application.name)
    await model.wait_for_idle(apps=[application.name], status="active", raise_on_error=True)
    yield application
