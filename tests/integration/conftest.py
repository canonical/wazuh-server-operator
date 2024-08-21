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

PROVIDER_CHARM_DIR = "tests/integration/tls_provider_charm"


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
    """The machine model for jenkins agent machine charm."""
    machine_model_name = f"jenkins-agent-machine-{secrets.token_hex(2)}"
    model = await machine_controller.add_model(machine_model_name)
    await model.connect(f"localhost:admin/{model.name}")
    yield model
    await machine_controller.destroy_models(
        model.name, destroy_storage=True, force=True, max_wait=10 * 60
    )
    await model.disconnect()


@pytest_asyncio.fixture(scope="module", name="model")
async def tls_certificates_provider_fixture(
    ops_test: OpsTest, model: Model
) -> typing.AsyncGenerator[Application, None]:
    """Deploy the tls_certificates_provider charm."""
    provider_charm = await ops_test.build_charm(f"{PROVIDER_CHARM_DIR}/")
    application = await model.deploy(
        provider_charm,
        application_name="tls-certificates-provider",
        series="jammy",
    )
    await model.wait_for_idle(
        apps=[application.name],
        status="blocked",
        timeout=1000,
    )
    yield application


@pytest_asyncio.fixture(scope="module", name="model")
async def opensearch_provider_fixture(
    machine_model: Model,
) -> typing.AsyncGenerator[Application, None]:
    """Deploy the opensearch charm."""
    certificates_application = await machine_model.deploy(
        "self-signed-certificates",
        application_name="self-signed-certificates",
        channel="latest/stable",
        config={"ca-common-name": "Test CA"},
    )
    application = await machine_model.deploy(
        "opensearch",
        application_name="opensearch",
        channel="2/beta",
    )
    await machine_model.add_relation(certificates_application.name, application.name)
    await machine_model.create_offer(f"{application.name}:opensearch-client", application.name)
    await machine_model.wait_for_idle(
        apps=[certificates_application.name, application.name],
        status="blocked",
        timeout=1000,
    )
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


@pytest_asyncio.fixture(scope="module", name="application")
async def application_fixture(
    charm: str,
    model: Model,
    opensearch_provider: Application,
    tls_certificates_provider: Application,
) -> typing.AsyncGenerator[Application, None]:
    """Deploy the charm."""
    # Deploy the charm and wait for active/idle status
    application = await model.deploy(f"./{charm}", trust=True)
    await model.add_relation(
        f"localhost:admin/{opensearch_provider.model.name}.{opensearch_provider.name}",
        application.name,
    )
    await model.add_relation(tls_certificates_provider.name, application.name)
    await model.wait_for_idle(
        apps=[application.name],
        status="active",
        raise_on_error=True,
    )
    yield application
