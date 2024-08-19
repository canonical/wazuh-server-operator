# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""General configuration module for integration tests."""

import logging
import os.path
import typing

import pytest
import pytest_asyncio
from juju.application import Application
from juju.model import Model
from pytest_operator.plugin import OpsTest

logger = logging.getLogger(__name__)

PROVIDER_CHARM_DIR = "tests/integration/tls_provider_charm"


@pytest_asyncio.fixture(scope="module", name="model")
async def model_fixture(ops_test: OpsTest) -> Model:
    """The current test model."""
    assert ops_test.model
    return ops_test.model


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
async def opensearch_provider_fixture(model: Model) -> typing.AsyncGenerator[Application, None]:
    """Deploy the opensearch charm."""
    certificates_application = await model.deploy(
        "self-signed-certificates",
        application_name="self-signed-certificates",
        channel="latest/stable",
        config={"ca-common-name": "Test CA"},
    )
    application = await model.deploy(
        "opensearch",
        application_name="tls-certificates-provider",
        channel="2/beta",
    )
    await model.add_relation(certificates_application.name, application.name)
    await model.wait_for_idle(
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
    await model.add_relation(opensearch_provider.name, application.name)
    await model.add_relation(tls_certificates_provider.name, application.name)
    await model.wait_for_idle(
        apps=[application.name],
        status="active",
        raise_on_error=True,
    )
    yield application
