# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""General configuration module for integration tests."""

import logging
import os.path
import secrets
import typing
from pathlib import Path

import pytest
import pytest_asyncio
from juju.application import Application
from juju.model import Controller, Model
from pytest_operator.plugin import OpsTest

from tests.integration.helpers import configure_single_node

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
    pytestconfig: pytest.Config,
) -> typing.AsyncGenerator[Model, None]:
    """The machine model for OpenSearch charm."""
    if model_name := pytestconfig.getoption("--model"):
        machine_model_name = f"{model_name}-machine"
    else:
        machine_model_name = f"machine-{secrets.token_hex(2)}"
    models = await machine_controller.list_models()
    if machine_model_name in models:
        logger.info("Using existing model %s", machine_model_name)
        model = await machine_controller.get_model(machine_model_name)
    else:
        model = await machine_controller.add_model(machine_model_name)
    await model.connect(f"localhost:admin/{model.name}")
    await model.set_config(MACHINE_MODEL_CONFIG)
    yield model
    await model.disconnect()


@pytest_asyncio.fixture(scope="module", name="traefik")
async def traefik_fixture(
    model: Model, pytestconfig: pytest.Config
) -> typing.AsyncGenerator[Application, None]:
    """Deploy the traefik charm."""
    app_name = "traefik-k8s"
    if pytestconfig.getoption("--no-deploy") and app_name in model.applications:
        logger.warning("Using existing application: %s", app_name)
        yield model.applications[app_name]
        return

    application = await model.deploy(
        app_name,
        application_name=app_name,
        channel="latest/edge",
        trust=True,
        config={"external_hostname": "wazuh-server.local"},
    )
    yield application


@pytest_asyncio.fixture(scope="module", name="self_signed_certificates")
async def self_signed_certificates_fixture(
    machine_model: Model,
    pytestconfig: pytest.Config,
) -> typing.AsyncGenerator[Application, None]:
    """Deploy the self signed certificates charm."""
    app_name = "self-signed-certificates"
    if pytestconfig.getoption("--no-deploy") and app_name in machine_model.applications:
        logger.warning("Using existing application: %s", app_name)
        yield machine_model.applications[app_name]
        return

    application = await machine_model.deploy(
        app_name,
        application_name=app_name,
        channel="latest/stable",
        config={"ca-common-name": "Test CA"},
    )
    await machine_model.create_offer(f"{application.name}:certificates", application.name)
    yield application


@pytest_asyncio.fixture(scope="module", name="opensearch_provider")
async def opensearch_provider_fixture(
    model: Model,
    machine_model: Model,
    pytestconfig: pytest.Config,
    self_signed_certificates: Application,
) -> typing.AsyncGenerator[Application, None]:
    """Deploy the opensearch charm."""
    app_name = "wazuh-indexer"

    k8s_controller_name = (await model.get_controller()).controller_name
    machine_controller_name = (await machine_model.get_controller()).controller_name
    logger.info(
        "Machine controller: %s, k8s controller: %s",
        machine_controller_name,
        k8s_controller_name,
    )

    if pytestconfig.getoption("--no-deploy") and app_name in machine_model.applications:
        logger.warning("Using existing application: %s", app_name)
        yield machine_model.applications[app_name]
        return

    num_units = 3
    if pytestconfig.getoption("--single-node-indexer"):
        num_units = 1
    application = await machine_model.deploy(
        app_name, application_name=app_name, channel="latest/edge", num_units=num_units
    )

    await machine_model.integrate(self_signed_certificates.name, application.name)

    await machine_model.wait_for_idle(
        apps=[app_name], status="active", raise_on_error=False, timeout=1800
    )
    if num_units == 1:
        await configure_single_node(machine_controller_name, k8s_controller_name)

    await machine_model.create_offer(f"{application.name}:opensearch-client", application.name)
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
    wazuh_server_app = "wazuh-server"
    if pytestconfig.getoption("--no-deploy") and wazuh_server_app in model.applications:
        logger.warning("Using existing application: %s", wazuh_server_app)
        yield model.applications[wazuh_server_app]
        return

    application = await model.deploy(
        f"./{charm}",
        config={"logs-ca-cert": (Path(__file__).parent / "certs/ca.crt").read_text()},
        resources=resources,
        trust=True,
    )
    await model.integrate(
        f"localhost:admin/{opensearch_provider.model.name}.{opensearch_provider.name}",
        application.name,
    )
    await model.integrate(
        f"localhost:admin/{self_signed_certificates.model.name}.{self_signed_certificates.name}",
        application.name,
    )
    await model.integrate(traefik.name, application.name)
    await model.wait_for_idle(
        apps=[traefik.name], status="active", raise_on_error=False, timeout=1800
    )
    await model.wait_for_idle(
        apps=[application.name], status="active", raise_on_error=False, timeout=1800
    )
    yield application
