# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""General configuration module for integration tests."""

import asyncio
import json
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
}
WAZUH_DASHBOARD_CHANNEL = "4.11/edge"
WAZUH_DASHBOARD_REVISION = 17
WAZUH_INDEXER_CHANNEL = "4.11/edge"
WAZUH_INDEXER_REVISION = 9


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
    await asyncio.sleep(1)
    current_task = asyncio.current_task()
    logger.debug("Cleaning up remaining asyncio tasks")
    for task in asyncio.all_tasks():
        if not task.done() and not task.cancelled() and task is not current_task:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)


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
    logger.info("Using VM for deployment until LXD+SNAP+Kernel 6.14 bug is fixed")
    await model.set_constraints(
        {
            "virt-type": "virtual-machine",
            "mem": 2048,
            "root-disk": 10240,
            "cores": 2,
        }
    )
    yield model
    await model.disconnect()


@pytest_asyncio.fixture(scope="module", name="traefik")
async def traefik_fixture(
    model: Model, pytestconfig: pytest.Config
) -> typing.AsyncGenerator[Application, None]:
    """Deploy the traefik charm."""
    app_name = "traefik-k8s"
    application: Application
    if pytestconfig.getoption("--no-deploy") and app_name in model.applications:
        logger.warning("Using existing application: %s", app_name)
        application = model.applications[app_name]
    else:
        application = await model.deploy(
            app_name,
            application_name=app_name,
            channel="latest/edge",
            revision=233,
            trust=True,
            config={"external_hostname": "wazuh-server.local"},
        )
    yield application
    if not pytestconfig.getoption("--keep-models") and app_name in model.applications:
        await model.applications[app_name].destroy(force=True, no_wait=True)


@pytest_asyncio.fixture(scope="module", name="machine_self_signed_certificates")
async def machine_self_signed_certificates_fixture(
    machine_model: Model,
    pytestconfig: pytest.Config,
) -> typing.AsyncGenerator[Application, None]:
    """Deploy the self-signed certificates charm."""
    app_name = "self-signed-certificates"
    application: Application
    if pytestconfig.getoption("--no-deploy") and app_name in machine_model.applications:
        logger.warning("Using existing application: %s", app_name)
        application = machine_model.applications[app_name]
    else:
        application = await machine_model.deploy(
            app_name,
            application_name=app_name,
            channel="latest/stable",
            config={"ca-common-name": "machine test CA"},
        )
    yield application
    if not pytestconfig.getoption("--keep-models") and app_name in machine_model.applications:
        await machine_model.applications[app_name].destroy(force=True, no_wait=True)


@pytest_asyncio.fixture(scope="module", name="k8s_self_signed_certificates")
async def k8s_self_signed_certificates_fixture(
    model: Model,
    pytestconfig: pytest.Config,
) -> typing.AsyncGenerator[Application, None]:
    """Deploy the self-signed certificates charm."""
    app_name = "self-signed-certificates"
    application: Application
    if pytestconfig.getoption("--no-deploy") and app_name in model.applications:
        logger.warning("Using existing application: %s", app_name)
        application = model.applications[app_name]
    else:
        application = await model.deploy(
            app_name,
            application_name=app_name,
            channel="latest/stable",
            config={"ca-common-name": "k8s test CA"},
        )
    yield application
    if not pytestconfig.getoption("--keep-models") and app_name in model.applications:
        await model.applications[app_name].destroy(force=True, no_wait=True)


@pytest_asyncio.fixture(scope="module", name="opensearch_provider")
async def opensearch_provider_fixture(
    machine_model: Model,
    pytestconfig: pytest.Config,
    machine_self_signed_certificates: Application,
) -> typing.AsyncGenerator[Application, None]:
    """Deploy the opensearch charm."""
    app_name = "wazuh-indexer"
    machine_controller_name = (await machine_model.get_controller()).controller_name
    application: Application
    if pytestconfig.getoption("--no-deploy") and app_name in machine_model.applications:
        logger.warning("Using existing application: %s", app_name)
        application = machine_model.applications[app_name]
    else:
        num_units = 3
        if pytestconfig.getoption("--single-node-indexer"):
            num_units = 1
        application = await machine_model.deploy(
            app_name,
            application_name=app_name,
            channel=WAZUH_INDEXER_CHANNEL,
            revision=WAZUH_INDEXER_REVISION,
            num_units=num_units,
            config={"profile": "testing"},
        )
        await machine_model.integrate(machine_self_signed_certificates.name, application.name)
        await machine_model.wait_for_idle(
            apps=[application.name],
            status="active",
            raise_on_error=True,
            timeout=1800,
        )
        if num_units == 1:
            await configure_single_node(f"{machine_controller_name}:admin/{machine_model.name}")
        await machine_model.create_offer(f"{application.name}:opensearch-client", application.name)
    yield application
    if not pytestconfig.getoption("--keep-models") and app_name in machine_model.applications:
        await machine_model.applications[app_name].destroy(force=True, no_wait=True)


@pytest_asyncio.fixture(scope="module", name="wazuh_dashboard")
async def wazuh_dashboard_fixture(
    machine_model: Model,
    pytestconfig: pytest.Config,
    opensearch_provider: Application,
    machine_self_signed_certificates: Application,
) -> typing.AsyncGenerator[Application, None]:
    """Deploy the opensearch charm."""
    app_name = "wazuh-dashboard"
    application: Application
    if pytestconfig.getoption("--no-deploy") and app_name in machine_model.applications:
        logger.warning("Using existing application: %s", app_name)
        application = machine_model.applications[app_name]
    else:
        num_units = 1
        application = await machine_model.deploy(
            app_name,
            application_name=app_name,
            channel=WAZUH_DASHBOARD_CHANNEL,
            revision=WAZUH_DASHBOARD_REVISION,
            num_units=num_units,
        )
        await machine_model.integrate(machine_self_signed_certificates.name, application.name)
        await machine_model.integrate(opensearch_provider.name, application.name)
    yield application
    if not pytestconfig.getoption("--keep-models") and app_name in machine_model.applications:
        await machine_model.applications[app_name].destroy(
            destroy_storage=True, force=True, no_wait=False
        )


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
    machine_model: Model,
    model: Model,
    k8s_self_signed_certificates: Application,
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

    await model.deploy(
        f"./{charm}",
        config={
            "logs-ca-cert": (Path(__file__).parent / "certs/ca.crt").read_text(),
            "enable-vulnerability-detection": False,
        },
        resources=resources,
        trust=True,
    )
    application = model.applications[wazuh_server_app]
    await model.integrate(
        f"localhost:admin/{opensearch_provider.model.name}.{opensearch_provider.name}",
        application.name,
    )
    await model.integrate(k8s_self_signed_certificates.name, application.name)
    await model.integrate(traefik.name, application.name)
    await model.wait_for_idle(
        apps=[traefik.name, application.name],
        status="active",
        raise_on_error=True,
        timeout=1800,
    )
    await machine_model.wait_for_idle(
        apps=[opensearch_provider.name],
        status="active",
        raise_on_error=True,
        timeout=1800,
    )
    yield application
    if not pytestconfig.getoption("--keep-models"):
        # cleanup secrets (library does not give us convenient methods for this)
        for unit in application.units:
            await unit.run(
                "while IFS= read -r secret; do secret-remove $secret; done < <(secret-ids)",
                timeout=30,
            )
        await application.destroy(destroy_storage=True, force=True, no_wait=False)


@pytest_asyncio.fixture(scope="module", name="any_opencti")
async def opencti_any_charm_fixture(
    model: Model,
    pytestconfig: pytest.Config,
    application: Application,
) -> typing.AsyncGenerator[Application, None]:
    """Deploy OpenCTI any-charm and integrate with Wazuh Server."""
    app_name = "any-opencti"
    any_charm_script = Path("tests/integration/any_charm.py").read_text(encoding="utf-8")
    any_charm_src_overwrite = {"any_charm.py": any_charm_script}
    any_app: Application
    if pytestconfig.getoption("--no-deploy") and app_name in model.applications:
        logger.warning("Using existing application: %s", app_name)
        any_app = model.applications[app_name]
    else:
        any_app = await model.deploy(
            "any-charm",
            application_name=app_name,
            channel="beta",
            config={
                "src-overwrite": json.dumps(any_charm_src_overwrite),
                "python-packages": "PyJWT",
            },
        )
        await model.wait_for_idle(apps=[app_name], timeout=600)
    await model.integrate(any_app.name, f"{application.name}:opencti-connector")
    await model.wait_for_idle(status="active", timeout=600)
    yield any_app
    if not pytestconfig.getoption("--keep-models") and app_name in model.applications:
        await model.applications[app_name].destroy(force=True, no_wait=True)
