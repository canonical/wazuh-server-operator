# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

r"""Benchmark script for measuring wazuh-server charm reconcile time.

Deploys the locally built wazuh-server charm with self-signed-certificates and
traefik-k8s on a Juju k8s model, integrates them, waits for idle, then reads the
Juju debug log to find and report the reconcile timing logged by the charm at DEBUG level.

With --full-deploy, also deploys wazuh-indexer and wazuh-dashboard on the machine
model and wires up all cross-model relations so wazuh-server reaches ActiveStatus.

Usage:
    python tests/benchmark/benchmark.py \\
        --charm-file wazuh-server_ubuntu-22.04-amd64.charm \\
        --wazuh-server-image 10.x.x.x:32000/wazuh-server:1.0

    # Full topology (also deploys wazuh-indexer + wazuh-dashboard):
    python tests/benchmark/benchmark.py \\
        --charm-file wazuh-server_ubuntu-22.04-amd64.charm \\
        --wazuh-server-image 10.x.x.x:32000/wazuh-server:1.0 \\
        --full-deploy
"""

import argparse
import asyncio
import logging
import re
import secrets
import subprocess
import sys
from pathlib import Path

from juju.controller import Controller
from juju.model import Model

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

SELF_SIGNED_CERTS_CHANNEL = "latest/stable"
TRAEFIK_CHANNEL = "latest/edge"
TRAEFIK_REVISION = 233
WAZUH_INDEXER_CHANNEL = "4.11/edge"
WAZUH_INDEXER_REVISION = 9
WAZUH_DASHBOARD_CHANNEL = "4.11/edge"
WAZUH_DASHBOARD_REVISION = 17

WAZUH_SERVER_APP = "wazuh-server"
RECONCILE_LOG_PATTERN = re.compile(r"reconciled charm in (\S+) seconds")


def get_current_controller() -> str:
    """Return the name of the currently active Juju controller.

    Returns:
        The controller name reported by ``juju switch``.
    """
    result = subprocess.run(["juju", "switch"], capture_output=True, text=True, check=True)
    # juju switch outputs "controller:user/model" or just "controller"
    return result.stdout.strip().split(":")[0]


async def deploy_machine_model(
    machine_controller: Controller,
    model_name: str,
    machine_controller_name: str,
) -> tuple[Model, str, str]:
    """Deploy wazuh-indexer and wazuh-dashboard on the machine model.

    Args:
        machine_controller: Connected localhost controller.
        model_name: Name for the machine model.
        machine_controller_name: Name of the machine Juju controller.

    Returns:
        Tuple of (model, opensearch_offer_url, opensearch_app_name).
    """
    logger.info("Creating machine model %s", model_name)
    model = await machine_controller.add_model(model_name)
    await model.connect(f"{machine_controller_name}:admin/{model_name}")
    await model.set_config({"logging-config": "<root>=INFO;unit=DEBUG"})
    await model.set_constraints({"virt-type": "virtual-machine", "mem": 4096, "root-disk": 15000, "cores": 4})

    logger.info("Deploying self-signed-certificates on machine model")
    await model.deploy(
        "self-signed-certificates",
        application_name="self-signed-certificates",
        channel=SELF_SIGNED_CERTS_CHANNEL,
        config={"ca-common-name": "benchmark CA"},
    )

    logger.info("Deploying wazuh-indexer (single-node)")
    await model.deploy(
        "wazuh-indexer",
        application_name="wazuh-indexer",
        channel=WAZUH_INDEXER_CHANNEL,
        revision=WAZUH_INDEXER_REVISION,
        num_units=1,
        config={"profile": "testing"},
    )
    await model.integrate("self-signed-certificates", "wazuh-indexer")

    logger.info("Waiting for wazuh-indexer to become active")
    await model.wait_for_idle(
        apps=["wazuh-indexer"],
        status="active",
        raise_on_error=True,
        timeout=1800,
    )

    logger.info("Deploying wazuh-dashboard")
    await model.deploy(
        "wazuh-dashboard",
        application_name="wazuh-dashboard",
        channel=WAZUH_DASHBOARD_CHANNEL,
        revision=WAZUH_DASHBOARD_REVISION,
        num_units=1,
    )
    await model.integrate("self-signed-certificates", "wazuh-dashboard")
    await model.integrate("wazuh-indexer", "wazuh-dashboard")

    logger.info("Creating opensearch-client offer")
    offer_name = "wazuh-indexer"
    await model.create_offer("wazuh-indexer:opensearch-client", offer_name)
    offer_url = f"{machine_controller_name}:admin/{model_name}.{offer_name}"

    return model, offer_url, "wazuh-indexer"


async def deploy_k8s_model(
    k8s_controller: Controller,
    model_name: str,
    charm_file: str,
    wazuh_image: str,
    storage_pool: str | None = None,
    k8s_cloud: str | None = None,
) -> Model:
    """Create a k8s model and deploy self-signed-certs, traefik-k8s, and wazuh-server.

    Args:
        k8s_controller: Connected k8s controller.
        model_name: Name for the k8s model.
        charm_file: Path to the locally built .charm file.
        wazuh_image: OCI image reference for wazuh-server.
        storage_pool: Juju storage pool name to use for wazuh-server and traefik-k8s.
            If None, the controller default is used.
        k8s_cloud: Name of the k8s cloud registered on the controller. Required when
            the controller hosts both machine and k8s clouds (e.g. ``microk8s``).
            If None, the controller's default cloud is used.

    Returns:
        Connected k8s Model with all charms deployed and integrated.
    """
    logger.info("Creating k8s model %s", model_name)
    model = await k8s_controller.add_model(model_name, cloud_name=k8s_cloud)
    await model.set_config({"logging-config": "<root>=INFO;unit=DEBUG"})

    if storage_pool:
        logger.info("Creating Juju storage pool %s in model %s", storage_pool, model_name)
        await model.create_storage_pool(
            name=storage_pool,
            provider_type="kubernetes",
            attributes=f"storage-class={storage_pool}",
        )

    logger.info("Deploying self-signed-certificates on k8s")
    await model.deploy(
        "self-signed-certificates",
        application_name="self-signed-certificates",
        channel=SELF_SIGNED_CERTS_CHANNEL,
        config={"ca-common-name": "benchmark k8s CA"},
    )

    traefik_storage = (
        {"configurations": {"pool": storage_pool, "size": 1024}} if storage_pool else None
    )
    logger.info("Deploying traefik-k8s")
    await model.deploy(
        "traefik-k8s",
        application_name="traefik-k8s",
        channel=TRAEFIK_CHANNEL,
        revision=TRAEFIK_REVISION,
        trust=True,
        config={"external_hostname": "wazuh-server.local"},
        storage=traefik_storage,
    )

    wazuh_storage = (
        {
            "data": {"pool": storage_pool, "size": 1024},
            "logs": {"pool": storage_pool, "size": 1024},
        }
        if storage_pool
        else None
    )
    logger.info("Deploying wazuh-server from %s", charm_file)
    await model.deploy(
        f"./{charm_file}",
        application_name=WAZUH_SERVER_APP,
        resources={"wazuh-server-image": wazuh_image},
        config={"enable-vulnerability-detection": False},
        trust=True,
        storage=wazuh_storage,
    )

    await model.integrate("self-signed-certificates", WAZUH_SERVER_APP)
    await model.integrate("traefik-k8s", WAZUH_SERVER_APP)
    return model


async def wire_full_deploy(
    k8s_model: Model,
    k8s_model_name: str,
    machine_model: Model,
    machine_model_name: str,
    opensearch_offer_url: str,
    k8s_controller_name: str,
) -> None:
    """Wire cross-model relations and wait for all apps to become active.

    Args:
        k8s_model: Connected k8s model.
        k8s_model_name: Name of the k8s model.
        machine_model: Connected machine model.
        machine_model_name: Name of the machine model (unused, kept for logging).
        opensearch_offer_url: Cross-model offer URL for opensearch-client.
        k8s_controller_name: Name of the k8s Juju controller.
    """
    logger.info("Consuming opensearch-client offer on k8s model")
    await k8s_model.consume(opensearch_offer_url)
    await k8s_model.integrate("wazuh-indexer", WAZUH_SERVER_APP)

    logger.info("Creating wazuh-api offer on k8s model for wazuh-dashboard")
    await k8s_model.create_offer(f"{WAZUH_SERVER_APP}:wazuh-api", "wazuh-server")
    wazuh_api_offer_url = f"{k8s_controller_name}:admin/{k8s_model_name}.wazuh-server"
    await machine_model.consume(wazuh_api_offer_url)
    await machine_model.integrate("wazuh-server", "wazuh-dashboard")

    logger.info("Waiting for full deployment to become active")
    await k8s_model.wait_for_idle(
        apps=[WAZUH_SERVER_APP, "traefik-k8s", "self-signed-certificates"],
        status="active",
        raise_on_error=True,
        timeout=1800,
    )
    await machine_model.wait_for_idle(
        apps=["wazuh-indexer", "wazuh-dashboard", "self-signed-certificates"],
        status="active",
        raise_on_error=True,
        timeout=1800,
    )


def collect_diagnostics(
    machine_model_name: str,
    machine_controller_name: str,
) -> None:
    """Collect and log unit status and debug-log for the machine model.

    Called when an exception occurs so that hook error messages are captured
    before the models are destroyed in the finally block.

    Args:
        machine_model_name: Name of the machine model.
        machine_controller_name: Name of the machine Juju controller.
    """
    model_ref = f"{machine_controller_name}:admin/{machine_model_name}"
    logger.error("=== Diagnostic dump for %s ===", model_ref)

    for cmd in [
        ["juju", "status", "-m", model_ref, "--format", "yaml"],
        [
            "juju",
            "debug-log",
            "-m",
            model_ref,
            "--include",
            "unit-wazuh-indexer-0",
            "--replay",
            "--no-tail",
            "--level",
            "DEBUG",
        ],
        [
            "juju",
            "ssh",
            "-m",
            model_ref,
            "wazuh-indexer/0",
            "--",
            "sudo",
            "cat",
            "/var/log/juju/unit-wazuh-indexer-0.log",
        ],
    ]:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            output = (result.stdout or "") + (result.stderr or "")
            logger.error("--- %s ---\n%s", " ".join(cmd[1:3]), output)
        except Exception as exc:
            logger.error("Failed to run %s: %s", cmd, exc)


def collect_and_report_reconcile_times(model_name: str, k8s_controller_name: str) -> None:
    """Read juju debug-log and print reconcile timing statistics.

    Args:
        model_name: Name of the k8s model to read logs from.
        k8s_controller_name: Name of the k8s Juju controller.

    Raises:
        SystemExit: If no reconcile timing entries are found in the log.
    """
    logger.info("Reading Juju debug log for reconcile timings")
    result = subprocess.run(
        [
            "juju",
            "debug-log",
            "-m",
            f"{k8s_controller_name}:admin/{model_name}",
            "--include",
            f"unit-{WAZUH_SERVER_APP}-0",
            "--level",
            "DEBUG",
            "--replay",
            "--no-tail",
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )

    times = [float(m.group(1)) for m in RECONCILE_LOG_PATTERN.finditer(result.stdout)]

    if not times:
        logger.warning("No reconcile timing entries found in the debug log")
        logger.debug("debug-log stdout: %s", result.stdout[-2000:])
        sys.exit(1)

    print("\n=== Wazuh Server Reconcile Benchmark ===")
    for i, t in enumerate(times, 1):
        print(f"  Run {i}: {t:.3f}s")
    print(f"  Count : {len(times)}")
    print(f"  Min   : {min(times):.3f}s")
    print(f"  Max   : {max(times):.3f}s")
    print(f"  Avg   : {sum(times) / len(times):.3f}s")
    print("=========================================\n")


async def _cleanup(
    keep_models: bool,
    k8s_model: Model | None,
    k8s_model_name: str,
    k8s_controller: Controller,
    machine_model: Model | None,
    machine_model_name: str,
    machine_controller: Controller | None,
) -> None:
    """Disconnect and optionally destroy all Juju models and controllers.

    Args:
        keep_models: If True, skip model destruction.
        k8s_model: Connected k8s model, or None if not created.
        k8s_model_name: Name of the k8s model.
        k8s_controller: Connected k8s controller.
        machine_model: Connected machine model, or None if not created.
        machine_model_name: Name of the machine model.
        machine_controller: Connected machine controller, or None if not connected.
    """
    if not keep_models:
        if k8s_model is not None:
            logger.info("Destroying k8s model %s", k8s_model_name)
            try:
                await k8s_model.disconnect()
                await k8s_controller.destroy_model(k8s_model_name, destroy_storage=True)
                k8s_model = None
            except Exception as exc:
                logger.warning("Failed to destroy k8s model: %s", exc)
        if machine_model is not None and machine_controller is not None:
            logger.info("Destroying machine model %s", machine_model_name)
            try:
                await machine_model.disconnect()
                await machine_controller.destroy_model(machine_model_name, destroy_storage=True)
                machine_model = None
            except Exception as exc:
                logger.warning("Failed to destroy machine model: %s", exc)

    if k8s_model is not None:
        await k8s_model.disconnect()
    if machine_model is not None:
        await machine_model.disconnect()
    if machine_controller is not None:
        await machine_controller.disconnect()
    await k8s_controller.disconnect()


async def run_benchmark(
    charm_file: str,
    wazuh_image: str,
    model_name: str | None,
    keep_models: bool,
    full_deploy: bool,
    machine_controller_name: str,
    storage_pool: str | None,
    k8s_cloud: str | None,
) -> None:
    """Deploy wazuh-server and report reconcile times from the Juju debug log.

    Args:
        charm_file: Path to the locally built wazuh-server .charm file.
        wazuh_image: OCI image reference for the wazuh-server resource.
        model_name: Base name for Juju models. Auto-generated if None.
        keep_models: If True, do not destroy models after the benchmark.
        full_deploy: If True, also deploy wazuh-indexer and wazuh-dashboard.
        machine_controller_name: Name of the machine Juju controller (used with --full-deploy).
        storage_pool: Juju storage pool name to use for PVC provisioning. If None, uses default.
        k8s_cloud: Name of the k8s cloud on the controller to deploy wazuh-server on.
            Required when the controller hosts multiple clouds. If None, uses default.
    """
    base_name = model_name or f"benchmark-{secrets.token_hex(2)}"
    k8s_model_name = base_name
    machine_model_name = f"{base_name}-machine"

    if not Path(charm_file).exists():
        charm_file = str(Path("..") / charm_file)

    k8s_controller = Controller()
    await k8s_controller.connect()
    k8s_controller_name = get_current_controller()

    machine_controller: Controller | None = None
    machine_model: Model | None = None
    k8s_model: Model | None = None

    try:
        k8s_model = await deploy_k8s_model(
            k8s_controller, k8s_model_name, charm_file, wazuh_image, storage_pool, k8s_cloud
        )

        if full_deploy:
            machine_controller = Controller()
            await machine_controller.connect_controller(machine_controller_name)
            machine_model, opensearch_offer_url, _ = await deploy_machine_model(
                machine_controller, machine_model_name, machine_controller_name
            )
            await wire_full_deploy(
                k8s_model,
                k8s_model_name,
                machine_model,
                machine_model_name,
                opensearch_offer_url,
                k8s_controller_name,
            )
        else:
            # Without opensearch, wazuh-server will be Waiting — that's expected.
            # The reconcile timing is still logged because IncompleteStateError is caught
            # before the logger.debug call in charm.py.
            logger.info("Waiting for wazuh-server to become idle (Waiting status expected)")
            await k8s_model.wait_for_idle(
                apps=[WAZUH_SERVER_APP, "traefik-k8s", "self-signed-certificates"],
                raise_on_blocked=False,
                raise_on_error=False,
                timeout=600,
            )

        collect_and_report_reconcile_times(k8s_model_name, k8s_controller_name)

    except Exception:
        if full_deploy and machine_model_name:
            collect_diagnostics(machine_model_name, machine_controller_name)
        raise
    finally:
        await _cleanup(
            keep_models,
            k8s_model,
            k8s_model_name,
            k8s_controller,
            machine_model,
            machine_model_name,
            machine_controller,
        )


def main() -> None:
    """Parse arguments and run the benchmark."""
    parser = argparse.ArgumentParser(description="Benchmark wazuh-server charm reconcile time.")
    parser.add_argument("--charm-file", required=True, help="Path to the built .charm file.")
    parser.add_argument(
        "--wazuh-server-image", required=True, help="OCI image reference for wazuh-server."
    )
    parser.add_argument(
        "--model", default=None, help="Base name for Juju models (auto-generated if omitted)."
    )
    parser.add_argument(
        "--keep-models",
        action="store_true",
        help="Do not destroy Juju models after the benchmark.",
    )
    parser.add_argument(
        "--machine-controller",
        default="localhost",
        help="Name of the machine Juju controller used with --full-deploy (default: localhost).",
    )
    parser.add_argument(
        "--full-deploy",
        action="store_true",
        help=(
            "Also deploy wazuh-indexer and wazuh-dashboard and wire up all "
            "cross-model relations so wazuh-server reaches ActiveStatus."
        ),
    )
    parser.add_argument(
        "--storage-pool",
        default=None,
        help=(
            "Juju storage pool name to use for PVC provisioning "
            "(e.g. 'local-path'). If omitted, the controller default is used."
        ),
    )
    parser.add_argument(
        "--k8s-cloud",
        default=None,
        help=(
            "Name of the k8s cloud registered on the Juju controller "
            "(e.g. 'microk8s'). Required when the controller hosts both machine and k8s "
            "clouds so that the k8s model is created on the correct cloud. "
            "If omitted, the controller's default cloud is used."
        ),
    )
    args = parser.parse_args()

    asyncio.run(
        run_benchmark(
            charm_file=args.charm_file,
            wazuh_image=args.wazuh_server_image,
            model_name=args.model,
            keep_models=args.keep_models,
            full_deploy=args.full_deploy,
            machine_controller_name=args.machine_controller,
            storage_pool=args.storage_pool,
            k8s_cloud=args.k8s_cloud,
        )
    )


if __name__ == "__main__":
    main()
