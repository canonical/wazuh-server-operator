# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

r"""Benchmark script for measuring wazuh-server charm reconcile time.

Deploys the locally built wazuh-server charm with self-signed-certificates and
traefik-k8s on a Juju k8s model, integrates them, waits for idle, then reads the
Juju debug log to find and report the reconcile timing logged by the charm at DEBUG level.

With --full-deploy, also deploys wazuh-indexer and wazuh-dashboard on the machine
model and wires up all cross-model relations so wazuh-server reaches ActiveStatus.

With --with-tracing, also deploys tempo-k8s and relates it to wazuh-server via the
charm-tracing relation so that reconcile spans are exported to Tempo.

Usage:
    python tests/benchmark/benchmark.py \\
        --charm-file wazuh-server_ubuntu-22.04-amd64.charm \\
        --wazuh-server-image 10.x.x.x:32000/wazuh-server:1.0

    # Full topology (also deploys wazuh-indexer + wazuh-dashboard) with tracing:
    python tests/benchmark/benchmark.py \\
        --charm-file wazuh-server_ubuntu-22.04-amd64.charm \\
        --wazuh-server-image 10.x.x.x:32000/wazuh-server:1.0 \\
        --full-deploy \\
        --with-tracing
"""

import argparse
import asyncio
import csv
import datetime
import json
import logging
import re
import secrets
import socket
import statistics
import subprocess  # nosec B404
import sys
import time
from pathlib import Path

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
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
TEMPO_CHANNEL = "latest/stable"
TEMPO_APP = "tempo"

WAZUH_SERVER_APP = "wazuh-server"
RECONCILE_LOG_PATTERN = re.compile(r"reconciled charm in (\S+) seconds")


def generate_dummy_ca_cert() -> str:
    """Generate a self-signed CA certificate for use as ``logs-ca-cert`` config.

    The ``logs-ca-cert`` Juju config option has no default value in the charm,
    so Juju returns ``None`` for it when unset.  Pydantic v2 rejects ``None``
    for the required ``str`` field ``WazuhConfig.logs_ca_cert``, causing
    ``RecoverableStateError`` and a permanent ``blocked`` status.  Passing any
    valid PEM CA cert satisfies the pydantic constraint and lets reconcile reach
    the opensearch/cert checks.

    Returns:
        PEM-encoded self-signed CA certificate as a string.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "benchmark-ca")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def get_current_controller() -> str:
    """Return the name of the currently active Juju controller.

    Returns:
        The controller name reported by ``juju switch``.
    """
    result = subprocess.run(  # nosec B603 B607
        ["juju", "switch"], capture_output=True, text=True, check=True
    )
    # juju switch outputs "controller:user/model" or just "controller"
    return result.stdout.strip().split(":")[0]


async def deploy_machine_model(
    machine_controller: Controller,
    model_name: str,
    machine_controller_name: str,
    lxd_cloud: str = "localhost",
) -> tuple[Model, str, str]:
    """Deploy wazuh-indexer and wazuh-dashboard on the machine model.

    Args:
        machine_controller: Connected localhost controller.
        model_name: Name for the machine model.
        machine_controller_name: Name of the machine Juju controller.
        lxd_cloud: Name of the LXD cloud on the controller (default: ``localhost``).
            Must be specified explicitly when the controller also hosts a k8s cloud so
            that Juju does not default to the k8s cloud for this model.

    Returns:
        Tuple of (model, opensearch_offer_url, opensearch_app_name).
    """
    logger.info("Creating machine model %s on LXD cloud %s", model_name, lxd_cloud)
    model = await machine_controller.add_model(model_name, cloud_name=lxd_cloud)
    await model.connect(f"{machine_controller_name}:admin/{model_name}")
    await model.set_config({"logging-config": "<root>=INFO;unit=DEBUG"})
    await model.set_constraints(
        {"virt-type": "virtual-machine", "mem": 3072, "root-disk": 10000, "cores": 2}
    )

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
    with_tracing: bool = False,
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
        with_tracing: If True, also deploy tempo-k8s and relate it to wazuh-server
            via the charm-tracing relation.

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
    dummy_ca_cert = generate_dummy_ca_cert()
    await model.deploy(
        f"./{charm_file}",
        application_name=WAZUH_SERVER_APP,
        resources={"wazuh-server-image": wazuh_image},
        config={
            "enable-vulnerability-detection": False,
            "logs-ca-cert": dummy_ca_cert,
        },
        trust=True,
        storage=wazuh_storage,
    )

    # Integrate traefik FIRST and wait for it to become active so that
    # external_hostname is already populated in the traefik-route relation
    # data before self-signed-certificates is integrated.  Without this
    # ordering, certificates_relation_joined fires when external_hostname is
    # still None, is deferred, and there is a race where the deferred retry
    # occurs before self-signed-certs has issued the cert, causing wazuh-server
    # to remain blocked after opensearch connects.
    await model.integrate("traefik-k8s", WAZUH_SERVER_APP)

    if with_tracing:
        logger.info("Deploying tempo-k8s for charm tracing")
        await model.deploy(
            "tempo-k8s",
            application_name=TEMPO_APP,
            channel=TEMPO_CHANNEL,
            trust=True,
        )
        await model.integrate(f"{TEMPO_APP}:tracing", f"{WAZUH_SERVER_APP}:charm-tracing")

    logger.info(
        "Waiting for traefik-k8s and self-signed-certificates to become active "
        "before integrating self-signed-certificates so external_hostname is ready"
    )
    await model.wait_for_idle(
        apps=["traefik-k8s", "self-signed-certificates"],
        status="active",
        raise_on_error=True,
        timeout=600,
    )

    # Now integrate self-signed-certs.  external_hostname is already available
    # so certificates_relation_joined will send the CSR without deferral.
    await model.integrate(
        "self-signed-certificates:certificates", f"{WAZUH_SERVER_APP}:certificates"
    )

    # Poll until wazuh-server has transitioned away from the cert-pending
    # status messages.  Once certificate_available fires and reconcile runs,
    # the unit status becomes "Charm state is not yet ready" (IncompleteStateError
    # for opensearch) rather than a cert-related message, which is our signal
    # that the TLS certificate was actually issued and received.
    cert_pending_messages = {
        "Charm not ready to make a CSR.",
        "Certificates do not exist. Waiting for new certificates to be issued.",
    }
    logger.info("Waiting for TLS certificate to be issued to wazuh-server")
    deadline = time.monotonic() + 300
    while time.monotonic() < deadline:
        await asyncio.sleep(10)
        unit = model.units.get(f"{WAZUH_SERVER_APP}/0")
        if unit is None:
            continue
        workload_status = unit.workload_status or ""
        status_message = unit.workload_status_message or ""
        logger.info("wazuh-server/0 status: %s: %s", workload_status, status_message)
        if status_message not in cert_pending_messages and workload_status in (
            "waiting",
            "active",
            "blocked",
        ):
            logger.info(
                "TLS certificate received by wazuh-server (status: %s: %s)",
                workload_status,
                status_message,
            )
            break
    else:
        raise TimeoutError("Timed out waiting for TLS certificate to be issued to wazuh-server")
    return model


async def wire_full_deploy(
    k8s_model: Model,
    k8s_model_name: str,
    machine_model: Model,
    machine_model_name: str,
    opensearch_offer_url: str,
    k8s_controller_name: str,
    with_tracing: bool = False,
) -> None:
    """Wire cross-model relations and wait for all apps to become active.

    Args:
        k8s_model: Connected k8s model.
        k8s_model_name: Name of the k8s model.
        machine_model: Connected machine model.
        machine_model_name: Name of the machine model (unused, kept for logging).
        opensearch_offer_url: Cross-model offer URL for opensearch-client.
        k8s_controller_name: Name of the k8s Juju controller.
        with_tracing: If True, include tempo-k8s in the idle wait.
    """
    logger.info("Consuming opensearch-client offer on k8s model")
    await k8s_model.consume(opensearch_offer_url)
    await k8s_model.integrate("wazuh-indexer", WAZUH_SERVER_APP)

    logger.info("Creating wazuh-api offer on k8s model for wazuh-dashboard")
    await k8s_model.create_offer(f"{WAZUH_SERVER_APP}:wazuh-api", "wazuh-server")
    wazuh_api_offer_url = f"{k8s_controller_name}:admin/{k8s_model_name}.wazuh-server"
    await machine_model.consume(wazuh_api_offer_url)
    await machine_model.integrate("wazuh-server", "wazuh-dashboard")

    logger.info("Waiting for wazuh-server to become active")
    k8s_idle_apps = [WAZUH_SERVER_APP, "traefik-k8s", "self-signed-certificates"]
    if with_tracing:
        k8s_idle_apps.append(TEMPO_APP)
    await k8s_model.wait_for_idle(
        apps=k8s_idle_apps,
        status="active",
        raise_on_error=True,
        timeout=1800,
    )
    # Once wazuh-server is active, the cross-model opensearch relation is
    # confirmed working — no need to re-check wazuh-indexer's status here.
    # NOTE: wazuh-indexer's application-level status is "blocked" on single-node
    # deployments (replica shards unassigned), even though the unit itself is
    # active.  Waiting for it with status="active" would time out indefinitely.
    # wazuh-dashboard may also be blocked ("Opensearch service is down") on
    # initial deploy; that does not affect the reconcile-time measurement.
    await machine_model.wait_for_idle(
        apps=["wazuh-dashboard"],
        raise_on_blocked=False,
        raise_on_error=False,
        timeout=600,
    )
    logger.info("Full deployment ready — wazuh-server is active")


def collect_diagnostics(
    machine_model_name: str,
    machine_controller_name: str,
    k8s_model_name: str | None = None,
) -> None:
    """Collect and log unit status and debug-log for the machine and k8s models.

    Called when an exception occurs so that hook error messages are captured
    before the models are destroyed in the finally block.

    Args:
        machine_model_name: Name of the machine model.
        machine_controller_name: Name of the machine Juju controller.
        k8s_model_name: Name of the k8s model (same controller). If provided,
            the wazuh-server debug-log is also collected.
    """
    model_refs = [f"{machine_controller_name}:admin/{machine_model_name}"]
    if k8s_model_name:
        model_refs.append(f"{machine_controller_name}:admin/{k8s_model_name}")

    for model_ref in model_refs:
        logger.error("=== Diagnostic dump for %s ===", model_ref)
        is_k8s_model = k8s_model_name and model_ref.endswith(k8s_model_name)
        debug_log_cmd = [
            "juju",
            "debug-log",
            "-m",
            model_ref,
            "--replay",
            "--no-tail",
            "--level",
            "DEBUG",
        ]
        if is_k8s_model:
            # Filter to wazuh-server unit logs only so we always capture the
            # charm error message regardless of how many other log lines exist.
            debug_log_cmd += ["--include", f"unit-{WAZUH_SERVER_APP}-0"]
        else:
            debug_log_cmd += ["--limit", "500"]
        for cmd in [
            ["juju", "status", "-m", model_ref, "--format", "yaml"],
            debug_log_cmd,
        ]:
            try:
                result = subprocess.run(  # nosec B603 B607
                    cmd, capture_output=True, text=True, timeout=60
                )
                output = (result.stdout or "") + (result.stderr or "")
                logger.error("--- %s ---\n%s", " ".join(cmd[1:3]), output)
            except Exception as exc:
                logger.error("Failed to run %s: %s", cmd, exc)


def collect_and_report_reconcile_times(
    model_name: str,
    k8s_controller_name: str,
    runs_output: Path = Path("benchmark_runs.csv"),
    summary_output: Path = Path("benchmark_summary.csv"),
) -> None:
    """Read juju debug-log, print reconcile timing statistics and write CSV reports.

    Args:
        model_name: Name of the k8s model to read logs from.
        k8s_controller_name: Name of the k8s Juju controller.
        runs_output: Path to write the per-run reconcile times CSV file.
        summary_output: Path to write the summary statistics CSV file.

    Raises:
        SystemExit: If no reconcile timing entries are found in the log.
    """
    logger.info("Reading Juju debug log for reconcile timings")
    result = subprocess.run(  # nosec B603 B607
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

    logger.info("\n=== Wazuh Server Reconcile Benchmark ===")
    for i, t in enumerate(times, 1):
        logger.info("  Run %d: %.3fs", i, t)
    logger.info("  Count : %d", len(times))
    logger.info("  Min   : %.3fs", min(times))
    logger.info("  Max   : %.3fs", max(times))
    logger.info("  Avg   : %.3fs", sum(times) / len(times))
    logger.info("=========================================")

    write_reconcile_csv_reports(times, runs_output, summary_output)


def write_reconcile_csv_reports(
    times: list[float], runs_output: Path, summary_output: Path
) -> None:
    """Write per-run and summary CSV reports for the collected reconcile times.

    Two CSV files are produced:

    * ``runs_output`` contains one row per reconcile run with columns
      ``run`` (1-based index) and ``reconcile_seconds``.
    * ``summary_output`` contains aggregate statistics in a ``metric,value``
      layout (count, min, max, mean, median and stdev).

    Args:
        times: Reconcile durations in seconds, ordered by run.
        runs_output: Path to write the per-run reconcile times CSV file.
        summary_output: Path to write the summary statistics CSV file.
    """
    with runs_output.open("w", newline="", encoding="utf-8") as runs_file:
        writer = csv.writer(runs_file)
        writer.writerow(["run", "reconcile_seconds"])
        for i, t in enumerate(times, 1):
            writer.writerow([i, f"{t:.3f}"])
    logger.info("Wrote per-run reconcile times to %s", runs_output)

    summary = {
        "count": len(times),
        "min": min(times),
        "max": max(times),
        "mean": statistics.mean(times),
        "median": statistics.median(times),
        "stdev": statistics.stdev(times) if len(times) > 1 else 0.0,
    }
    with summary_output.open("w", newline="", encoding="utf-8") as summary_file:
        writer = csv.writer(summary_file)
        writer.writerow(["metric", "value"])
        writer.writerow(["count", summary["count"]])
        for metric in ("min", "max", "mean", "median", "stdev"):
            writer.writerow([metric, f"{summary[metric]:.3f}"])
    logger.info("Wrote summary statistics to %s", summary_output)


def _wait_for_port(host: str, port: int, timeout: float = 30.0) -> None:
    """Block until a TCP connection to host:port succeeds or timeout is reached.

    Args:
        host: Hostname or IP address to connect to.
        port: TCP port number.
        timeout: Maximum seconds to wait before raising TimeoutError.

    Raises:
        TimeoutError: If the port is not reachable within the timeout.
    """
    deadline = time.monotonic() + timeout
    while True:
        try:
            with socket.create_connection((host, port), timeout=1):
                return
        except OSError:
            if time.monotonic() >= deadline:
                raise TimeoutError(f"Port {host}:{port} not reachable after {timeout}s")
            time.sleep(0.2)


def export_traces(model_name: str, output_file: Path) -> None:
    r"""Export all Tempo traces to an OTLP JSON file before model teardown.

    Opens a ``kubectl port-forward`` to the Tempo service in the k8s model,
    queries the Tempo HTTP API to retrieve all trace IDs and their spans, then
    writes a single OTLP JSON file (``resourceSpans`` format) containing every
    resource-span batch.

    The resulting file can be viewed as a flame graph in Jaeger UI::

        # 1. Start Jaeger (one-time)
        docker run -d -p 16686:16686 -p 4318:4318 \
            -e COLLECTOR_OTLP_ENABLED=true \
            jaegertracing/all-in-one:latest

        # 2. Push the traces
        curl -X POST http://localhost:4318/v1/traces \
            -H "Content-Type: application/json" \
            -d @traces.json

        # 3. Open http://localhost:16686, select service "wazuh-server",
        #    click a trace → use the flame graph icon for flame graph view.

    Args:
        model_name: Name of the k8s model, which is also the k8s namespace.
        output_file: Destination path for the OTLP JSON trace export.
    """
    logger.info("Exporting traces from Tempo to %s", output_file)
    port_forward = subprocess.Popen(  # nosec B603 B607
        [
            "sudo",
            "microk8s",
            "kubectl",
            "port-forward",
            "-n",
            model_name,
            "svc/tempo",
            "3200:3200",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        _wait_for_port("localhost", 3200, timeout=30)
        tempo_url = "http://localhost:3200"

        search = requests.get(f"{tempo_url}/api/search", params={"limit": 100}, timeout=10)
        search.raise_for_status()
        trace_ids = [t["traceID"] for t in search.json().get("traces", [])]
        logger.info("Found %d traces in Tempo", len(trace_ids))

        resource_spans: list[dict] = []
        for trace_id in trace_ids:
            resp = requests.get(
                f"{tempo_url}/api/traces/{trace_id}",
                headers={"Accept": "application/json"},
                timeout=10,
            )
            resp.raise_for_status()
            # Tempo returns {"batches": [...]} — rename to "resourceSpans" for OTLP HTTP.
            resource_spans.extend(resp.json().get("batches", []))

        # Write as OTLP ExportTraceServiceRequest JSON so the file can be POSTed
        # directly to any OTLP HTTP collector (e.g. Jaeger all-in-one on port 4318).
        output_file.write_text(json.dumps({"resourceSpans": resource_spans}, indent=2))
        logger.info(
            "Exported %d resource-span batches (%d traces) to %s",
            len(resource_spans),
            len(trace_ids),
            output_file,
        )
        logger.info("Traces exported to: %s", output_file.resolve())
        logger.info("To view as flame graph:")
        logger.info(
            "  docker run -d -p 16686:16686 -p 4318:4318 "
            "-e COLLECTOR_OTLP_ENABLED=true jaegertracing/all-in-one:latest"
        )
        logger.info(
            "  curl -X POST http://localhost:4318/v1/traces "
            '-H "Content-Type: application/json" -d @%s',
            output_file,
        )
        logger.info("  open http://localhost:16686")
    except Exception as exc:
        logger.warning("Failed to export traces from Tempo: %s", exc)
    finally:
        port_forward.terminate()
        port_forward.wait()


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
    lxd_cloud: str,
    with_tracing: bool = False,
    traces_output: str = "traces.json",
    runs_output: str = "benchmark_runs.csv",
    summary_output: str = "benchmark_summary.csv",
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
        lxd_cloud: Name of the LXD cloud on the controller for the machine model.
            Explicitly passed to avoid Juju defaulting to the k8s cloud.
        with_tracing: If True, deploy tempo-k8s and relate it to wazuh-server.
        traces_output: Path to write exported OTLP JSON traces when with_tracing is True.
        runs_output: Path to write the per-run reconcile times CSV file.
        summary_output: Path to write the summary statistics CSV file.
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
            k8s_controller,
            k8s_model_name,
            charm_file,
            wazuh_image,
            storage_pool,
            k8s_cloud,
            with_tracing=with_tracing,
        )

        if full_deploy:
            machine_controller = Controller()
            await machine_controller.connect_controller(machine_controller_name)
            machine_model, opensearch_offer_url, _ = await deploy_machine_model(
                machine_controller, machine_model_name, machine_controller_name, lxd_cloud
            )
            await wire_full_deploy(
                k8s_model,
                k8s_model_name,
                machine_model,
                machine_model_name,
                opensearch_offer_url,
                k8s_controller_name,
                with_tracing=with_tracing,
            )
        else:
            # Without opensearch, wazuh-server will be Waiting — that's expected.
            # The reconcile timing is still logged because IncompleteStateError is caught
            # before the logger.debug call in charm.py.
            logger.info("Waiting for wazuh-server to become idle (Waiting status expected)")
            idle_apps = [WAZUH_SERVER_APP, "traefik-k8s", "self-signed-certificates"]
            if with_tracing:
                idle_apps.append(TEMPO_APP)
            await k8s_model.wait_for_idle(
                apps=idle_apps,
                raise_on_blocked=False,
                raise_on_error=False,
                timeout=600,
            )

        collect_and_report_reconcile_times(
            k8s_model_name,
            k8s_controller_name,
            Path(runs_output),
            Path(summary_output),
        )
        if with_tracing:
            export_traces(k8s_model_name, Path(traces_output))

    except Exception:
        if full_deploy and machine_model_name:
            collect_diagnostics(machine_model_name, machine_controller_name, k8s_model_name)
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
    parser.add_argument(
        "--lxd-cloud",
        default="localhost",
        help=(
            "Name of the LXD cloud registered on the Juju controller "
            "(default: 'localhost'). Used with --full-deploy to ensure the machine "
            "model is created on LXD and not accidentally on a k8s cloud."
        ),
    )
    parser.add_argument(
        "--with-tracing",
        action="store_true",
        help=(
            "Deploy tempo-k8s and relate it to wazuh-server via the charm-tracing "
            "relation so that reconcile spans are exported to Tempo during the benchmark."
        ),
    )
    parser.add_argument(
        "--traces-output",
        default="traces.json",
        help=(
            "Path to write the exported OTLP JSON traces file when --with-tracing is set "
            "(default: traces.json). Load into Jaeger UI for flame graph visualization: "
            "docker run -p 16686:16686 jaegertracing/jaeger:2"
        ),
    )
    parser.add_argument(
        "--runs-output",
        default="benchmark_runs.csv",
        help=(
            "Path to write the per-run reconcile times CSV file, with one row per run "
            "(default: benchmark_runs.csv)."
        ),
    )
    parser.add_argument(
        "--summary-output",
        default="benchmark_summary.csv",
        help=(
            "Path to write the summary statistics CSV file (count, min, max, mean, "
            "median, stdev) (default: benchmark_summary.csv)."
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
            lxd_cloud=args.lxd_cloud,
            with_tracing=args.with_tracing,
            traces_output=args.traces_output,
            runs_output=args.runs_output,
            summary_output=args.summary_output,
        )
    )


if __name__ == "__main__":
    main()
