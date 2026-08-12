#!/usr/bin/env python3

# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Integration tests."""

import asyncio
import logging
import secrets
import ssl
from pathlib import Path

import pytest
import requests
import requests.adapters
import yaml
from juju.application import Application
from juju.model import Model
from juju.unit import Unit
from pytest_operator.plugin import OpsTest

import state
import wazuh
from tests.integration.helpers import (
    RsyslogCertificateAuthority,
    found_in_logs,
    get_k8s_service_address,
    get_wazuh_ip,
    provision_rsyslog_certificates,
    send_syslog_over_tls,
)

logger = logging.getLogger(__name__)

CHARMCRAFT = yaml.safe_load(Path("./charmcraft.yaml").read_text(encoding="utf-8"))
APP_NAME = CHARMCRAFT["name"]

PEBBLE_SOCKET = "/charm/containers/wazuh-server/pebble.socket"
PEBBLE_EXEC = f"PEBBLE_SOCKET={PEBBLE_SOCKET} /charm/bin/pebble exec"


@pytest.mark.abort_on_fail
async def test_api(model: Model, application: Application, traefik: Application):
    """
    Arrange: deploy the charm together with related charms.
    Act: do nothing.
    Assert: the default credentials are no longer valid for the API.
    """
    await model.wait_for_idle(
        apps=[application.name, traefik.name], status="active", timeout=1200, idle_period=20
    )

    traefik_ip = await get_k8s_service_address(model, "traefik-k8s-lb")
    response = requests.get(  # nosec
        f"https://{traefik_ip}:{wazuh.API_PORT}/security/user/authenticate",
        auth=("wazuh", state.WAZUH_USERS["wazuh"]["default_password"]),
        timeout=10,
        verify=False,
    )

    assert response.status_code == 401, response.content


@pytest.mark.abort_on_fail
async def test_clustering_ok(model: Model, application: Application, traefik: Application):
    """
    Arrange: deploy the charm together with related charms.
    Act: scale up to two units.
    Assert: the clustering config is valid.
    """
    await application.scale(2)
    await model.wait_for_idle(apps=[application.name, traefik.name], status="active", timeout=1400)
    wazuh_unit = application.units[0]  # type: ignore
    action = await wazuh_unit.run(
        f"{PEBBLE_EXEC} -- /var/ossec/bin/cluster_control -l", timeout=10
    )
    await action.wait()
    code = action.results.get("return-code")
    stdout = action.results.get("stdout")
    stderr = action.results.get("stderr")
    assert code == 0, f"cluster test for unit 0 failed with code {code}: {stderr or stdout}"
    assert "master" in stdout, stdout
    assert "worker" in stdout, stdout

    action = await wazuh_unit.run(
        f"{PEBBLE_EXEC} -- /var/ossec/bin/cluster_control -i", timeout=10
    )
    await action.wait()
    code = action.results.get("return-code")
    stdout = action.results.get("stdout")
    stderr = action.results.get("stderr")
    assert code == 0, f"cluster test for unit 0 failed with code {code}: {stderr or stdout}"
    assert "connected nodes (1)" in stdout, stdout
    assert "wazuh-server-1" in stdout, stdout


@pytest.mark.abort_on_fail
async def test_cluster_api_credentials(
    model: Model, application: Application, traefik: Application
):
    """
    Arrange: NA, leverage prior test's arrangement.
    Act: retrieve leader-created API credentials, test against leader and non-leader API.
    Assert: the API credentials are valid.
    """
    await model.wait_for_idle(apps=[application.name, traefik.name], status="active", timeout=1400)

    wazuh_leader = None
    wazuh_followers = []
    for unit in application.units:
        if await unit.is_leader_from_status():
            wazuh_leader = unit
        else:
            wazuh_followers.append(unit)

    assert isinstance(wazuh_leader, Unit), "Could not find Wazuh leader"

    # get API password for wazuh
    action = await wazuh_leader.run(
        f"secret-get --label {state.WAZUH_API_CREDENTIAL_SECRET_LABEL} | grep -oP 'wazuh: \\K.*'",
        timeout=10,
    )
    await action.wait()
    code = action.results.get("return-code")
    stdout = action.results.get("stdout")
    stderr = action.results.get("stderr")
    assert code == 0, f"Failed to get Wazuh API credentials: {stderr or stdout}"
    password = stdout.strip()

    # test API connection
    for unit in application.units:
        action = await unit.run(
            "ip -o -4 addr show dev eth0 | grep -oP 'inet \\K[^/]+'", timeout=10
        )
        await action.wait()
        code = action.results.get("return-code")
        stdout = action.results.get("stdout")
        stderr = action.results.get("stderr")
        assert code == 0, f"Failed to get unit IP: {stderr or stdout}"
        ip = stdout.strip()

        logger.info(
            "Attempting auth with Wazuh API on unit %s (IP %s) with password %s",
            unit.name,
            ip,
            password,
        )
        retries = 5
        while retries:
            url = f"https://{ip}:55000/security/user/authenticate"
            response = requests.get(  # nosec
                url,
                auth=("wazuh", password),
                timeout=10,
                verify=False,
            )

            if response.status_code == 200:
                break

            logger.warning(
                "Wazuh API authentication failed with status %s. %s retries remaining. %s.",
                response.status_code,
                retries,
                url,
            )
            retries -= 1
            await asyncio.sleep(1)
        assert response.status_code == 200, f"Wazuh API authentication failed for {unit.name}."
        logger.info("Successfully authenticated to API on unit %s", unit.name)


@pytest.mark.abort_on_fail
async def test_rsyslog_invalid_server_ca(application: Application):
    """
    Arrange: a working Wazuh deployment with a CA not matching the client CA
    Act: send a syslog message over tls
    Assert: the client raises an error
    """
    assert application
    ca_cert = (Path(__file__).parent / "certs/ca.crt").read_text()
    wazuh_ip = await get_wazuh_ip(application.model.name)

    with pytest.raises(ssl.SSLCertVerificationError):
        await send_syslog_over_tls("test", host=wazuh_ip, server_ca=ca_cert, valid_cn=True)


@pytest.mark.parametrize(
    ["valid_cn", "expect_logs"],
    [
        pytest.param(True, True, id="valid"),
        pytest.param(False, False, id="invalid"),
    ],
)
async def test_rsyslog_client_cn(
    application: Application,
    traefik: Application,
    rsyslog_ca: RsyslogCertificateAuthority,
    valid_cn: bool,
    expect_logs: bool,
):
    """
    Arrange: a working Wazuh deployment with a log-certification-authority configured
    Act: send a syslog message over tls (with or without a valid CN)
    Assert: the message appears in the log only if the CN is valid
    """
    controller = await application.model.get_controller()
    model_url = f"{controller.controller_name}:{application.model.name}"
    if len(application.units) < 2:
        await application.scale(2)
        # The new unit requests its own rsyslog certificate; provide it before waiting active.
        await provision_rsyslog_certificates(model_url, rsyslog_ca)
        await application.model.wait_for_idle(
            apps=[application.name, traefik.name], status="active", timeout=1400
        )
    server_ca_cert = rsyslog_ca.root_certificate
    wazuh_ip = await get_wazuh_ip(model_url)

    needle = secrets.token_hex()
    sent = await send_syslog_over_tls(
        needle, host=wazuh_ip, server_ca=server_ca_cert, valid_cn=valid_cn
    )
    assert sent, "Log was not sent."

    sent = await send_syslog_over_tls(
        needle, host=wazuh_ip, server_ca=server_ca_cert, valid_cn=valid_cn
    )
    assert sent, "Log was not sent."
    log_timeout = 15.0 if expect_logs else 0.0
    found_0 = await found_in_logs(
        needle, application.model.name, application.units[0].name, timeout=log_timeout
    )
    found_1 = await found_in_logs(
        needle, application.model.name, application.units[1].name, timeout=log_timeout
    )

    found = found_0 or found_1
    assert found is expect_logs, f"Found logs={found}, while expected logs={expect_logs}"


@pytest.mark.abort_on_fail
async def test_opencti_integration(
    any_opencti: Application,
    application: Application,
    ops_test: OpsTest,
):
    """
    Arrange: A working Wazuh deployment integrated with OpenCTI any-charm.
    Act: Get the unit data for both wazuh-server and any-opencti charms.
    Assert: The required opencti data is present.
    """
    assert any_opencti
    assert application

    app_data = {}
    any_opencti_name = any_opencti.units[0].name
    _, result, _ = await ops_test.juju("show-unit", any_opencti_name)
    opencti_unit_data = yaml.safe_load(result)
    for relation in opencti_unit_data[any_opencti_name]["relation-info"]:
        if relation["endpoint"] == "require-opencti-connector":
            app_data = relation["application-data"]
    for key in ["connector_charm_name", "connector_type"]:
        assert key in app_data, f"Missing key in app data: {key}"

    wazuh_server_name = application.units[0].name
    _, result, _ = await ops_test.juju("show-unit", wazuh_server_name)
    wazuh_server_unit_data = yaml.safe_load(result)
    for relation in wazuh_server_unit_data[wazuh_server_name]["relation-info"]:
        if relation["endpoint"] == "opencti-connector":
            app_data = relation["application-data"]
    for key in ["opencti_url", "opencti_token"]:
        assert key in app_data, f"Missing key in app data: {key}"


@pytest.mark.abort_on_fail
async def test_filebeat_credentials(
    model: Model,
    machine_model: Model,
    application: Application,
    opensearch_provider: Application,
):
    """
    Arrange: A working Wazuh deployment integrated with the Wazuh indexer.
    Act: Validate filebeat output configuration.
    Assert: Filebeat successfully authenticates to and trusts the indexer.
    """
    assert application

    await model.wait_for_idle(apps=[application.name], status="active", timeout=1400)
    await machine_model.wait_for_idle(
        apps=[opensearch_provider.name], status="active", timeout=1400
    )
    wazuh_unit = application.units[0]  # type: ignore
    action = await wazuh_unit.run(f"{PEBBLE_EXEC} -- /usr/bin/filebeat test output", timeout=10)
    await action.wait()
    code = action.results.get("return-code")
    stdout = action.results.get("stdout")
    stderr = action.results.get("stderr")
    assert code == 0, f"filebeat output test failed with code {code}: {stderr or stdout}"


@pytest.mark.abort_on_fail
async def test_rsyslog_full_chain_written(application: Application):
    """
    Arrange: a Wazuh deployment whose rsyslog certificate is issued from a 3-tier chain
        (leaf -> intermediate -> root).
    Act: read the certificate file the charm wrote for rsyslog.
    Assert: it holds the full chain (>= 3 certificates), not just the leaf.

    That the served chain actually validates against the root (i.e. the intermediate is
    presented) is covered by test_rsyslog_client_cn, which trusts only the root CA.
    """
    wazuh_unit = application.units[0]
    action = await wazuh_unit.run(f"{PEBBLE_EXEC} -- cat /etc/rsyslog.d/certs/certificate.pem")
    await action.wait()
    certificate_count = (action.results.get("stdout") or "").count("-----BEGIN CERTIFICATE-----")
    assert certificate_count >= 3, f"Expected the full chain, found {certificate_count}"
