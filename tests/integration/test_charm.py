#!/usr/bin/env python3

# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Integration tests."""

import logging
import secrets
import ssl
from pathlib import Path

import pytest
import requests
import yaml
from juju.application import Application
from juju.model import Model
from pytest_operator.plugin import OpsTest

import state
import wazuh
from tests.integration.helpers import (
    found_in_logs,
    get_ca_certificate,
    get_k8s_service_address,
    get_wazuh_ip,
    send_syslog_over_tls,
)

logger = logging.getLogger(__name__)

CHARMCRAFT = yaml.safe_load(Path("./charmcraft.yaml").read_text(encoding="utf-8"))
APP_NAME = CHARMCRAFT["name"]


@pytest.mark.abort_on_fail
async def test_api(model: Model, application: Application):
    """
    Arrange: deploy the charm together with related charms.
    Act: do nothing.
    Assert: the default credentials are no longer valid for the API.
    """
    await model.wait_for_idle(apps=[application.name], status="active", timeout=1400)

    traefik_ip = await get_k8s_service_address(model, "traefik-k8s-lb")
    response = requests.get(  # nosec
        f"https://{traefik_ip}:{wazuh.API_PORT}/security/user/authenticate",
        auth=("wazuh", state.WAZUH_USERS["wazuh"]["default_password"]),
        timeout=10,
        verify=False,
    )

    assert response.status_code == 401, response.content


@pytest.mark.skip
@pytest.mark.abort_on_fail
async def test_clustering_ok(model: Model, application: Application):
    """
    Arrange: deploy the charm together with related charms.
    Act: scale up to two units.
    Assert: the clustering config is valid.
    """
    await application.scale(2)
    await model.wait_for_idle(apps=[application.name], status="active", timeout=1400)
    wazuh_unit = application.units[0]  # type: ignore
    pebble_exec = "PEBBLE_SOCKET=/charm/containers/wazuh-server/pebble.socket pebble exec"
    action = await wazuh_unit.run(
        f"{pebble_exec} -- /var/ossec/bin/cluster_control -l", timeout=10
    )
    await action.wait()
    code = action.results.get("return-code")
    stdout = action.results.get("stdout")
    stderr = action.results.get("stderr")
    assert code == 0, f"cluster test for unit 0 failed with code {code}: {stderr or stdout}"
    assert "master" in stdout, stdout
    assert "worker" in stdout, stdout

    action = await wazuh_unit.run(
        f"{pebble_exec} -- /var/ossec/bin/cluster_control -i", timeout=10
    )
    await action.wait()
    code = action.results.get("return-code")
    stdout = action.results.get("stdout")
    stderr = action.results.get("stderr")
    assert code == 0, f"cluster test for unit 0 failed with code {code}: {stderr or stdout}"
    assert "connected nodes (1)" in stdout, stdout
    assert "wazuh-server-1" in stdout, stdout


@pytest.mark.abort_on_fail
async def test_rsyslog_invalid_server_ca(application: Application):
    """
    Arrange: a working Wazuh deployment with a CA not matching the client CA
    Act: send a syslog message over tls
    Assert: the client raises an error
    """
    assert application
    ca_cert = (Path(__file__).parent / "certs/ca.crt").read_text()

    wazuh_ip = await get_wazuh_ip()

    with pytest.raises(ssl.SSLCertVerificationError):
        await send_syslog_over_tls("test", host=wazuh_ip, server_ca=ca_cert, valid_cn=True)


@pytest.mark.parametrize(
    ["valid_cn", "expect_logs"],
    [
        pytest.param(True, True, id="valid"),
        pytest.param(False, False, id="invalid"),
    ],
)
async def test_rsyslog_client_cn(application: Application, valid_cn: bool, expect_logs: bool):
    """
    Arrange: a working Wazuh deployment with a log-certification-authority configured
    Act: send a syslog message over tls (with or without a valid CN)
    Assert: the message appears in the log only if the CN is valid
    """
    assert application
    server_ca_cert = await get_ca_certificate()
    wazuh_ip = await get_wazuh_ip()

    needle = secrets.token_hex()
    sent = await send_syslog_over_tls(
        needle, host=wazuh_ip, server_ca=server_ca_cert, valid_cn=valid_cn
    )
    assert sent, "Log was not sent."

    found = await found_in_logs(needle)

    assert found is expect_logs, f"Found logs={found}, while expected logs={expect_logs}"


async def test_opencti_integration(
    any_opencti: Application,
    application: Application,
    ops_test: OpsTest,
):
    """
    Arrange: a working Wazuh deployment integrated with OpenCTI any-charm.
    Act: do nothing.
    Assert: the opencti-connector relation is established and the required data is present.
    """
    assert any_opencti
    assert application

    unit_name = any_opencti.units[0].name
    result = await ops_test.juju("show-unit", unit_name)
    print(f"{unit_name} show-unit result: ", result)

    unit_name = application.units[0].name
    result = await ops_test.juju("show-unit", unit_name)
    print(f"{unit_name} show-unit result: ", result)
    show_unit = yaml.safe_load(result.stdout)
    print("Show unit: ", show_unit)

    unit_info = show_unit[unit_name]
    relation_info = unit_info.get("relation-info", [])
    print("Relation info: ", relation_info)

    for rel in relation_info:
        if rel.get("endpoint") == "opencti-connector":
            app_data = rel.get("application-data", {})
            related_units = rel.get("related-units", {})

            for unit, unit_data in related_units.items():
                print(f"Unit: {unit}")
                print(f"nit databag: {unit_data.get('data', {})}")
            break
    else:
        pytest.fail("No relation found between wazuh:opencti and opencti:connector")

    for key in ["connector_charm_name", "connector_type", "opencti_url", "opencti_token"]:
        assert key in app_data, f"Missing key in app data: {key}"
