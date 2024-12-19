#!/usr/bin/env python3

# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Integration tests."""

import logging
from pathlib import Path

import pytest
import requests
import yaml
from juju.application import Application
from juju.model import Model

import state

logger = logging.getLogger(__name__)

CHARMCRAFT = yaml.safe_load(Path("./charmcraft.yaml").read_text(encoding="utf-8"))
APP_NAME = CHARMCRAFT["name"]


@pytest.mark.abort_on_fail
async def test_api(model: Model, application: Application):
    """
    Arrange: deploy the charm together with related charms.
    Act: scale up to two units
    Assert: the default credentials are no longer valid for any of the units.
    """
    await application.scale(2)
    await model.wait_for_idle(
        apps=[application.name], status="active", raise_on_blocked=True, timeout=1000
    )

    status = await model.get_status()
    units = list(status.applications[application.name].units)
    for unit in units:
        address = status["applications"][application.name]["units"][unit]["address"]
        # Check the defaults are changed instead of the new creds
        # https://github.com/juju/python-libjuju/issues/947
        response = requests.get(  # nosec
            f"https://{address}:55000/security/user/authenticate",
            auth=("wazuh", state.WAZUH_USERS["wazuh"]["default_password"]),
            timeout=10,
            verify=False,
        )
        assert response.status_code == 401, f"Default user still in use for unit {unit.name}"


@pytest.mark.abort_on_fail
async def test_clustering_ok(application: Application):
    """
    Arrange: deploy the charm together with related charms.
    Act: scale up to two units
    Assert: the clustering config is valid.
    """
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
