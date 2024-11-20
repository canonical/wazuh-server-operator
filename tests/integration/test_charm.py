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

logger = logging.getLogger(__name__)

CHARMCRAFT = yaml.safe_load(Path("./charmcraft.yaml").read_text(encoding="utf-8"))
APP_NAME = CHARMCRAFT["name"]


@pytest.mark.abort_on_fail
async def test_filebeat_ok(application: Application):
    """Deploy the charm together with related charms.

    Assert: the filebeat config is valid.
    """
    wazuh_unit = application.units[0]  # type: ignore
    output = await wazuh_unit.run("filebeat test output", timeout=10)
    code = output.data["results"].get("Code")
    stdout = output.data["results"].get("Stdout")
    stderr = output.data["results"].get("Stderr")
    assert code == "0", f"filebeat test failed with code {code}: {stderr or stdout}"


@pytest.mark.abort_on_fail
async def test_api(model: Model, application: Application, api_password: str):
    """Deploy the charm together with related charms.

    Assert: the filebeat config is valid.
    """
    status = await model.get_status()
    unit = list(status.applications[application.name].units)[0]
    address = status["applications"][application.name]["units"][unit]["address"]
    auth = f"Bearer wazuh:{api_password}"
    response = requests.post(  # nosec
        f"https://{address}:55000/security/user/authenticate",
        headers={"Authorization": auth},
        timeout=10,
        verify=False,
    )
    assert response.status_code == 200


@pytest.mark.abort_on_fail
async def test_clustering_ok(model: Model, application: Application):
    """Deploy the charm together with related charms and scale to two units.

    Assert: the clustering config is valid.
    """
    await application.scale(2)
    await model.wait_for_idle(idle_period=30, apps=[application.name], status="active")

    wazuh_unit = application.units[0]  # type: ignore
    output = await wazuh_unit.run("/var/ossec/bin/cluster_control -l", timeout=10)
    code = output.data["results"].get("Code")
    stdout = output.data["results"].get("Stdout")
    stderr = output.data["results"].get("Stderr")
    assert code == "0", f"cluster test for unit 0 failed with code {code}: {stderr or stdout}"
    assert "master" in stdout
    assert "worker" in stdout

    output = await wazuh_unit.run("/var/ossec/bin/cluster_control -i", timeout=10)
    code = output.data["results"].get("Code")
    stdout = output.data["results"].get("Stdout")
    stderr = output.data["results"].get("Stderr")
    assert code == "0", f"cluster test for unit 0 failed with code {code}: {stderr or stdout}"
    assert "connected nodes (1)" in stdout
    assert "wazuh-server-1" in stdout
