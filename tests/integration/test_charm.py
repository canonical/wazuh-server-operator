#!/usr/bin/env python3

# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Integration tests."""

import logging
from pathlib import Path

import pytest
import yaml
from juju.application import Application
from juju.model import Model

logger = logging.getLogger(__name__)

CHARMCRAFT = yaml.safe_load(Path("./charmcraft.yaml").read_text(encoding="utf-8"))
APP_NAME = CHARMCRAFT["name"]


@pytest.mark.abort_on_fail
async def test_clustering_ok(model: Model, application: Application):
    """Deploy the charm together with related charms and scale to two units.

    Assert: the clustering config is valid.
    """
    await model.wait_for_idle(
        apps=[application.name], status="active", raise_on_blocked=True, timeout=1000
    )
    await application.scale(2)
    await model.wait_for_idle(idle_period=30, apps=[application.name], status="active")

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
    assert "master" in stdout
    assert "worker" in stdout

    action = await wazuh_unit.run(
        f"{pebble_exec} -- /var/ossec/bin/cluster_control -i", timeout=10
    )
    await action.wait()
    code = action.results.get("return-code")
    stdout = action.results.get("stdout")
    stderr = action.results.get("stderr")
    assert code == 0, f"cluster test for unit 0 failed with code {code}: {stderr or stdout}"
    assert "connected nodes (1)" in stdout
    assert "wazuh-server-1" in stdout


@pytest.mark.abort_on_fail
async def test_filebeat_ok(model: Model, application: Application):
    """Deploy the charm together with related charms.

    Assert: the filebeat config is valid.
    """
    await model.wait_for_idle(
        apps=[application.name], status="active", raise_on_blocked=True, timeout=1000
    )

    wazuh_unit = application.units[0]  # type: ignore
    pebble_exec = "PEBBLE_SOCKET=/charm/containers/wazuh-server/pebble.socket pebble exec"
    action = await wazuh_unit.run(f"{pebble_exec} -- /usr/bin/filebeat test output", timeout=10)
    await action.wait()
    logger.error(action.results)
    code = action.results.get("return-code")
    stdout = action.results.get("stdout")
    stderr = action.results.get("stderr")
    assert code == 0, f"filebeat test failed with code {code}: {stderr or stdout}"
