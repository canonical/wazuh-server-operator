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
async def test_filebeat_ok(model: Model, application: Application):
    """Deploy the charm together with related charms.

    Assert on the unit status.
    """
    model.wait_for_idle(
        apps=[application.name], status="active", raise_on_blocked=True, timeout=1000
    )
    wazuh_unit = application.units[0]  # type: ignore
    output = await wazuh_unit.run("filebeat test output", timeout=10)
    code = output.data["results"].get("Code")
    stdout = output.data["results"].get("Stdout")
    stderr = output.data["results"].get("Stderr")
    assert code == "0", f"filebeat test failed with code {code}: {stderr or stdout}"
