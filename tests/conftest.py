# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Fixtures for charm tests."""


def pytest_addoption(parser):
    """Parse additional pytest options.

    Args:
        parser: Pytest parser.
    """
    parser.addoption("--charm-file", action="store")
    parser.addoption("--kube-config", action="store", default="~/.kube/config")
    parser.addoption("--wazuh-server-image", action="store")
    parser.addoption("--single-node-indexer", action="store_true")
