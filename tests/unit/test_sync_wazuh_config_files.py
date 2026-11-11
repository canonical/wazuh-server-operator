# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Scenario-based unit tests for wazuh.sync_wazuh_config_files.

These tests use ops.testing's Scenario framework (Context/State/Container/Manager)
rather than the deprecated Harness, and lean on the shared fixtures/helpers in
conftest.py to keep the test bodies focused on behaviour rather than test
scaffolding.
"""

from unittest.mock import ANY

import wazuh

from .conftest import fake_missing_paths, real_rsync, track_exec

INTERNAL_OPTIONS_CONF_PATH = "/var/ossec/etc/internal_options.conf"
STOCK_INTERNAL_OPTIONS_CONF = "# DO NOT TOUCH THIS FILE\nanalysisd.default_timeframe=360\n"


def test_preserves_stock_internal_options_conf_when_absent_from_repository(
    monkeypatch, synced_wazuh_container
):
    """
    arrange: a container with a stock internal_options.conf already in place, and a
        custom repository that does not provide its own var/ossec/etc/internal_options.conf.
    act: resync the wazuh config files, running the real rsync binary.
    assert: the stock internal_options.conf is still present in the container, unchanged -
        it is not deleted just because the repository omits it.
    """
    container, _ = synced_wazuh_container
    real_rsync(monkeypatch, container)
    container.push(
        INTERNAL_OPTIONS_CONF_PATH, STOCK_INTERNAL_OPTIONS_CONF, encoding="utf-8", make_dirs=True
    )

    changed = wazuh.sync_wazuh_config_files(container)

    assert changed is True
    assert container.exists(INTERNAL_OPTIONS_CONF_PATH)
    assert (
        container.pull(INTERNAL_OPTIONS_CONF_PATH, encoding="utf-8").read()
        == STOCK_INTERNAL_OPTIONS_CONF
    )


def test_applies_repository_provided_internal_options_conf(monkeypatch, synced_wazuh_container):
    """
    arrange: a container with a stock internal_options.conf already in place, and a
        custom repository that provides its own, different
        var/ossec/etc/internal_options.conf.
    act: resync the wazuh config files, running the real rsync binary.
    assert: the repository's internal_options.conf lands in the container, replacing the
        stock one.
    """
    container, _ = synced_wazuh_container
    real_rsync(monkeypatch, container)
    container.push(
        INTERNAL_OPTIONS_CONF_PATH, STOCK_INTERNAL_OPTIONS_CONF, encoding="utf-8", make_dirs=True
    )
    custom_internal_options_conf = (
        "# custom internal_options.conf\nanalysisd.default_timeframe=720\n"
    )
    container.push(
        f"{wazuh.REPO_WAZUH_CONF_PATH}/etc/internal_options.conf",
        custom_internal_options_conf,
        encoding="utf-8",
        make_dirs=True,
    )

    changed = wazuh.sync_wazuh_config_files(container)

    assert changed is True
    assert (
        container.pull(INTERNAL_OPTIONS_CONF_PATH, encoding="utf-8").read()
        == custom_internal_options_conf
    )


def test_skips_missing_permission_fixup_paths(monkeypatch, synced_wazuh_container):
    """
    arrange: the custom repository does not provide var/ossec/integrations or
        var/ossec/etc/shared/default, so those paths do not exist after the rsync passes.
    act: resync the wazuh config files.
    assert: the sync completes successfully without attempting find/chmod against the
        missing paths.
    """
    container, save_applied_commit_marker_mock = synced_wazuh_container
    commands = track_exec(monkeypatch, container, "rsync", "chmod", "chown", "find")
    fake_missing_paths(
        monkeypatch,
        container,
        wazuh.WAZUH_INTEGRATIONS_PATH,
        wazuh.WAZUH_SHARED_DEFAULT_GROUP_PATH,
    )

    changed = wazuh.sync_wazuh_config_files(container)

    assert changed is True
    save_applied_commit_marker_mock.assert_called_once_with(ANY, wazuh.WAZUH_APPLIED_COMMIT_PATH)
    assert not any(cmd[0] == "find" for cmd in commands)
    assert not any(cmd[0] == "chmod" for cmd in commands)
