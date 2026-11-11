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

from .conftest import fake_missing_paths, track_exec


def test_only_excludes_internal_options_conf_in_destructive_pass(
    monkeypatch, synced_wazuh_container
):
    """
    arrange: a container with a pending config sync from its custom repository.
    act: resync the wazuh config files.
    assert: internal_options.conf is excluded from the destructive (--delete) rsync pass
        before the include patterns that would otherwise match it, but is NOT excluded
        from the non-destructive pass, so a custom repository can still patch it.
    """
    container, save_applied_commit_marker_mock = synced_wazuh_container
    commands = track_exec(monkeypatch, container, "rsync", "chmod", "chown", "find")

    changed = wazuh.sync_wazuh_config_files(container)

    assert changed is True
    save_applied_commit_marker_mock.assert_called_once_with(ANY, wazuh.WAZUH_APPLIED_COMMIT_PATH)

    rsync_commands = [cmd for cmd in commands if cmd[0] == "rsync"]
    assert rsync_commands
    destructive_commands = [cmd for cmd in rsync_commands if "--delete" in cmd]
    non_destructive_commands = [cmd for cmd in rsync_commands if "--delete" not in cmd]
    assert destructive_commands
    assert non_destructive_commands

    for command in destructive_commands:
        exclude_index = command.index("--exclude=etc/internal_options.conf")
        for include in ("--include=etc/*.conf", "--include=etc/***"):
            if include in command:
                assert exclude_index < command.index(include)

    for command in non_destructive_commands:
        # the non-destructive pass can never delete the stock file, so it must keep
        # internal_options.conf in scope in order to still sync a repository-provided one
        assert "--exclude=etc/internal_options.conf" not in command
        assert "--include=etc/***" in command


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
