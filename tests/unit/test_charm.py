# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

# pylint detects the patches states as duplicate code
# pylint: disable=duplicate-code,too-many-locals

"""Charm unit tests."""

import secrets
from unittest.mock import ANY, MagicMock, call, patch

import ops
import pytest
from ops.testing import Harness
from pydantic import AnyUrl

import wazuh
from certificates_observer import CertificatesObserver
from charm import WAZUH_PEER_RELATION_NAME, WazuhServerCharm
from state import (
    WAZUH_API_CREDENTIAL_SECRET_LABEL,
    WAZUH_USERS,
    IncompleteStateError,
    InvalidStateError,
    RecoverableStateError,
    State,
    WazuhConfig,
)


@patch.object(WazuhServerCharm, "units_fqdns")
@patch.object(CertificatesObserver, "get_csr")
@patch.object(State, "from_charm")
def test_invalid_state_reaches_error_status(state_from_charm_mock, *_):
    """
    arrange: mock State.from_charm so that it raises an InvalidStateError.
    act: instantiate a charm.
    assert: the charm reaches error status when the state is fetched.
    """
    state_from_charm_mock.side_effect = InvalidStateError()

    harness = Harness(WazuhServerCharm)
    harness.begin()

    with pytest.raises(InvalidStateError):
        harness.charm.state  # noqa: B018


@patch.object(WazuhServerCharm, "units_fqdns")
@patch.object(CertificatesObserver, "get_csr")
@patch.object(State, "from_charm")
def test_invalid_state_reaches_blocked_status(state_from_charm_mock, *_):
    """
    arrange: mock State.from_charm so that it raises a RecoverableStateError.
    act: instantiate a charm and call reconcile.
    assert: the charm reaches blocked status.
    """
    state_from_charm_mock.side_effect = RecoverableStateError()

    harness = Harness(WazuhServerCharm)
    harness.begin()
    container = harness.model.unit.containers.get("wazuh-server")
    assert container
    harness.set_can_connect(container, True)
    harness.charm.reconcile(None)
    assert harness.model.unit.status.name == ops.BlockedStatus().name


@patch.object(WazuhServerCharm, "units_fqdns")
@patch.object(CertificatesObserver, "get_csr")
@patch.object(State, "from_charm")
def test_incomplete_state_reaches_waiting_status(state_from_charm_mock, *_):
    """
    arrange: mock State.from_charm so that it raises an IncompleteStateError.
    act: instantiate a charm and call reconcile.
    assert: the charm reaches waiting status.
    """
    state_from_charm_mock.side_effect = IncompleteStateError()

    harness = Harness(WazuhServerCharm)
    harness.begin()
    container = harness.model.unit.containers.get("wazuh-server")
    assert container
    harness.set_can_connect(container, True)
    harness.charm.reconcile(None)

    assert harness.model.unit.status.name == ops.WaitingStatus().name


@patch.object(WazuhServerCharm, "units_fqdns")
@patch.object(wazuh, "sync_config_repo")
@patch.object(WazuhServerCharm, "_reconcile_filebeat")
@patch.object(WazuhServerCharm, "_reconcile_wazuh")
@patch.object(CertificatesObserver, "get_csr")
@patch.object(State, "from_charm")
def test_no_logs_ca_cert_reaches_blocked_status(state_from_charm_mock, *_):
    """
    arrange: mock State.from_charm so that it raises an IncompleteStateError.
    act: instantiate a charm and call reconcile.
    assert: the charm reaches waiting status.
    """
    mock_state = MagicMock()
    mock_state.logs_ca_cert = None
    state_from_charm_mock.return_value = mock_state
    harness = Harness(WazuhServerCharm)
    harness.begin()
    container = harness.model.unit.containers.get("wazuh-server")
    assert container
    harness.set_can_connect(container, True)
    harness.charm.reconcile(None)

    assert harness.model.unit.status.name == ops.BlockedStatus().name
    assert (
        harness.model.unit.status.message
        == "Invalid charm configuration: 'logs-ca-cert' is missing."
    )


# pylint: disable=too-many-arguments, too-many-locals, too-many-positional-arguments
@patch.object(wazuh, "sync_filebeat_config")
@patch.object(wazuh, "sync_wazuh_config_files")
@patch.object(wazuh, "create_api_user")
@patch.object(wazuh, "authenticate_user")
@patch.object(wazuh, "change_api_password")
@patch.object(State, "from_charm")
@patch.object(wazuh, "sync_config_repo", spec=wazuh.sync_config_repo)
@patch.object(wazuh, "sync_ossec_conf")
@patch.object(wazuh, "sync_agent_password")
@patch.object(wazuh, "sync_certificates")
@patch.object(wazuh, "sync_filebeat_user")
@patch.object(wazuh, "ensure_log_ingestion_dir")
@patch.object(wazuh, "get_version")
@patch.object(CertificatesObserver, "get_csr")
def test_reconcile_reaches_active_status_when_repository_and_password_configured(
    filebeat_csr_mock,
    get_version_mock,
    ensure_log_ingestion_dir_mock,
    sync_filebeat_user_mock,
    wazuh_sync_certificates_mock,
    wazuh_sync_agent_password_mock,
    wazuh_sync_ossec_conf_mock,
    sync_config_repo_mock,
    state_from_charm_mock,
    *_,
):
    """
    arrange: mock system calls and charm state.
    act: call reconcile.
    assert: the charm reaches active status and configs are applied.
    """
    custom_config_repository = "git+ssh://user1@git.server/repo_name@main"
    secret_id = f"secret:{secrets.token_hex(21)}"
    api_credentials = {
        "wazuh": secrets.token_hex(),
        "wazuh-wui": secrets.token_hex(),
        "prometheus": secrets.token_hex(),
    }
    wazuh_config = WazuhConfig(
        custom_config_repository=AnyUrl(custom_config_repository),
        custom_config_ssh_key=secret_id,
        logs_ca_cert="logs_ca",
    )
    password = secrets.token_hex()
    agent_password = secrets.token_hex()
    cluster_key = secrets.token_hex(16)
    opencti_token = secrets.token_hex(16)
    opencti_url = "https://opencti.example.com"
    state_from_charm_mock.return_value = State(
        agent_password=agent_password,
        api_credentials=api_credentials,
        rsyslog_public_cert="certificate",
        cluster_key=cluster_key,
        indexer_endpoints=["10.0.0.1"],
        filebeat_username="user1",
        filebeat_password=password,
        filebeat_ca="filebeat_ca",
        wazuh_config=wazuh_config,
        custom_config_ssh_key="somekey",
        opencti_token=opencti_token,
        opencti_url=opencti_url,
    )
    get_version_mock.return_value = "v4.14.7"
    filebeat_csr_mock.return_value = b""
    harness = Harness(WazuhServerCharm)
    harness.begin()
    harness.add_relation(WAZUH_PEER_RELATION_NAME, harness.charm.app.name)
    container = harness.model.unit.containers.get("wazuh-server")
    assert container
    harness.set_can_connect(container, True)

    harness.charm.reconcile(None)

    wazuh_sync_certificates_mock.assert_has_calls(
        [
            call(
                container=container,
                path=wazuh.FILEBEAT_CERTIFICATES_PATH,
                root_ca="filebeat_ca",
                user="root",
                group="root",
            ),
            call(
                container=container,
                path=wazuh.RSYSLOG_CERTIFICATES_PATH,
                private_key=ANY,
                public_key="certificate",
                root_ca="logs_ca",
                user="syslog",
                group="syslog",
            ),
        ],
        any_order=True,
    )
    wazuh_sync_ossec_conf_mock.assert_called_with(
        container,
        ["10.0.0.1"],
        "wazuh-server-0.wazuh-server-endpoints",
        "wazuh-server/0",
        cluster_key,
        opencti_url=opencti_url,
        opencti_token=opencti_token,
        enable_vulnerability_detection=True,
    )
    sync_filebeat_user_mock.assert_called_with(container, "user1", password)
    ensure_log_ingestion_dir_mock.assert_called_with(container)
    wazuh_sync_agent_password_mock.assert_called_with(container=container, password=agent_password)
    sync_config_repo_mock.assert_called_with(
        container, wazuh_config.custom_config_repository, "somekey"
    )
    get_version_mock.assert_called_with(container)
    assert harness.model.unit.status.name == ops.ActiveStatus().name


# pylint: disable=too-many-arguments, too-many-positional-arguments
@patch.object(wazuh, "sync_filebeat_config")
@patch.object(wazuh, "create_api_user")
@patch.object(wazuh, "authenticate_user")
@patch.object(wazuh, "change_api_password")
@patch.object(State, "from_charm")
@patch.object(wazuh, "pull_config_repo")
@patch.object(wazuh, "sync_wazuh_config_files")
@patch.object(wazuh, "sync_ossec_conf")
@patch.object(wazuh, "sync_agent_password")
@patch.object(wazuh, "sync_certificates")
@patch.object(wazuh, "sync_filebeat_user")
@patch.object(wazuh, "ensure_log_ingestion_dir")
@patch.object(wazuh, "get_version")
@patch.object(CertificatesObserver, "get_csr")
def test_reconcile_reaches_active_status_when_repository_and_password_not_configured(
    filebeat_csr_mock,
    get_version_mock,
    ensure_log_ingestion_dir_mock,
    sync_filebeat_user_mock,
    wazuh_sync_certificates_mock,
    wazuh_sync_agent_password_mock,
    wazuh_sync_ossec_conf_mock,
    sync_wazuh_config_files_mock,
    pull_config_repo_mock,
    state_from_charm_mock,
    *_,
):
    """
    arrange: mock system calls and charm state.
    act: call reconcile.
    assert: the charm reaches active status and configs are applied.
    """
    password = secrets.token_hex()
    api_credentials = {
        "wazuh": secrets.token_hex(),
        "wazuh-wui": secrets.token_hex(),
        "prometheus": secrets.token_hex(),
    }
    cluster_key = secrets.token_hex(16)
    state_from_charm_mock.return_value = State(
        agent_password=None,
        api_credentials=api_credentials,
        rsyslog_public_cert="certificate",
        cluster_key=cluster_key,
        indexer_endpoints=["10.0.0.1"],
        filebeat_username="user1",
        filebeat_password=password,
        filebeat_ca="filebeat_ca",
        wazuh_config=WazuhConfig(
            custom_config_repository=None,
            custom_config_ssh_key=None,
            logs_ca_cert="logs_ca",
        ),
        custom_config_ssh_key=None,
    )
    get_version_mock.return_value = "v4.14.7"
    filebeat_csr_mock.return_value = b""
    harness = Harness(WazuhServerCharm)
    harness.begin()
    harness.add_relation(WAZUH_PEER_RELATION_NAME, harness.charm.app.name)
    container = harness.model.unit.containers.get("wazuh-server")
    assert container
    harness.set_can_connect(container, True)

    harness.charm.reconcile(None)

    wazuh_sync_certificates_mock.assert_has_calls(
        [
            call(
                container=container,
                path=wazuh.FILEBEAT_CERTIFICATES_PATH,
                root_ca="filebeat_ca",
                user="root",
                group="root",
            ),
            call(
                container=container,
                path=wazuh.RSYSLOG_CERTIFICATES_PATH,
                private_key=ANY,
                public_key="certificate",
                root_ca="logs_ca",
                user="syslog",
                group="syslog",
            ),
        ],
        any_order=True,
    )
    sync_filebeat_user_mock.assert_called_with(container, "user1", password)
    ensure_log_ingestion_dir_mock.assert_called_with(container)
    wazuh_sync_agent_password_mock.assert_not_called()
    pull_config_repo_mock.assert_not_called()
    sync_wazuh_config_files_mock.assert_not_called()
    wazuh_sync_ossec_conf_mock.assert_called_with(
        container,
        ["10.0.0.1"],
        "wazuh-server-0.wazuh-server-endpoints",
        "wazuh-server/0",
        cluster_key,
        opencti_token=None,
        opencti_url=None,
        enable_vulnerability_detection=True,
    )
    get_version_mock.assert_called_with(container)
    assert harness.model.unit.status.name == ops.ActiveStatus().name


@patch.object(CertificatesObserver, "get_csr")
@patch.object(wazuh, "generate_api_password")
@patch.object(wazuh, "change_api_password")
@patch.object(wazuh, "authenticate_user")
@patch.object(State, "from_charm")
def test_reconcile_users_does_not_rotate_valid_credentials(
    state_from_charm_mock,
    authenticate_user_mock,
    change_api_password_mock,
    generate_api_password_mock,
    _get_csr_mock,
):
    """
    arrange: API credentials from the secret are valid.
    act: reconcile the API users.
    assert: credentials are not rotated and the secret is not updated.
    """
    credentials = {
        "wazuh": secrets.token_hex(),
        "wazuh-wui": secrets.token_hex(),
        "prometheus": secrets.token_hex(),
    }
    state_from_charm_mock.return_value = MagicMock(api_credentials=credentials)
    harness = Harness(WazuhServerCharm)
    harness.begin()
    harness.set_leader(True)
    secret = harness.charm.app.add_secret(credentials, label=WAZUH_API_CREDENTIAL_SECRET_LABEL)
    revision = secret.get_info().revision
    authenticate_user_mock.return_value = "token"

    harness.charm._reconcile_users()

    assert authenticate_user_mock.call_count == len(credentials)
    change_api_password_mock.assert_not_called()
    generate_api_password_mock.assert_not_called()
    secret = harness.charm.model.get_secret(label=WAZUH_API_CREDENTIAL_SECRET_LABEL)
    assert dict(secret.get_content(refresh=True)) == credentials
    assert secret.get_info().revision == revision


@patch.object(CertificatesObserver, "get_csr")
@patch("charm.time.sleep")
@patch.object(wazuh, "generate_api_password")
@patch.object(wazuh, "create_api_user")
@patch.object(wazuh, "change_api_password")
@patch.object(wazuh, "authenticate_user")
@patch.object(State, "from_charm")
def test_reconcile_users_reapplies_stored_credentials_after_restart(
    state_from_charm_mock,
    authenticate_user_mock,
    change_api_password_mock,
    create_api_user_mock,
    generate_api_password_mock,
    _sleep_mock,
    _get_csr_mock,
):
    """
    arrange: the API user database has been reset to its defaults after a restart.
    act: reconcile the API users.
    assert: the passwords stored in the secret are reapplied without rotation.
    """
    credentials = {
        "wazuh": secrets.token_hex(),
        "wazuh-wui": secrets.token_hex(),
        "prometheus": secrets.token_hex(),
    }
    valid_passwords = {
        username: details["default_password"] for username, details in WAZUH_USERS.items()
    }

    def authenticate(username, password):
        if password and valid_passwords[username] == password:
            return f"token-{username}"
        raise wazuh.WazuhAuthenticationError

    def set_password(username, password, _token):
        valid_passwords[username] = password

    authenticate_user_mock.side_effect = authenticate
    change_api_password_mock.side_effect = set_password
    create_api_user_mock.side_effect = set_password

    state_from_charm_mock.return_value = MagicMock(api_credentials=credentials)
    harness = Harness(WazuhServerCharm)
    harness.begin()
    harness.set_leader(True)
    secret = harness.charm.app.add_secret(credentials, label=WAZUH_API_CREDENTIAL_SECRET_LABEL)
    revision = secret.get_info().revision

    harness.charm._reconcile_users()

    generate_api_password_mock.assert_not_called()
    change_api_password_mock.assert_has_calls(
        [
            call("wazuh", credentials["wazuh"], "token-wazuh"),
            call("wazuh-wui", credentials["wazuh-wui"], "token-wazuh-wui"),
            call("prometheus", credentials["prometheus"], "token-wazuh"),
        ]
    )
    create_api_user_mock.assert_called_once_with(
        "prometheus", credentials["prometheus"], "token-wazuh"
    )
    secret = harness.charm.model.get_secret(label=WAZUH_API_CREDENTIAL_SECRET_LABEL)
    assert dict(secret.get_content(refresh=True)) == credentials
    assert secret.get_info().revision == revision


@patch.object(CertificatesObserver, "get_csr")
@patch("charm.time.sleep")
@patch.object(wazuh, "generate_api_password")
@patch.object(wazuh, "create_api_user")
@patch.object(wazuh, "change_api_password")
@patch.object(wazuh, "authenticate_user")
@patch.object(State, "from_charm")
def test_reconcile_users_does_not_rotate_when_authentication_fails(
    state_from_charm_mock,
    authenticate_user_mock,
    change_api_password_mock,
    create_api_user_mock,
    generate_api_password_mock,
    _sleep_mock,
    _get_csr_mock,
):
    """
    arrange: the API rejects both the stored and the default passwords.
    act: reconcile the API users.
    assert: WazuhNotReadyError is raised and credentials are not rotated.
    """
    credentials = {
        "wazuh": secrets.token_hex(),
        "wazuh-wui": secrets.token_hex(),
        "prometheus": secrets.token_hex(),
    }
    state_from_charm_mock.return_value = MagicMock(api_credentials=credentials)
    authenticate_user_mock.side_effect = wazuh.WazuhAuthenticationError
    harness = Harness(WazuhServerCharm)
    harness.begin()
    harness.set_leader(True)
    harness.charm.app.add_secret(credentials, label=WAZUH_API_CREDENTIAL_SECRET_LABEL)

    with pytest.raises(wazuh.WazuhNotReadyError):
        harness.charm._reconcile_users()

    change_api_password_mock.assert_not_called()
    create_api_user_mock.assert_not_called()
    generate_api_password_mock.assert_not_called()


@patch.object(CertificatesObserver, "get_csr")
@patch.object(wazuh, "generate_api_password")
@patch.object(wazuh, "create_api_user")
@patch.object(wazuh, "change_api_password")
@patch.object(wazuh, "authenticate_user")
@patch.object(State, "from_charm")
def test_reconcile_users_generates_credentials_when_secret_is_missing(
    state_from_charm_mock,
    authenticate_user_mock,
    change_api_password_mock,
    create_api_user_mock,
    generate_api_password_mock,
    _get_csr_mock,
):
    """
    arrange: no API credentials secret exists yet.
    act: reconcile the API users.
    assert: new credentials are generated, applied and stored in a secret.
    """
    credentials = {
        username: details["default_password"] for username, details in WAZUH_USERS.items()
    }
    generated_passwords = [secrets.token_hex() for _ in WAZUH_USERS]
    state_from_charm_mock.return_value = MagicMock(api_credentials=credentials)
    authenticate_user_mock.return_value = "token"
    generate_api_password_mock.side_effect = generated_passwords
    harness = Harness(WazuhServerCharm)
    harness.begin()
    harness.set_leader(True)

    harness.charm._reconcile_users()

    assert generate_api_password_mock.call_count == len(WAZUH_USERS)
    change_api_password_mock.assert_has_calls(
        [
            call("wazuh", generated_passwords[0], "token"),
            call("wazuh-wui", generated_passwords[1], "token"),
        ]
    )
    create_api_user_mock.assert_called_once_with("prometheus", generated_passwords[2], "token")
    secret = harness.charm.model.get_secret(label=WAZUH_API_CREDENTIAL_SECRET_LABEL)
    assert dict(secret.get_content(refresh=True)) == {
        "wazuh": generated_passwords[0],
        "wazuh-wui": generated_passwords[1],
        "prometheus": generated_passwords[2],
    }


def test_reconcile_reaches_waiting_status_when_cant_connect():
    """
    arrange: do nothing.
    act: call reconcile.
    assert: the charm reaches waiting status.
    """
    harness = Harness(WazuhServerCharm)
    harness.begin()
    container = harness.model.unit.containers.get("wazuh-server")
    assert container
    harness.set_can_connect(container, False)

    harness.charm.reconcile(None)

    assert harness.model.unit.status.name == ops.WaitingStatus().name


@patch.object(State, "from_charm")
@patch.object(CertificatesObserver, "get_csr")
def test_reconcile_reaches_error_status_when_no_state(state_from_charm_mock, *_):
    """
    arrange: mock the state to raise an exception.
    act: call reconcile.
    assert: the charm reaches error status.
    """
    state_from_charm_mock.side_effect = InvalidStateError()
    harness = Harness(WazuhServerCharm)
    harness.begin()
    container = harness.model.unit.containers.get("wazuh-server")
    assert container
    harness.set_can_connect(container, True)

    with pytest.raises(InvalidStateError):
        harness.charm.reconcile(None)
