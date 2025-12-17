"""Helper class for Wazuh Prometheus exporter."""

# based on https://github.com/pyToshka/wazuh-prometheus-exporter

import http.client
import json
import logging
import os
from base64 import b64encode

import json_logging
import requests
import urllib3

log_level = os.environ.get("EXPORTER_LOG_LEVEL", "INFO")
if log_level == "DEBUG":
    http.client.HTTPConnection.debuglevel = 1


def get_logger():
    """Utility function to get logger object.

    Returns:
        logging.Logger
    """
    json_logging.init_non_web(enable_json=True)
    logger = logging.getLogger("wazuh-exporter")
    logging.basicConfig()
    json_logging.config_root_logger()
    logger.setLevel(log_level)
    logging.addLevelName(logging.ERROR, "error")
    logging.addLevelName(logging.CRITICAL, "critical")
    logging.addLevelName(logging.WARNING, "warning")
    logging.addLevelName(logging.INFO, "info")
    logging.addLevelName(logging.DEBUG, "debug")
    logger.addHandler(logging.NullHandler())
    return logger


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = get_logger()


class Wazuh:
    def __init__(self, protocol, host, port, login_endpoint, user, password):
        self.protocol = protocol
        self.host = host
        self.port = port
        self.login_endpoint = login_endpoint
        self.user = user
        self.password = password
        self.url = f"{self.protocol}://{self.host}:{self.port}"

    def login(self):
        login_url = f"{self.url}/{self.login_endpoint}"
        basic_auth = f"{self.user}:{self.password}".encode()
        login_headers = {
            "Content-Type": "application/json",
            "Authorization": f"Basic {b64encode(basic_auth).decode()}",
        }
        response = requests.get(login_url, headers=login_headers, verify=False)  # nosec
        token = json.loads(response.content.decode())["data"]["token"]
        requests_headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        }
        return requests_headers

    def make_request(self, path, headers, affected_items=False):
        response = requests.get(self.url + path, headers=headers, verify=False)
        if response.status_code != 200:
            logger.warning(
                f"Got response http code {response.status_code}, response body: {response.content}"
            )
        try:
            data = response.json()
        except requests.JSONDecodeError:
            logger.error("Got JSON decode error for %s, response body: %s", path, response.content)
            return

        if not isinstance(data, dict):
            return {}

        if affected_items:
            return data.get("data", {}).get("affected_items", {})
        return data.get("data", {})

    def wazuh_api_info(self, headers):
        return self.make_request("/", headers)

    def wazuh_get_daemons_stat(self, headers):
        return self.make_request("/manager/status", headers, affected_items=True)

    def wazuh_get_base_info(self, headers):
        return self.make_request("/manager/info", headers, affected_items=True)

    def wazuh_get_configuration(self, headers):
        return self.make_request("/manager/configuration", headers, affected_items=True)

    def wazuh_validate_configuration(self, headers):
        return self.make_request("/manager/configuration/validation", headers, affected_items=True)

    def wazuh_get_stats(self, headers):
        return self.make_request("/manager/stats?pretty=true", headers, affected_items=True)

    def wazuh_get_hourly_stats(self, headers):
        # TODO: determine if this outlier is correct or a mistake
        return self.make_request("/manager/stats/hourly", headers)

    def wazuh_get_weekly_stats(self, headers):
        return self.make_request("/manager/stats/weekly", headers, affected_items=True)

    def wazuh_get_analysisd_stats(self, headers):
        return self.make_request("/manager/stats/analysisd", headers, affected_items=True)

    def wazuh_get_remote_stats(self, headers):
        return self.make_request("/manager/stats/remoted", headers, affected_items=True)

    def wazuh_get_logs(self, headers):
        return self.make_request("/manager/logs", headers, affected_items=True)

    def wazuh_get_logs_summary(self, headers):
        return self.make_request("/manager/logs/summary", headers, affected_items=True)

    def wazuh_get_agent_connection(self, headers):
        return self.make_request(
            "/agents?pretty&offset=0&sort=status", headers, affected_items=True
        )

    def wazuh_get_agents_overview(self, headers):
        # TODO: determine if this outlier is correct or a mistake
        return self.make_request("/overview/agents", headers)

    def wazuh_get_nodes_healtchecks(self, headers):
        return self.make_request("/cluster/healthcheck", headers, affected_items=True)

    def wazuh_get_last_scan_syscheck(self, headers, agent_id):
        return self.make_request(f"/syscheck/{agent_id}", headers, affected_items=True)
