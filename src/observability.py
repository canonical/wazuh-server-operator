# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Provide the Observability class to represent the observability stack for Wazuh."""


import ops
from charms.grafana_k8s.v0.grafana_dashboard import GrafanaDashboardProvider
from charms.loki_k8s.v1.loki_push_api import LogProxyConsumer
from charms.prometheus_k8s.v0.prometheus_scrape import MetricsEndpointProvider

import wazuh

LOG_PATHS = [
    (wazuh.WAZUH_SERVICE_LOG_DIR / "*.log").absolute().as_posix(),
    (wazuh.FILEBEAT_SERVICE_LOG_PATH / "filebeat").absolute().as_posix(),
    (wazuh.RSYSLOG_SERVICE_LOG_PATH).absolute().as_posix(),
]
PROMETHEUS_PORT = 5000


class Observability:  # pylint: disable=too-few-public-methods
    """A class representing the observability stack for Wazuh application."""

    def __init__(self, charm: ops.CharmBase):
        """Initialize a new instance of the Observability class.

        Args:
            charm: The charm object that the Observability instance belongs to.
        """
        self._grafana_dashboards = GrafanaDashboardProvider(
            charm, relation_name="grafana-dashboard"
        )
        prometheus_target = [f"*:{PROMETHEUS_PORT}"]
        self._metrics_endpoint = MetricsEndpointProvider(
            charm,
            relation_name="metrics-endpoint",
            jobs=[
                {
                    "job_name": "stats_exporter",
                    "static_configs": [{"targets": prometheus_target}],
                },
            ],
        )
        self._logging = LogProxyConsumer(
            charm,
            relation_name="logging",
            logs_scheme={
                f"{wazuh.CONTAINER_NAME}": {
                    "log-files": LOG_PATHS,
                },
            },
        )
