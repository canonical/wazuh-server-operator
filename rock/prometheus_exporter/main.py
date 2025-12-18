#!/usr/bin/env python3

# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Prometheus exporter for Wazuh.

forked from https://github.com/pyToshka/wazuh-prometheus-exporter
"""

import logging
import os
import sys
import time
from typing import Iterable

import wazuh_metrics_collector as wmc
from packaging.version import Version
from prometheus_client import REGISTRY, Metric, start_http_server
from prometheus_client.metrics_core import GaugeMetricFamily, InfoMetricFamily
from prometheus_client.registry import Collector

logger = wmc.get_logger()

host = ""
port = ""
user = ""
password = ""
protocol = os.getenv("WAZUH_PROTOCOL", "https")
try:
    host = os.getenv("WAZUH_API_HOST")
    port = int(os.getenv("WAZUH_API_PORT"))
    user = os.getenv("WAZUH_API_USERNAME")
    password = os.getenv("WAZUH_API_PASSWORD")
    listen_port = os.getenv("EXPORTER_PORT", default="5000")
    if not host or not port or not user or not password:
        logger.critical(
            f"System variables are not set, please check:"
            f" Wazuh host {host}, Wazuh port {port}, Wazuh api user {user},"
            f" Wazuh api password {password}"
        )
        raise KeyError
except KeyError:
    logger.critical(
        "Please check system variables:"
        f" Wazuh host {host}, Wazuh port {port}, Wazuh api user {user},"
        f" Wazuh api password {password}"
    )
    sys.exit(2)

login_endpoint = "security/user/authenticate"


class WazuhCollector(Collector):
    def __init__(self):
        logger.info("Start collector")
        self.connection = wmc.Wazuh(
            protocol=protocol,
            host=host,
            port=port,
            login_endpoint=login_endpoint,
            user=user,
            password=password,
        )

    def collect(self):  # noqa: C901
        auth = self.connection.login()
        if not auth:
            logger.warning("Could not authenticate, sleeping 10s and returning")
            time.sleep(10)
            return

        agents = self.connection.wazuh_get_agents_overview(auth)
        mgr_stats_hourly = self.connection.wazuh_get_hourly_stats(auth)
        manager_stats = self.connection.wazuh_get_stats(auth)
        remote_stats = self.connection.wazuh_get_remote_stats(auth)
        get_logs = self.connection.wazuh_get_logs(auth)
        analysisd_stats = self.connection.wazuh_get_analysisd_stats(auth)
        validate_config = self.connection.wazuh_validate_configuration(auth)

        if not isinstance(agents, dict):
            logger.warning("'agents' object is not a dict, values will be null")
            agents = {}

        metric = Metric("wazuh_total_agent", "Total Wazuh agents count", "summary")
        for agent in agents.get("nodes", ()):
            metric.add_sample(
                "wazuh_agents_count",
                value=agent.get("count", 0),
                labels={"node_name": agent.get("node_name", "")},
            )
        yield metric

        metric = Metric("wazuh_total_group", "Total Wazuh groups count", "summary")
        for group in agents.get("groups", ()):
            group = group if isinstance(group, dict) else {}
            metric.add_sample(
                "wazuh_agents_group",
                value=group.get("count", 0),
                labels={"group_name": group.get("name", "")},
            )
        yield metric

        metric = Metric("wazuh_agent_status", "Total Wazuh agents by status", "summary")
        if "connection" in agents.get("agent_status", ()):
            # Wazuh >= v4.4
            agents_path = agents["agent_status"]["connection"]
        else:
            # Legacy Wazuh support (< v4.4)
            agents_path = agents.get("agent_status", {})
        metric.add_sample("wazuh_active_agents", value=agents_path.get("active", 0), labels={})
        metric.add_sample(
            "wazuh_disconnected_agents",
            value=agents_path.get("disconnected", 0),
            labels={},
        )
        metric.add_sample(
            "wazuh_never_connected_agents",
            value=agents_path.get("never_connected", 0),
            labels={},
        )
        metric.add_sample("wazuh_pending_agents", value=agents_path.get("pending", 0), labels={})
        metric.add_sample("wazuh_total_agents", value=agents_path.get("total", 0), labels={})
        yield metric

        metric = GaugeMetricFamily(
            "wazuh_agent_version", "Wazuh agent versions", labels=["version"]
        )
        for version in agents.get("agent_version", ()):
            metric.add_metric(
                labels=[version.get("version", "")],
                value=version.get("count", 0),
            )
        yield metric

        if not os.getenv("SKIP_LAST_REGISTERED_AGENT"):
            metric = InfoMetricFamily("last_registered_agent", "Wazuh last registered agent")
            for version in agents.get("last_registered_agent", ()):
                if version.get("status") == "never_connected":
                    logging.warning(
                        f"Last Wazuh agent with name {version.get("name")}"
                        f" has status {version.get("status")},"
                        f" last_registered_agent metric has been skipped please check agent."
                        f" Full agent trace {version}"
                    )
                else:
                    for value_key, value in version.get("os", {}).items():
                        node_name = version.get("node_name", "")
                        node_value = f"{node_name}-{value_key}"
                        prom_node_name_format = node_name.replace("-", "_")
                        prom_node_value_format = node_value.replace("-", "_")
                        metric.add_metric(
                            labels=prom_node_name_format,
                            value={prom_node_value_format: f"{value}"},
                        )
            yield metric

        mgr_stats_hourly = mgr_stats_hourly if isinstance(mgr_stats_hourly, dict) else {}
        metric = InfoMetricFamily(
            "manager_stats_hourly",
            "Wazuh statistical information per hour. "
            "Each number in the averages field represents the average of alerts per hour",
        )
        metric.add_sample(
            "total_affected_items",
            value=mgr_stats_hourly.get("total_affected_items", 0),
            labels={},
        )
        metric.add_sample(
            "total_failed_items",
            value=mgr_stats_hourly.get("total_failed_items", 0),
            labels={},
        )
        yield metric
        metric = InfoMetricFamily(
            "nodes_healthcheck", "Wazuh nodes healthcheck", labels=["node_name"]
        )
        nodes = self.connection.wazuh_get_nodes_healtchecks(auth)
        if nodes is not None:
            for node in nodes:
                infos = {
                    k: str(v)
                    for (k, v) in node.get("info", ()).items()
                    if k != "name" and k != "n_active_agents"
                }
                metric.add_metric(labels=[node.get("info", {}).get("name", "")], value=infos)
            yield metric

        info = self.connection.wazuh_api_info(auth)
        info = info if isinstance(info, dict) else {}
        if not os.getenv("SKIP_WAZUH_API_INFO"):
            metric = InfoMetricFamily("wazuh_api", "Wazuh API information")
            for value_key, value in info.items():
                metric.add_metric(labels="wazuh_api_version", value={str(value_key): str(value)})
            yield metric

        manager_stats = manager_stats if isinstance(manager_stats, Iterable) else ()
        metric = Metric(
            "manager_stats_total",
            "Wazuh statistical information for the current date",
            "summary",
        )
        for stats in manager_stats:
            samples = (
                ("alerts", "totalAlerts"),
                ("syscheck", "syscheck"),
                ("firewall", "firewall"),
                ("events", "events"),
            )
            for name, value_key in samples:
                metric.add_sample(
                    f'total_{name}_hour_{stats.get("hour", "")}',
                    value=stats.get(value_key, 0),
                    labels={},
                )
        yield metric

        remote_stats = remote_stats if isinstance(remote_stats, Iterable) else ()
        metric = Metric("manager_stats_remote", "Wazuh remoted statistical information", "summary")
        for remote_state in remote_stats:
            samples = (
                "queue_size",
                "total_queue_size",
                "tcp_sessions",
                "evt_count",
                "ctrl_msg_count",
                "discarded_count",
                "recv_bytes",
                "dequeued_after_close",
            )
            for sample in samples:
                metric.add_sample(
                    sample,
                    value=remote_state.get(sample, 0),
                    labels={"manager_stats_remote": sample},
                )
            if Version(info.get("api_version", "")) < Version("4.7.0"):
                metric.add_sample(
                    "queued_msgs",
                    value=remote_state["queued_msgs"],
                    labels={"manager_stats_remote": "queued_msgs"},
                )
        yield metric

        if not os.getenv("SKIP_LAST_LOGS", default=""):
            metric = InfoMetricFamily("last_logs", "The last 2000 wazuh log entries")
            get_logs = get_logs if isinstance(get_logs, Iterable) else ()
            for log in get_logs:
                key = "_".join(
                    (log.get("tag", "").replace("-", "_").replace(":", "_"), log.get("level", ""))
                )
                metric.add_metric(
                    labels=f'wazuh_last_logs_{log["tag"]}',
                    value={key: f'{log.get("description", "").strip()}'},
                )
            yield metric

        metric = Metric("analysisd_stats", "Wazuh analysisd statistical information", "summary")
        analysisd_stats = analysisd_stats if isinstance(analysisd_stats, Iterable) else ()
        for analysisd_stat in analysisd_stats:
            if Version(info.get("api_version", "")) < Version("4.7.0"):
                samples = (
                    "syscheck_edps",
                    "syscollector_edps",
                    "rootcheck_edps",
                    "sca_edps",
                    "hostinfo_events_decoded",
                    "hostinfo_edps",
                    "winevt_edps",
                    "dbsync_mdps",
                    "other_events_edps",
                    "events_edps",
                )
                for sample in samples:
                    metric.add_sample(
                        "analysisd_stats",
                        value=analysisd_stat[sample],
                        labels={"analysisd_stats": sample},
                    )
            samples = (
                "total_events_decoded",
                "syscheck_events_decoded",
                "syscollector_events_decoded",
                "rootcheck_events_decoded",
                "sca_events_decoded",
                "winevt_events_decoded",
                "dbsync_messages_dispatched",
                "other_events_decoded",
                "events_processed",
                "events_received",
                "events_dropped",
                "alerts_written",
                "firewall_written",
                "fts_written",
                "syscheck_queue_usage",
                "syscheck_queue_size",
                "syscollector_queue_usage",
                "syscollector_queue_size",
                "rootcheck_queue_usage",
                "rootcheck_queue_size",
                "sca_queue_usage",
                "sca_queue_size",
                "sca_queue_size",
                "hostinfo_queue_usage",
                "hostinfo_queue_size",
                "winevt_queue_usage",
                "dbsync_queue_usage",
                "dbsync_queue_size",
                "upgrade_queue_usage",
                "upgrade_queue_size",
                "event_queue_usage",
                "event_queue_size",
                "rule_matching_queue_usage",
                "rule_matching_queue_size",
                "alerts_queue_usage",
                "alerts_queue_size",
                "firewall_queue_usage",
                "statistical_queue_usage",
                "statistical_queue_size",
                "archives_queue_usage",
                "archives_queue_size",
            )
            for sample in samples:
                metric.add_sample(
                    "analysisd_stats",
                    value=analysisd_stat[sample],
                    labels={"analysisd_stats": sample},
                )

        yield metric

        metric = InfoMetricFamily(
            "wazuh_validate_configuration",
            "Return whether the Wazuh configuration is correct",
        )
        validate_config = validate_config if isinstance(validate_config, Iterable) else ()
        for validate in validate_config:
            metric.add_metric(
                labels=f'wazuh_{validate.get("name", "")}',
                value={
                    "status": f'{validate.get("status", "").strip()}',
                    "node_name": f'{validate.get("name", "")}',
                },
            )
        yield metric


if __name__ == "__main__":
    logger.info("Starting Wazuh prometheus exporter")
    start_http_server(int(listen_port))
    REGISTRY.register(WazuhCollector())

    while True:
        time.sleep(1)
