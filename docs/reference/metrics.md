(reference_metrics)=

# Metrics

The Wazuh Server charm exposes Prometheus-compatible metrics through the `metrics-endpoint`
relation. The metrics are produced by a [Wazuh Prometheus exporter](https://github.com/pyToshka/wazuh-prometheus-exporter)
that is shipped with the charm. The charm's version of the exporter is modified by Canonical.
The exporter queries the [Wazuh server API](https://documentation.wazuh.com/current/user-manual/api/reference.html)
and converts the responses to metrics.

To collect the metrics, see [Integrate with COS](../how-to/integrate-with-cos.md).

## Scrape endpoint

- Interface: `prometheus_scrape`
- Relation endpoint: `metrics-endpoint`
- Job name: `stats_exporter`
- Metrics path: `/metrics`
- Metrics port: `5000`

## Available metrics

The exporter collects the following metrics. For the meaning of the underlying values,
see the [Wazuh server API reference](https://documentation.wazuh.com/current/user-manual/api/reference.html)
and the [Wazuh statistics documentation](https://documentation.wazuh.com/current/user-manual/reference/statistics-files/index.html).

### Agents

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `wazuh_agents_count` | summary | `node_name` | Number of agents connected to each cluster node. |
| `wazuh_agents_group` | summary | `group_name` | Number of agents in each group. |
| `wazuh_active_agents` | summary | - | Number of agents with the `active` status. |
| `wazuh_disconnected_agents` | summary | - | Number of agents with the `disconnected` status. |
| `wazuh_never_connected_agents` | summary | - | Number of agents that have never connected. |
| `wazuh_pending_agents` | summary | - | Number of agents with the `pending` status. |
| `wazuh_total_agents` | summary | - | Total number of registered agents. |
| `wazuh_agent_version` | gauge | `version` | Number of agents for each agent version. |
| `last_registered_agent_info` | info | - | Operating system information of the last registered agent. |

### Cluster and API

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `nodes_healthcheck_info` | info | `node_name` | Health check information for each cluster node. |
| `wazuh_api_info` | info | - | Wazuh API information, such as the API version. |
| `wazuh_validate_configuration_info` | info | - | Whether the Wazuh configuration of each node is valid. |
| `last_logs_info` | info | - | The last 2000 Wazuh log entries. |

### Manager statistics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `total_alerts_hour_<hour>` | summary | - | Alerts for the current day, for each hour (`0`-`23`). |
| `total_syscheck_hour_<hour>` | summary | - | File integrity monitoring events for the current day, for each hour. |
| `total_firewall_hour_<hour>` | summary | - | Firewall events for the current day, for each hour. |
| `total_events_hour_<hour>` | summary | - | Events for the current day, for each hour. |
| `total_affected_items` | info | - | Number of items returned by the hourly statistics API. |
| `total_failed_items` | info | - | Number of items that failed in the hourly statistics API. |

### Remote daemon (`wazuh-remoted`)

Each sample below is exposed as its own series, labeled with `manager_stats_remote` set to the
sample name.

| Sample | Description |
|--------|-------------|
| `queue_size` | Current size of the message queue. |
| `total_queue_size` | Maximum capacity of the message queue. |
| `tcp_sessions` | Number of active TCP sessions. |
| `evt_count` | Number of events received. |
| `ctrl_msg_count` | Number of control messages received. |
| `discarded_count` | Number of discarded messages. |
| `recv_bytes` | Number of bytes received. |
| `dequeued_after_close` | Number of messages dequeued after the connection closed. |
| `queued_msgs` | Number of queued messages. Only reported for Wazuh API versions earlier than 4.7.0. |

### Analysis daemon (`wazuh-analysisd`)

The `analysisd_stats` metric carries the `analysisd_stats` label set to one of the following
values:

- Events decoded: `total_events_decoded`, `syscheck_events_decoded`,
  `syscollector_events_decoded`, `rootcheck_events_decoded`, `sca_events_decoded`,
  `winevt_events_decoded`, `other_events_decoded`
- Event flow: `events_processed`, `events_received`, `events_dropped`, `dbsync_messages_dispatched`
- Output: `alerts_written`, `firewall_written`, `fts_written`
- Queue usage and size: `syscheck_queue_usage`, `syscheck_queue_size`,
  `syscollector_queue_usage`, `syscollector_queue_size`, `rootcheck_queue_usage`,
  `rootcheck_queue_size`, `sca_queue_usage`, `sca_queue_size`, `hostinfo_queue_usage`,
  `hostinfo_queue_size`, `winevt_queue_usage`, `dbsync_queue_usage`, `dbsync_queue_size`,
  `upgrade_queue_usage`, `upgrade_queue_size`, `event_queue_usage`, `event_queue_size`,
  `rule_matching_queue_usage`, `rule_matching_queue_size`, `alerts_queue_usage`,
  `alerts_queue_size`, `firewall_queue_usage`, `statistical_queue_usage`,
  `statistical_queue_size`, `archives_queue_usage`, `archives_queue_size`
- Events per second, only reported for Wazuh API versions earlier than 4.7.0: `syscheck_edps`,
  `syscollector_edps`, `rootcheck_edps`, `sca_edps`, `hostinfo_edps`, `winevt_edps`,
  `other_events_edps`, `events_edps`, `dbsync_mdps`, `hostinfo_events_decoded`
