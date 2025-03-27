# Architecture overview

Wazuh is a security platform that provides unified XDR and SIEM protection for endpoints and cloud workloads. The solution is composed of a single universal agent and three central components: the Wazuh Server, the Wazuh indexer, and the Wazuh dashboard.

The universal agent is not yet available in the charmed Wazuh ecosystem. Logs are collected through an agentless architecture relying on `rsyslog`.


```mermaid
C4Context
title Wazuh architecture overview

Person(security-analyst, "Security Analyst", "")
Rel(security-analyst, wazuh-dashboard, "")

Container_Boundary(wazuh-dashboard, "Wazuh Dashboard Charm") {
    Component(wazuh-dashboard, "Wazuh Dashboard Snap", "","A customized OpenSearch dashboard")
}


Container_Boundary(synapse, "Wazuh Server Charm") {
  Component(wazuh-server, "Wazuh Server", "", "Analyzing logs and events")
  Component(wazuh-filebeat, "Wazuh Filebeat", "", "Forwarding logs")
  ComponentDb(filesystem, "Ephemeral storage", "", "Log files on filesystem")
  Component(wazuh-rsyslog, "Wazuh Rsyslog server", "", "Collecting logs")
  Rel(wazuh-rsyslog, filesystem,"")
  Rel(wazuh-filebeat, filesystem,"")
}
Rel(wazuh-filebeat, wazuh-indexer,"Store logs")

Container_Boundary(wazuh-indexer, "Wazuh Indexer Charm") {
    Component(wazuh-indexer, "Wazuh Indexer Snap", "","A cutomized opensearch to store logs, events, alerts..")
}


Container_Boundary(endpoints, "Endpoints") {
    Component(endpoint-rsyslog, "Endpoint rsyslog", "","Forwarding log to Wazuh.")
}


Rel(wazuh-server, wazuh-indexer, "Store events")
Rel(wazuh-dashboard, wazuh-indexer, "Access events")
Rel(wazuh-dashboard, wazuh-server, "")
Rel(endpoint-rsyslog, wazuh-rsyslog, "")

UpdateRelStyle(wazuh-server, wazuh-indexer, $offsetX="-120", $offsetY="200")
UpdateRelStyle(wazuh-filebeat, wazuh-indexer, $offsetX="75", $offsetY="-80")

UpdateLayoutConfig($c4ShapeInRow="2", $c4BoundaryInRow="2")
```