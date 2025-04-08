# Architecture overview

Wazuh is a security platform that provides unified XDR and SIEM protection for endpoints and cloud workloads. The solution is composed of a single universal agent and three central components: the Wazuh server, the Wazuh indexer, and the Wazuh dashboard.

The universal agent is not yet available in the charmed Wazuh ecosystem. Logs are collected through an agentless architecture relying on `rsyslog`.

```mermaid
C4Context
title Wazuh architecture overview

Person(security-analyst, "Security Analyst", "")
Rel(security-analyst, wazuh-dashboard, "")

Container_Boundary(wazuh-dashboard, "Wazuh dashboard charm") {
    Component(wazuh-dashboard, "Wazuh Dashboard Snap", "","A customized OpenSearch dashboard")
}


Container_Boundary(synapse, "Wazuh server charm") {
  Component(wazuh-server, "Wazuh server", "", "Analyzes logs and events")
  Component(wazuh-filebeat, "Wazuh filebeat", "", "Forwards logs")
  ComponentDb(filesystem, "Ephemeral storage", "", "Logs files on filesystem")
  Component(wazuh-rsyslog, "Wazuh rsyslog server", "", "Collects logs")
  Rel(wazuh-rsyslog, filesystem,"")
  Rel(filesystem, wazuh-filebeat, "")
}
Rel(wazuh-filebeat, wazuh-indexer,"Store logs")

Container_Boundary(wazuh-indexer, "Wazuh indexer charm") {
    Component(wazuh-indexer, "Wazuh indexer snap", "","A customized OpenSearch to store logs, events, alerts")
}


Container_Boundary(endpoints, "Endpoints") {
    Component(endpoint-rsyslog, "Endpoint rsyslog", "","Forwards logs to Wazuh")
}


Rel(wazuh-server, wazuh-indexer, "Store events")
Rel(wazuh-dashboard, wazuh-indexer, "Access events")
Rel(wazuh-dashboard, wazuh-server, "")
Rel(endpoint-rsyslog, wazuh-rsyslog, "")

UpdateRelStyle(wazuh-server, wazuh-indexer, $offsetX="-120", $offsetY="200")
UpdateRelStyle(wazuh-filebeat, wazuh-indexer, $offsetX="75", $offsetY="-80")

UpdateLayoutConfig($c4ShapeInRow="2", $c4BoundaryInRow="2")
```
