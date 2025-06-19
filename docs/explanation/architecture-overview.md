# Architecture overview

Wazuh is a security platform that provides unified XDR and SIEM protection for endpoints and cloud workloads. The solution is composed of a single universal agent and three central components: the Wazuh server, the Wazuh indexer, and the Wazuh dashboard.

The universal agent is not yet available in the charmed Wazuh ecosystem. Logs are collected through an agentless architecture relying on `rsyslog`.

```mermaid
C4Context
title Wazuh architecture overview

Person(security-analyst, "Security Analyst", "")
Rel(security-analyst, wazuh-dashboard, "")

Deployment_Node(vm-model, "VM model") {
  Container_Boundary(wazuh-dashboard, "Wazuh dashboard charm") {
    Component(wazuh-dashboard, "Wazuh Dashboard", "","A customized OpenSearch dashboard")
  }
  Container_Boundary(wazuh-indexer, "Wazuh indexer charm") {
    Component(wazuh-indexer, "Wazuh Indexer", "","A customized OpenSearch to store logs, events, alerts")
  }
}

Deployment_Node(k8s-model, "k8s model") {
  Container_Boundary(wazuh-server, "Wazuh Server charm") {
    Component(wazuh-server, "Wazuh Server", "", "Received, analyzes and exports logs and events")
  }
}

System_Ext(endpoint-rsyslog, "Endpoint rsyslog", "","Forwards logs to Wazuh")

Rel(wazuh-server, wazuh-indexer, "Store events")
Rel(wazuh-dashboard, wazuh-indexer, "Access events")
Rel(wazuh-dashboard, wazuh-server, "")
Rel(endpoint-rsyslog, wazuh-server, "")

UpdateRelStyle(wazuh-server, wazuh-indexer, $offsetX="-120", $offsetY="200")

UpdateLayoutConfig($c4ShapeInRow="2", $c4BoundaryInRow="2")
```
