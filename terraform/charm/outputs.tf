# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

output "app_name" {
  description = "Name of the deployed application."
  value       = juju_application.wazuh_server.name
}

output "application" {
  description = "Object representing the deployed application."
  value       = juju_application.wazuh_server
}

output "provides" {
  description = "Provides endpoints."
  value = {
    grafana_dashboard = {
      kind     = "endpoint"
      name     = juju_application.wazuh_server.name
      endpoint = "grafana-dashboard"
    }
    metrics_endpoint = {
      kind     = "endpoint"
      name     = juju_application.wazuh_server.name
      endpoint = "metrics-endpoint"
    }
    wazuh_api = {
      kind     = "endpoint"
      name     = juju_application.wazuh_server.name
      endpoint = "wazuh-api"
    }
    opencti_connector = {
      kind     = "endpoint"
      name     = juju_application.wazuh_server.name
      endpoint = "opencti-connector"
    }
  }
}

output "requires" {
  description = "Requires endpoints."
  value = {
    certificates = {
      kind       = "endpoint"
      name       = juju_application.wazuh_server.name
      endpoint   = "certificates"
      controller = null
    }
    ingress = {
      kind     = "endpoint"
      name     = juju_application.wazuh_server.name
      endpoint = "ingress"
    }
    logging = {
      kind     = "endpoint"
      name     = juju_application.wazuh_server.name
      endpoint = "logging"
    }
    opensearch-client = {
      kind       = "endpoint"
      name       = juju_application.wazuh_server.name
      endpoint   = "opensearch-client"
      controller = null
    }
  }
}
