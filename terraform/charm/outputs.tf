# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

output "app_name" {
  description = "Name of the deployed application."
  value       = juju_application.wazuh_server.name
}

output "requires" {
  value = {
    certificates      = "certificates"
    ingress           = "ingress"
    logging           = "logging"
    opensearch-client = "opensearch-client"
  }
}

output "provides" {
  value = {
    grafana_dashboard = "grafana-dashboard"
    metrics_endpoint  = "metrics-endpoint"
  }
}
