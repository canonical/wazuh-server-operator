# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

output "wazuh_server_name" {
  description = "Name of the deployed Wazuh server application."
  value       = module.wazuh_server.app_name
}

output "wazuh_server_requires" {
  value = {
    logging = "logging"
  }
}

output "wazuh_server_provides" {
  value = {
    grafana_dashboard = "grafana-dashboard"
    metrics_endpoint  = "metrics-endpoint"
  }
}

output "traefik_name" {
  description = "Name of the deployed Traefik application."
  value       = juju_application.traefik_k8s.name
}

output "traefik_requires" {
  value = {
    logging = "logging"
  }
}

output "traefik_provides" {
  value = {
    grafana_dashboard = "grafana-dashboard"
    metrics_endpoint  = "metrics-endpoint"
  }
}

output "wazuh_indexer_name" {
  description = "Name of the deployed Wazuh indexer application."
  value       = module.wazuh_indexer.app_name
}

output "wazuh_indexer_grafana_agent_requires" {
  value = module.wazuh_indexer.requires
}

output "wazuh_indexer_grafana_agent_provides" {
  value = module.wazuh_indexer.provides
}

output "wazuh_dashboard_name" {
  description = "Name of the deployed Wazuh dashboard application."
  value       = module.wazuh_dashboard.app_name
}

output "wazuh_dashboard_grafana_agent_requires" {
  value = module.wazuh_dashboard.requires
}

output "wazuh_dashboard_grafana_agent_provides" {
  value = module.wazuh_dashboard.provides
}
