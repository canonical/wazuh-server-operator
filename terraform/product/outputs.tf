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
  value       = module.traefik_k8s.app_name
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

output "wazuh_indexer_provides" {
  value = {
    cos_agent = "cos-agent"
  }
}

output "wazuh_dashboard_name" {
  description = "Name of the deployed Wazuh dashboard application."
  value       = module.wazuh_dashboard.app_name
}

output "wazuh_dashboard_provides" {
  value = {
    cos_agent = "cos-agent"
  }
}
