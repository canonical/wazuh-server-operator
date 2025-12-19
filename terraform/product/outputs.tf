# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

output "self_signed_certificates_app_name" {
  description = "Name of the deployed self-signed-certificates application."
  value       = juju_application.self_signed_certificates.name
}

output "self_signed_certificates_provides" {
  value = {
    certificates = "certificates"
    send_ca_cert = "send-ca-cert"
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

output "wazuh_server_name" {
  description = "Name of the deployed Wazuh server application."
  value       = module.wazuh_server.app_name
}

output "wazuh_server_requires" {
  value = {
    logging      = "logging"
    certificates = "certificates"
  }
}

output "wazuh_server_provides" {
  value = {
    grafana_dashboard = "grafana-dashboard"
    metrics_endpoint  = "metrics-endpoint"
    opencti_connector = "opencti-connector"
  }
}

output "wazuh_indexer_name" {
  description = "Name of the deployed Wazuh indexer application."
  value       = module.wazuh_indexer.app_name
}

output "wazuh_indexer_grafana_agent_name" {
  description = "Name of the deployed Grafana agent for the Wazuh indexer application."
  value       = module.wazuh_indexer.grafana_agent_app_name
}

output "wazuh_indexer_grafana_agent_requires" {
  value = module.wazuh_indexer.grafana_agent_requires
}

output "wazuh_indexer_grafana_agent_provides" {
  value = module.wazuh_indexer.grafana_agent_provides
}

output "wazuh_dashboard_name" {
  description = "Name of the deployed Wazuh dashboard application."
  value       = module.wazuh_dashboard.app_name
}

output "wazuh_dashboard_requires" {
  value = module.wazuh_dashboard.wazuh_dashboard_requires
}

output "wazuh_dashboard_grafana_agent_name" {
  description = "Name of the deployed Grafana agent for the Wazuh dashboard application."
  value       = module.wazuh_dashboard.grafana_agent_app_name
}

output "wazuh_dashboard_grafana_agent_requires" {
  value = module.wazuh_dashboard.grafana_agent_requires
}

output "wazuh_dashboard_grafana_agent_provides" {
  value = module.wazuh_dashboard.grafana_agent_provides
}
