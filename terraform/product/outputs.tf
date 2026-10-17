# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

output "metadata" {
  description = "Metadata of the product deployment."
  value = {
    version     = "1.0.0"
    deployed_at = terraform_data.deployed_at.output
    updated_at  = timestamp()
  }
}

output "models" {
  description = "Map of the key of the model and the components deployed in the model."
  value = {
    wazuh_server = {
      model_uuid = data.juju_model.wazuh_server.uuid
      components = {
        wazuh_server = module.wazuh_server.application
        traefik_k8s  = juju_application.traefik_k8s
      }
    }
    wazuh_indexer = {
      model_uuid = data.juju_model.wazuh_indexer.uuid
      components = {
        wazuh_indexer            = module.wazuh_indexer.app_name # TODO: expose application
        self_signed_certificates = juju_application.self_signed_certificates
        data_integrator          = juju_application.data_integrator
        wazuh_indexer_backup     = module.wazuh_indexer_backup.application
      }
    }
    wazuh_dashboard = {
      model_uuid = data.juju_model.wazuh_dashboard.uuid
      components = {
        wazuh_dashboard = module.wazuh_dashboard.app_name # TODO: expose application
      }
    }
  }
}

output "self_signed_certificates_app_name" {
  description = "Name of the deployed self-signed-certificates application."
  value       = juju_application.self_signed_certificates.name
}

output "self_signed_certificates_offer_url" {
  description = "URL of the self-signed-certificates offer."
  value       = juju_offer.self_signed_certificates.url
}

output "traefik_name" {
  description = "Name of the deployed Traefik application."
  value       = juju_application.traefik_k8s.name
}

output "traefik_provides" {
  description = "Provides endpoints of the deployed Traefik application."
  value = {
    grafana_dashboard = "grafana-dashboard"
    metrics_endpoint  = "metrics-endpoint"
  }
}

output "traefik_requires" {
  description = "Requires endpoints of the deployed Traefik application."
  value = {
    logging = "logging"
  }
}

output "wazuh_dashboard_grafana_agent_name" {
  description = "Name of the deployed Grafana agent for the Wazuh dashboard application."
  value       = module.wazuh_dashboard.grafana_agent_app_name
}

output "wazuh_dashboard_grafana_agent_provides" {
  description = "Provides endpoints of the deployed Grafana agent for the Wazuh dashboard application."
  value       = module.wazuh_dashboard.grafana_agent_provides
}

output "wazuh_dashboard_grafana_agent_requires" {
  description = "Requires endpoints of the deployed Grafana agent for the Wazuh dashboard application."
  value       = module.wazuh_dashboard.grafana_agent_requires
}

output "wazuh_dashboard_name" {
  description = "Name of the deployed Wazuh dashboard application."
  value       = module.wazuh_dashboard.app_name
}

output "wazuh_dashboard_requires" {
  description = "Requires endpoints of the deployed Wazuh dashboard application."
  value       = module.wazuh_dashboard.wazuh_dashboard_requires
}

output "wazuh_indexer_grafana_agent_name" {
  description = "Name of the deployed Grafana agent for the Wazuh indexer application."
  value       = module.wazuh_indexer.grafana_agent_app_name
}

output "wazuh_indexer_grafana_agent_provides" {
  description = "Provides endpoints of the deployed Grafana agent for the Wazuh indexer application."
  value       = module.wazuh_indexer.grafana_agent_provides
}

output "wazuh_indexer_grafana_agent_requires" {
  description = "Requires endpoints of the deployed Grafana agent for the Wazuh indexer application."
  value       = module.wazuh_indexer.grafana_agent_requires
}

output "wazuh_indexer_name" {
  description = "Name of the deployed Wazuh indexer application."
  value       = module.wazuh_indexer.app_name
}

output "wazuh_server_name" {
  description = "Name of the deployed Wazuh server application."
  value       = module.wazuh_server.app_name
}

output "wazuh_server_provides" {
  description = "Provides endpoints of the deployed Wazuh server application."
  value = {
    grafana_dashboard = "grafana-dashboard"
    metrics_endpoint  = "metrics-endpoint"
    opencti_connector = "opencti-connector"
  }
}

output "wazuh_server_requires" {
  description = "Requires endpoints of the deployed Wazuh server application."
  value = {
    logging      = "logging"
    certificates = "certificates"
  }
}
