# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

data "juju_model" "wazuh_server" {
  name = var.model
}

data "juju_model" "wazuh_indexer" {
  name = var.indexer_model

  provider = juju.wazuh_indexer
}

# resource "juju_secret" "agent_password" {
#   model = local.juju_model_name
#   name  = "agent_password"
#   value = var.wazuh_server.config
#     value = data.vault_generic_secret.agent_password.data["agent-password"]
#   }
#   info = "Password for the Wazuh agents"
# }

module "wazuh_server" {
  source      = "../charm"
  app_name    = var.wazuh_server.app_name
  channel     = var.wazuh_server.channel
  config      = var.wazuh_server.config
  model       = data.juju_model.wazuh_server.name
  constraints = var.wazuh_server.constraints
  revision    = var.wazuh_server.revision
  base        = var.wazuh_server.base
  units       = var.wazuh_server.units
}

module "traefik_k8s" {
  source      = "git::https://github.com/canonical/traefik-k8s-operator//terraform"
  app_name    = var.traefik_k8s.app_name
  channel     = var.traefik_k8s.channel
  config      = var.traefik_k8s.config
  constraints = var.traefik_k8s.constraints
  model       = data.juju_model.wazuh_server.name
  revision    = var.traefik_k8s.revision
  base        = var.traefik_k8s.base
  units       = var.traefik_k8s.units
}

resource "juju_integration" "wazuh_server_traefik_ingress" {
  model = data.juju_model.wazuh_server.name

  application {
    name     = module.wazuh_server.app_name
    endpoint = module.wazuh_server.requires.ingress
  }

  application {
    name     = module.traefik_k8s.app_name
    endpoint = module.traefik_k8s.provides.traefik_route
  }
}

module "self-signed-certificates" {
  source      = "git::https://github.com/canonical/self-signed-certificates-operator//terraform"
  app_name    = var.self_signed_certificates.app_name
  channel     = var.self_signed_certificates.channel
  config      = var.self_signed_certificates.config
  constraints = var.self_signed_certificates.constraints
  model       = data.juju_model.wazuh_indexer.name
  revision    = var.self_signed_certificates.revision
  base        = var.self_signed_certificates.base
  units       = var.self_signed_certificates.units

  providers = {
    juju = juju.wazuh_indexer
  }
}

resource "juju_offer" "self_signed_certificates" {
  model = data.juju_model.wazuh_indexer.name

  name             = "self-signed-certificates"
  application_name = module.self_signed_certificates.app_name
  endpoint         = module.self_signed_certificates.provides.certificates

  providers = {
    juju = juju.wazuh_indexer
  }
}

resource "juju_access_offer" "self_signed_certificates" {
  offer_url = juju_offer.self_signed_certificates.url
  admin     = [data.juju_model.wazuh_indexer.name]
  consume   = [data.juju_model.wazuh_server.name]

  providers = {
    juju = juju.wazuh_indexer
  }
}

resource "juju_integration" "wazuh_server_certificates" {
  model = data.juju_model.wazuh_server.name

  application {
    name     = module.wazuh_server.app_name
    endpoint = module.wazuh_server.requires.certificates
  }

  application {
    name     = juju_offer.self_signed_certificates.app_name
    endpoint = juju_offer.self_signed_certificates.provides.certificates
  }
}

resource "juju_application" "sysconfig" {
  name  = "sysconfig"
  model = data.juju_model.wazuh_indexer.name
  units = 0

  charm {
    name     = "sysconfig"
    revision = 33
    channel  = "latest/stable"
    base     = "ubuntu@22.04"
  }

  config = {
    sysctl = "{vm.max_map_count: 262144, vm.swappiness: 0, net.ipv4.tcp_retries2: 5, fs.file-max: 1048576}"
  }

  providers = {
    juju = juju.wazuh_indexer
  }
}

module "wazuh-indexer" {
  source      = "git::https://github.com/canonical/wazuh-indexer-operator//terraform/charm"
  app_name    = var.wazuh_indexer.app_name
  channel     = var.wazuh_indexer.channel
  config      = var.wazuh_indexer.config
  constraints = var.wazuh_indexer.constraints
  model       = data.juju_model.wazuh_indexer.name
  revision    = var.wazuh_indexer.revision
  base        = var.wazuh_indexer.base
  units       = var.wazuh_indexer.units

  providers = {
    juju = juju.wazuh_indexer
  }
}

resource "juju_access_offer" "wazuh_indexer" {
  offer_url = juju_offer.wazuh_indexer.url
  admin     = [data.juju_model.wazuh_indexer.name]
  consume   = [data.juju_model.wazuh_server.name]

  providers = {
    juju = juju.wazuh_indexer
  }
}

resource "juju_integration" "wazuh_indexer_sysconfig" {
  model = data.juju_model.wazuh_indexer.name

  application {
    name     = module.wazuh_indexer.app_name
    endpoint = "juju-info"
  }
  application {
    name     = juju_application.sysconfig.name
    endpoint = "juju-info"
  }

  providers = {
    juju = juju.wazuh_indexer
  }
}

module "wazuh-dashboard" {
  source      = "git::https://github.com/canonical/wazuh-dashboard-operator//terraform/charm"
  app_name    = var.wazuh_dashboard.app_name
  channel     = var.wazuh_dashboard.channel
  config      = var.wazuh_dashboard.config
  constraints = var.wazuh_dashboard.constraints
  model       = data.juju_model.wazuh_indexer.name
  revision    = var.wazuh_dashboard.revision
  base        = var.wazuh_dashboard.base
  units       = var.wazuh_dashboard.units

  providers = {
    juju = juju.wazuh_indexer
  }
}

resource "juju_integration" "wazuh_indexer_dashboard" {
  model = data.juju_model.wazuh_indexer.name

  application {
    name     = module.wazuh_indexer.app_name
    endpoint = module.wazuh_indexer.provides.opensearch_client
  }

  application {
    name     = module.wazuh_dashboard.app_name
    endpoint = module.wazuh_dashboard.requires.opensearch_client
  }

  providers = {
    juju = juju.wazuh_indexer
  }
}

resource "juju_integration" "wazuh_indexer_certificates" {
  model = data.juju_model.wazuh_indexer.name

  application {
    name     = module.wazuh_indexer.app_name
    endpoint = module.wazuh_indexer.requires.certificates
  }

  application {
    name     = juju_offer.self_signed_certificates.app_name
    endpoint = juju_offer.self_signed_certificates.provides.certificates
  }

  providers = {
    juju = juju.wazuh_indexer
  }
}

resource "juju_integration" "wazuh_dashboard_certificates" {
  model = data.juju_model.wazuh_indexer.name

  application {
    name     = module.wazuh_dashboard.app_name
    endpoint = module.wazuh_dashboard.requires.certificates
  }
  application {
    name     = juju_offer.self_signed_certificates.app_name
    endpoint = juju_offer.self_signed_certificates.provides.certificates
  }

  providers = {
    juju = juju.wazuh_indexer
  }
}

resource "juju_application" "data_integrator" {
  name  = "data-integrator"
  model = data.juju_model.wazuh_indexer.name
  units = 1

  charm {
    name     = "data-integrator"
    revision = 41
    channel  = "latest/stable"
    base     = "ubuntu@22.04"
  }

  config = {
    extra-user-roles = "admin"
    index-name       = "placeholder"
  }

  providers = {
    juju = juju.wazuh_indexer
  }
}

resource "juju_integration" "wazuh_indexer_data_integrator" {
  model = data.juju_model.wazuh_indexer.name

  application {
    name     = module.wazuh_indexer.app_name
    endpoint = module.wazuh_indexer.provides.opensearch_client
  }
  application {
    name     = juju_application.data_integrator.name
    endpoint = "opensearch"
  }

  providers = {
    juju = juju.wazuh_indexer
  }
}

resource "juju_integration" "wazuh_server_indexer" {
  model = data.juju_model.wazuh_server.name

  application {
    name     = module.wazuh_server.app_name
    endpoint = module.wazuh_server.requires.opensearch_client
  }

  application {
    name     = juju_offer.wazuh_indexer.app_name
    endpoint = juju_offer.wazuh_indexer.provides.opensearch_client
  }
}
