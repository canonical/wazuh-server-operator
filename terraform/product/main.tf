# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

data "juju_model" "wazuh_server" {
  name = var.server_model
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

resource "juju_offer" "wazuh_server_api" {
  model = data.juju_model.wazuh_server.name

  name             = "wazuh-server-api"
  application_name = var.wazuh_server.app_name
  endpoint         = module.wazuh_server.provides.wazuh_api
}

resource "juju_access_offer" "wazuh_server_api" {
  offer_url = juju_offer.wazuh_server_api.url
  admin     = [data.juju_model.wazuh_server.name]
  consume   = [data.juju_model.wazuh_indexer.name]
}

resource "juju_integration" "wazuh_server_api" {
  provider = juju.wazuh_indexer
  model    = data.juju_model.wazuh_indexer.name

  application {
    name     = module.wazuh_dashboard.app_name
    endpoint = module.wazuh_dashboard.requires.wazuh_api
  }

  application {
    offer_url = "${var.server_controller}:${juju_offer.wazuh_server_api.url}"
  }

  depends_on = [
    juju_access_offer.wazuh_server_api
  ]

}

module "traefik_k8s" {
  source      = "git::https://github.com/canonical/traefik-k8s-operator//terraform?ref=rev236"
  app_name    = var.traefik_k8s.app_name
  channel     = var.traefik_k8s.channel
  config      = var.traefik_k8s.config
  constraints = var.traefik_k8s.constraints
  model_name  = data.juju_model.wazuh_server.name
  revision    = var.traefik_k8s.revision
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
    endpoint = module.traefik_k8s.endpoints.traefik_route
  }
}

module "self_signed_certificates" {
  source      = "git::https://github.com/canonical/self-signed-certificates-operator//terraform?ref=rev281"
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

  provider = juju.wazuh_indexer
}

resource "juju_access_offer" "self_signed_certificates" {
  offer_url = juju_offer.self_signed_certificates.url
  admin     = [data.juju_model.wazuh_indexer.name]
  consume   = [data.juju_model.wazuh_server.name]

  provider = juju.wazuh_indexer
}

resource "juju_integration" "wazuh_server_certificates" {
  model = data.juju_model.wazuh_server.name

  application {
    name     = module.wazuh_server.app_name
    endpoint = module.wazuh_server.requires.certificates
  }

  application {
    offer_url = "${var.indexer_controller}:${juju_offer.self_signed_certificates.url}"
  }

  depends_on = [
    juju_access_offer.self_signed_certificates
  ]
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

  provider = juju.wazuh_indexer
}

module "wazuh_indexer" {
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

resource "juju_offer" "wazuh_indexer" {
  model = data.juju_model.wazuh_indexer.name

  name             = "wazuh-indexer"
  application_name = module.wazuh_indexer.app_name
  endpoint         = module.wazuh_indexer.provides.opensearch_client

  provider = juju.wazuh_indexer
}

resource "juju_access_offer" "wazuh_indexer" {
  offer_url = juju_offer.wazuh_indexer.url
  admin     = [data.juju_model.wazuh_indexer.name]
  consume   = [data.juju_model.wazuh_server.name]

  provider = juju.wazuh_indexer
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

  provider = juju.wazuh_indexer
}

module "wazuh_dashboard" {
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

  provider = juju.wazuh_indexer
}

resource "juju_integration" "wazuh_indexer_certificates" {
  model = data.juju_model.wazuh_indexer.name

  application {
    name     = module.wazuh_indexer.app_name
    endpoint = module.wazuh_indexer.requires.certificates
  }

  application {
    name     = module.self_signed_certificates.app_name
    endpoint = module.self_signed_certificates.provides.certificates
  }

  provider = juju.wazuh_indexer
}

resource "juju_integration" "wazuh_dashboard_certificates" {
  model = data.juju_model.wazuh_indexer.name

  application {
    name     = module.wazuh_dashboard.app_name
    endpoint = module.wazuh_dashboard.requires.certificates
  }
  application {
    name     = module.self_signed_certificates.app_name
    endpoint = module.self_signed_certificates.provides.certificates
  }

  provider = juju.wazuh_indexer
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

  provider = juju.wazuh_indexer
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

  provider = juju.wazuh_indexer
}

resource "juju_integration" "wazuh_server_indexer" {
  model = data.juju_model.wazuh_server.name

  application {
    name     = module.wazuh_server.app_name
    endpoint = module.wazuh_server.requires.opensearch-client
  }

  application {
    offer_url = "${var.indexer_controller}:${juju_offer.wazuh_indexer.url}"
  }

  depends_on = [
    juju_access_offer.wazuh_indexer
  ]
}
