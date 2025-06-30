# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

data "juju_model" "wazuh_server" {
  name = var.server_model
}

data "juju_model" "wazuh_indexer" {
  name = var.indexer_model

  provider = juju.wazuh_indexer
}

data "juju_model" "wazuh_dashboard" {
  name = var.dashboard_model

  provider = juju.wazuh_dashboard
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
  consume   = [data.juju_model.wazuh_dashboard.name]
}

resource "juju_integration" "wazuh_server_api" {
  provider = juju.wazuh_dashboard
  model    = data.juju_model.wazuh_dashboard.name

  application {
    name     = module.wazuh_dashboard.app_name
    endpoint = module.wazuh_dashboard.wazuh_dashboard_requires.wazuh_api
  }

  application {
    offer_url = "${var.server_controller}:${juju_offer.wazuh_server_api.url}"
  }

  depends_on = [
    juju_access_offer.wazuh_server_api
  ]
}

resource "juju_application" "traefik_k8s" {
  name  = var.traefik_k8s.app_name
  model = data.juju_model.wazuh_server.name
  trust = true
  charm {
    name     = "traefik-k8s"
    channel  = var.traefik_k8s.channel
    revision = var.traefik_k8s.revision
  }
  units  = var.traefik_k8s.units
  config = var.traefik_k8s.config
}

resource "juju_integration" "wazuh_server_traefik_ingress" {
  model = data.juju_model.wazuh_server.name

  application {
    name     = module.wazuh_server.app_name
    endpoint = module.wazuh_server.requires.ingress
  }

  application {
    name     = juju_application.traefik_k8s.name
    endpoint = "traefik-route"
  }
}

resource "juju_application" "self_signed_certificates" {
  name  = var.self_signed_certificates.app_name
  model = data.juju_model.wazuh_indexer.name

  charm {
    name     = "self-signed-certificates"
    channel  = var.self_signed_certificates.channel
    revision = var.self_signed_certificates.revision
    base     = var.self_signed_certificates.base
  }

  config      = var.self_signed_certificates.config
  constraints = var.self_signed_certificates.constraints
  units       = var.self_signed_certificates.units

  provider = juju.wazuh_indexer
}

resource "juju_offer" "self_signed_certificates" {
  model = data.juju_model.wazuh_indexer.name

  name             = "self-signed-certificates"
  application_name = juju_application.self_signed_certificates.name
  endpoint         = "certificates"

  provider = juju.wazuh_indexer
}

resource "juju_access_offer" "self_signed_certificates" {
  offer_url = juju_offer.self_signed_certificates.url
  admin     = [data.juju_model.wazuh_indexer.name]
  consume   = [data.juju_model.wazuh_server.name, data.juju_model.wazuh_dashboard.name]

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

module "wazuh_indexer" {
  source = "git::https://github.com/canonical/wazuh-indexer-operator//terraform/product?ref=rev10&depth=1"

  model = data.juju_model.wazuh_indexer.name

  grafana_agent = {
    app_name = var.wazuh_indexer_grafana_agent.app_name
    channel  = var.wazuh_indexer_grafana_agent.channel
    revision = var.wazuh_indexer_grafana_agent.revision
  }

  sysconfig = {
    app_name = var.sysconfig.app_name
    channel  = var.sysconfig.channel
    revision = var.sysconfig.revision
  }

  wazuh_indexer = {
    app_name    = var.wazuh_indexer.app_name
    channel     = var.wazuh_indexer.channel
    config      = var.wazuh_indexer.config
    constraints = var.wazuh_indexer.constraints
    revision    = var.wazuh_indexer.revision
    base        = var.wazuh_indexer.base
    units       = var.wazuh_indexer.units
  }

  providers = {
    juju = juju.wazuh_indexer
  }
}

resource "juju_offer" "wazuh_indexer" {
  model = data.juju_model.wazuh_indexer.name

  name             = module.wazuh_indexer.app_name
  application_name = module.wazuh_indexer.app_name
  endpoint         = module.wazuh_indexer.wazuh_indexer_provides.opensearch_client

  provider = juju.wazuh_indexer
}

resource "juju_access_offer" "wazuh_indexer" {
  offer_url = juju_offer.wazuh_indexer.url
  admin     = [data.juju_model.wazuh_indexer.name]
  consume   = [data.juju_model.wazuh_server.name, data.juju_model.wazuh_dashboard.name]

  provider = juju.wazuh_indexer
}

resource "juju_integration" "wazuh_indexer_certificates" {
  model = data.juju_model.wazuh_indexer.name

  application {
    name     = module.wazuh_indexer.app_name
    endpoint = module.wazuh_indexer.wazuh_indexer_requires.certificates
  }

  application {
    name     = juju_application.self_signed_certificates.name
    endpoint = "certificates"
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
    endpoint = module.wazuh_indexer.wazuh_indexer_provides.opensearch_client
  }
  application {
    name     = juju_application.data_integrator.name
    endpoint = "opensearch"
  }

  provider = juju.wazuh_indexer
}

module "wazuh_indexer_backup" {
  source = "./modules/s3-integrator"
  model  = data.juju_model.wazuh_indexer.name

  app_name      = "${var.wazuh_indexer.app_name}-backup"
  channel       = var.wazuh_indexer_backup.channel
  config        = var.wazuh_indexer_backup.config
  constraints   = var.wazuh_indexer_backup.constraints
  revision      = var.wazuh_indexer_backup.revision
  base          = var.wazuh_indexer_backup.base
  units         = var.wazuh_indexer_backup.units
  s3_access_key = var.wazuh_indexer_backup.s3_access_key
  s3_secret_key = var.wazuh_indexer_backup.s3_secret_key

  providers = {
    juju = juju.wazuh_indexer
  }

  depends_on = [
    juju_access_offer.wazuh_indexer
  ]
}

resource "juju_integration" "wazuh_indexer_backup" {
  model = data.juju_model.wazuh_indexer.name

  application {
    name     = module.wazuh_indexer.app_name
    endpoint = module.wazuh_indexer.wazuh_indexer_requires.s3_credentials
  }

  application {
    name     = module.wazuh_indexer_backup.app_name
    endpoint = module.wazuh_indexer_backup.provides.s3_credentials
  }

  provider = juju.wazuh_indexer
}

module "wazuh_dashboard" {
  source = "git::https://github.com/canonical/wazuh-dashboard-operator//terraform/product?ref=rev14&depth=1"

  model = data.juju_model.wazuh_dashboard.name

  grafana_agent = {
    app_name = var.wazuh_dashboard_grafana_agent.app_name
    channel  = var.wazuh_dashboard_grafana_agent.channel
    revision = var.wazuh_dashboard_grafana_agent.revision
  }

  wazuh_dashboard = {
    app_name    = var.wazuh_dashboard.app_name
    channel     = var.wazuh_dashboard.channel
    config      = var.wazuh_dashboard.config
    constraints = var.wazuh_dashboard.constraints
    revision    = var.wazuh_dashboard.revision
    base        = var.wazuh_dashboard.base
    units       = var.wazuh_dashboard.units
  }

  providers = {
    juju = juju.wazuh_dashboard
  }
}

resource "juju_integration" "wazuh_indexer_dashboard" {
  model = data.juju_model.wazuh_dashboard.name

  application {
    name     = module.wazuh_dashboard.app_name
    endpoint = module.wazuh_dashboard.wazuh_dashboard_requires.opensearch_client
  }

  application {
    offer_url = "${var.indexer_controller}:${juju_offer.wazuh_indexer.url}"
  }

  provider = juju.wazuh_dashboard
}

resource "juju_integration" "wazuh_dashboard_certificates" {
  model = data.juju_model.wazuh_dashboard.name

  application {
    name     = module.wazuh_dashboard.app_name
    endpoint = module.wazuh_dashboard.wazuh_dashboard_requires.certificates
  }
  application {
    offer_url = "${var.indexer_controller}:${juju_offer.self_signed_certificates.url}"
  }

  provider = juju.wazuh_dashboard
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
