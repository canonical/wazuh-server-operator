module "wazuh" {
  source               = "../../"
  server_model_name    = juju_model.wazuh_server.name
  server_model_uuid    = juju_model.wazuh_server.uuid
  indexer_model_name   = juju_model.wazuh_indexer.name
  indexer_model_uuid   = juju_model.wazuh_indexer.uuid
  dashboard_model_name = juju_model.wazuh_dashboard.name
  dashboard_model_uuid = juju_model.wazuh_dashboard.uuid

  providers = {
    juju                 = juju
    juju.wazuh_indexer   = juju.wazuh_indexer
    juju.wazuh_dashboard = juju.wazuh_dashboard
  }

  wazuh_server = {
    channel = "4.11/edge"
    # renovate: depName="wazuh-server"
    revision = 250
    storage  = {}
  }

  wazuh_indexer = {
    channel = "4.11/edge"
    # renovate: depName="wazuh-indexer"
    revision = 13
    config = {
      profile = "testing"
    }
    prevent_destroy = false
  }

  wazuh_indexer_grafana_agent = {}

  sysconfig = {
    # renovate: depName="sysconfig"
    revision = 33
  }

  wazuh_dashboard = {
    channel = "4.11/edge"
    # renovate: depName="wazuh-dashboard"
    revision = 21
  }

  wazuh_dashboard_grafana_agent = {}

  traefik_k8s = {
    # renovate: depName="traefik-k8s"
    revision = 285
  }

  self_signed_certificates = {
    channel = "1/edge"
    # renovate: depName="self-signed-certificates"
    revision = 518
    base     = "ubuntu@22.04"
  }

  wazuh_indexer_backup = {
    # renovate: depName="s3-integrator"
    revision = 155
  }
}
