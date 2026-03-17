# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

provider "juju" {}

provider "juju" {
  alias = "wazuh_indexer"
}

provider "juju" {
  alias = "wazuh_dashboard"
}

run "setup_tests" {
  module {
    source = "./tests/setup"
  }
}

run "basic_deploy" {
  command = apply 

  variables {
    server_model_uuid    = run.setup_tests.server_model_uuid
    server_model_name    = run.setup_tests.server_model_name
    indexer_model_uuid   = run.setup_tests.indexer_model_uuid
    indexer_model_name   = run.setup_tests.indexer_model_name
    dashboard_model_uuid = run.setup_tests.dashboard_model_uuid
    dashboard_model_name = run.setup_tests.dashboard_model_name

    wazuh_server = {
      channel = "4.11/edge"
      # renovate: depName="wazuh-server"
      revision = 246
      storage  = {}
    }

    wazuh_indexer = {
      channel = "4.11/edge"
      # renovate: depName="wazuh-indexer"
      revision = 12
    }

    wazuh_indexer_grafana_agent = {}

    sysconfig = {
      # renovate: depName="sysconfig"
      revision = 161
    }

    wazuh_dashboard = {
      channel = "4.11/edge"
      # renovate: depName="wazuh-dashboard"
      revision = 21
    }

    wazuh_dashboard_grafana_agent = {}

    traefik_k8s = {
      # renovate: depName="traefik-k8s"
      revision = 273
    }

    self_signed_certificates = {
      # renovate: depName="self-signed-certificates"
      revision = 602
    }

    wazuh_indexer_backup = {
      # renovate: depName="s3-integrator"
      revision = 155
    }
  }
}
