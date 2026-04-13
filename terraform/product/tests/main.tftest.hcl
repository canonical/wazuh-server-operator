# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

provider "juju" {
}

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

  assert {
    condition     = output.wazuh_server_name == "wazuh-server"
    error_message = "wazuh-server app_name did not match expected"
  }

  assert {
    condition     = output.wazuh_indexer_name == "wazuh-indexer"
    error_message = "wazuh-indexer app_name did not match expected"
  }

  assert {
    condition     = output.wazuh_dashboard_name == "wazuh-dashboard"
    error_message = "wazuh-dashboard app_name did not match expected"
  }

  assert {
    condition     = output.traefik_name == "traefik-k8s"
    error_message = "traefik-k8s app_name did not match expected"
  }

  assert {
    condition     = output.self_signed_certificates_app_name == "self-signed-certificates"
    error_message = "self-signed-certificates app_name did not match expected"
  }
}

run "wait_for_dashboard_active" {
  variables {
    model_uuid = run.setup_tests.dashboard_model_uuid
    app_name   = "wazuh-dashboard"
    timeout    = 180
  }

  module {
    source = "./tests/wait_for_active"
  }

  assert {
    condition     = data.external.app_status.result.status == "active"
    error_message = "wazuh-dashboard did not reach active state"
  }
}

run "wait_for_indexer_active" {
  variables {
    model_uuid = run.setup_tests.indexer_model_uuid
    app_name   = "wazuh-indexer"
    timeout    = 300
  }

  module {
    source = "./tests/wait_for_active"
  }

  assert {
    condition     = data.external.app_status.result.status == "active"
    error_message = "wazuh-indexer did not reach active state"
  }
}

