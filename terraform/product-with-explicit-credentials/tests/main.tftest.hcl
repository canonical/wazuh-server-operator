# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

variable "lxd_controller_addresses" {
  description = "Juju controller API endpoint(s) for the LXD controller, comma-separated"
  type        = string
}

variable "lxd_ca_certificate" {
  description = "CA certificate for the LXD controller"
  type        = string
  sensitive   = true
}

variable "lxd_username" {
  description = "Username for the LXD controller"
  type        = string
}

variable "lxd_password" {
  description = "Password for the LXD controller"
  type        = string
  sensitive   = true
}

variable "k8s_controller_addresses" {
  description = "Juju controller API endpoint(s) for the K8s controller, comma-separated"
  type        = string
}

variable "k8s_ca_certificate" {
  description = "CA certificate for the K8s controller"
  type        = string
  sensitive   = true
}

variable "k8s_username" {
  description = "Username for the K8s controller"
  type        = string
}

variable "k8s_password" {
  description = "Password for the K8s controller"
  type        = string
  sensitive   = true
}

provider "juju" {
  controller_addresses = var.k8s_controller_addresses
  ca_certificate       = var.k8s_ca_certificate
  username             = var.k8s_username
  password             = var.k8s_password
}

provider "juju" {
  alias                = "wazuh_indexer"
  controller_addresses = var.lxd_controller_addresses
  ca_certificate       = var.lxd_ca_certificate
  username             = var.lxd_username
  password             = var.lxd_password
}

provider "juju" {
  alias                = "wazuh_dashboard"
  controller_addresses = var.lxd_controller_addresses
  ca_certificate       = var.lxd_ca_certificate
  username             = var.lxd_username
  password             = var.lxd_password
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
      constraints = "arch=amd64 cores=2 mem=3000"
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
      constraints = "arch=amd64 cores=2 mem=3000"
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
