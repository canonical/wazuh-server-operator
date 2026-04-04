# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

terraform {
  required_version = "~> 1.12"
  required_providers {
    juju = {
      version = "~> 1.0"
      source  = "juju/juju"
      configuration_aliases = [juju.wazuh_indexer, juju.wazuh_dashboard]
    }
  }
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

resource "juju_model" "wazuh_server" {
  name = "tf-wazuh-server-${formatdate("YYYYMMDDhhmmss", timestamp())}"

  provider = juju
}

resource "juju_model" "wazuh_indexer" {
  name = "tf-wazuh-indexer-${formatdate("YYYYMMDDhhmmss", timestamp())}"

  provider = juju.wazuh_indexer
}

resource "juju_model" "wazuh_dashboard" {
  name = "tf-wazuh-dashboard-${formatdate("YYYYMMDDhhmmss", timestamp())}"

  provider = juju.wazuh_dashboard
}

resource "juju_user" "wazuh_indexer_in_indexer" {
  name = juju_model.wazuh_indexer.name
  password = "Dummy12345"

  provider = juju.wazuh_indexer
}
resource "juju_user" "wazuh_indexer_in_server" {
  name = juju_model.wazuh_indexer.name
  password = "Dummy12345"

  provider = juju
}

resource "juju_user" "wazuh_dashboard_in_server" {
  name = juju_model.wazuh_dashboard.name
  password = "Dummy12345"
  provider = juju
}
resource "juju_user" "wazuh_dashboard_in_dashboard" {
  name = juju_model.wazuh_dashboard.name
  password = "Dummy12345"
  provider = juju.wazuh_dashboard
}

resource "juju_user" "wazuh_server_in_dashboard" {
  name = juju_model.wazuh_server.name
  password = "Dummy12345"
  provider = juju.wazuh_dashboard
}
resource "juju_user" "wazuh_server_in_server" {
  name = juju_model.wazuh_server.name
  password = "Dummy12345"
  provider = juju
}

output "server_model_uuid" {
  value = juju_model.wazuh_server.uuid
}

output "server_model_name" {
  value = juju_model.wazuh_server.name
}

output "indexer_model_uuid" {
  value = juju_model.wazuh_indexer.uuid
}

output "indexer_model_name" {
  value = juju_model.wazuh_indexer.name
}

output "dashboard_model_uuid" {
  value = juju_model.wazuh_dashboard.uuid
}

output "dashboard_model_name" {
  value = juju_model.wazuh_dashboard.name
}
