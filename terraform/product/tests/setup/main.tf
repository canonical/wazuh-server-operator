# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

terraform {
  required_version = "~> 1.12"
  required_providers {
    juju = {
      version = "~> 1.0"
      source  = "juju/juju"
    }
  }
}

provider "juju" {}

resource "juju_model" "wazuh_server" {
  name       = "tf-wazuh-server-${formatdate("YYYYMMDDhhmmss", timestamp())}"
  credential = "tfk8s"

  cloud {
    name = "tfk8s"
  }
}
resource "juju_user" "wazuh_server" {
  name     = "tf-wazuh-server-${formatdate("YYYYMMDDhhmmss", timestamp())}"
  password = "changeme"
}

resource "juju_model" "wazuh_indexer" {
  name = "tf-wazuh-indexer-${formatdate("YYYYMMDDhhmmss", timestamp())}"
}
resource "juju_user" "wazuh_indexer" {
  name     = "tf-wazuh-indexer-${formatdate("YYYYMMDDhhmmss", timestamp())}"
  password = "changeme"
}

resource "juju_model" "wazuh_dashboard" {
  name = "tf-wazuh-dashboard-${formatdate("YYYYMMDDhhmmss", timestamp())}"
}
resource "juju_user" "wazuh_dashboard" {
  name     = "tf-wazuh-dashboard-${formatdate("YYYYMMDDhhmmss", timestamp())}"
  password = "changeme"
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
