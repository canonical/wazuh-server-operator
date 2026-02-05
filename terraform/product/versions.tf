# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

terraform {
  required_version = ">= 1.7.2"
  required_providers {
    juju = {
      source                = "juju/juju"
      version               = "~> 1.2.0"
      configuration_aliases = [juju.wazuh_indexer, juju.wazuh_dashboard]
    }
  }
}
