# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

terraform {
  required_providers {
    juju = {
      source  = "juju/juju"
      version = ">= 0.17.1"
      configuration_aliases = [juju.wazuh_indexer]
    }
  }
}
