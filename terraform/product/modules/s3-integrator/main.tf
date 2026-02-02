# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

resource "juju_application" "s3_integrator" {
  name       = var.app_name
  model_uuid = var.model_uuid

  charm {
    name     = "s3-integrator"
    channel  = var.channel
    revision = var.revision
    base     = var.base
  }

  config      = var.config
  constraints = var.constraints
  units       = var.units
}
