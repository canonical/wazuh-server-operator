# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

output "app_name" {
  description = "Name of the deployed application."
  value       = juju_application.s3_integrator.name
}

output "application" {
  description = "Object representing the deployed application."
  value       = juju_application.s3_integrator
}

output "provides" {
  description = "Provides endpoints."
  value = {
    s3_credentials = {
      kind     = "endpoint"
      name     = juju_application.s3_integrator.name
      endpoint = "s3-credentials"
    }
  }
}

output "requires" {
  description = "Requires endpoints."
  value       = {}
}
