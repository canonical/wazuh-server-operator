# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

variable "dashboard_model_name" {
  description = "Juju model for Wazuh Dashboard"
  type        = string
}

variable "dashboard_model_uuid" {
  description = "Juju model UUID for Wazuh Dashboard"
  type        = string
}

variable "indexer_consumers" {
  description = "Additional model names that need to consume the indexer offer"
  type        = list(string)
  default     = []
}

variable "indexer_model_name" {
  description = "Juju model for Wazuh Indexer"
  type        = string
}

variable "indexer_model_uuid" {
  description = "Juju model UUID for Wazuh Indexer"
  type        = string
}

variable "risk" {
  description = <<-EOT
    Risk level for the solution. Controls the channel risk of bundled
    components that do not expose their own channel input, such as the
    data-integrator charm. Per-charm "channel" fields remain independently
    configurable and are not overridden by this flag.
  EOT
  type        = string
  default     = "stable"
  nullable    = false

  validation {
    condition     = contains(["stable", "edge"], var.risk)
    error_message = "risk must be one of: stable, edge."
  }
}

variable "self_signed_certificates" {
  type = object({
    app_name    = optional(string, "self-signed-certificates")
    channel     = optional(string, "1/stable")
    config      = optional(map(string), {})
    constraints = optional(string, "arch=amd64")
    revision    = optional(number)
    base        = optional(string, "ubuntu@22.04")
    units       = optional(number, 1)
    storage     = optional(map(string), {})
  })
}

variable "server_model_name" {
  description = "Juju model for Wazuh Server"
  type        = string
}

variable "server_model_uuid" {
  description = "Juju model UUID for Wazuh Server"
  type        = string
}

variable "sysconfig" {
  type = object({
    app_name = optional(string, "sysconfig")
    channel  = optional(string, "latest/stable")
    revision = optional(number)
  })
}

variable "traefik_k8s" {
  type = object({
    app_name    = optional(string, "traefik-k8s")
    channel     = optional(string, "latest/edge")
    config      = optional(map(string), {})
    constraints = optional(string, "arch=amd64")
    revision    = optional(number)
    base        = optional(string, "ubuntu@20.04")
    units       = optional(number, 1)
    storage     = optional(map(string), {})
  })
}

variable "wazuh_dashboard" {
  type = object({
    app_name    = optional(string, "wazuh-dashboard")
    channel     = optional(string, "4.14/edge")
    config      = optional(map(string), {})
    constraints = optional(string, "arch=amd64")
    revision    = optional(number)
    base        = optional(string, "ubuntu@22.04")
    units       = optional(number, 3)
  })
}

variable "wazuh_dashboard_grafana_agent" {
  type = object({
    app_name = optional(string, "grafana-agent")
    channel  = optional(string, "1/stable")
    config   = optional(map(string), {})
    revision = optional(number)
  })
}

variable "wazuh_indexer" {
  type = object({
    app_name    = optional(string, "wazuh-indexer")
    channel     = optional(string, "4.14/edge")
    config      = optional(map(string), {})
    constraints = optional(string, "arch=amd64")
    revision    = optional(number)
    base        = optional(string, "ubuntu@22.04")
    units       = optional(number, 3)
  })
}

variable "wazuh_indexer_backup" {
  type = object({
    app_name    = optional(string, "wazuh_indexer_backup")
    channel     = optional(string, "latest/edge")
    config      = optional(map(string), {})
    constraints = optional(string, "arch=amd64")
    revision    = optional(number)
    base        = optional(string, "ubuntu@22.04")
    units       = optional(number, 1)
  })
}

variable "wazuh_indexer_grafana_agent" {
  type = object({
    app_name = optional(string, "grafana-agent")
    channel  = optional(string, "1/stable")
    config   = optional(map(string), {})
    revision = optional(number)
  })
}

variable "wazuh_server" {
  type = object({
    app_name    = optional(string, "wazuh-server")
    channel     = optional(string, "4.14/edge")
    config      = optional(map(string), {})
    constraints = optional(string, "arch=amd64")
    revision    = optional(number)
    base        = optional(string, "ubuntu@22.04")
    units       = optional(number, 1)
    storage     = optional(map(string), {})
  })
}
