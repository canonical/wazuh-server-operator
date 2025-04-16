# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

variable "server_controller" {
  description = "Reference to the Juju controller where Wazuh server is deployed."
  type        = string
}

variable "indexer_controller" {
  description = "Reference to the Juju controller where Wazuh indexer is deploy."
  type        = string
}

variable "server_model" {
  description = "Reference to the k8s Juju model to deploy Wazuh server to."
  type        = string
}

variable "indexer_model" {
  description = "Reference to the VM Juju model to deploy the indexer charms to."
  type        = string
}

variable "dashboard_model" {
  description = "Reference to the VM Juju model to deploy the dashboard charms to."
  type        = string
}

variable "wazuh_indexer" {
  type = object({
    app_name    = optional(string, "wazuh-indexer")
    channel     = optional(string, "4.9/edge")
    config      = optional(map(string), {})
    constraints = optional(string, "arch=amd64")
    revision    = optional(number)
    base        = optional(string, "ubuntu@22.04")
    units       = optional(number, 3)
  })
}

variable "wazuh_dashboard" {
  type = object({
    app_name    = optional(string, "wazuh-dashboard")
    channel     = optional(string, "4.9/edge")
    config      = optional(map(string), {})
    constraints = optional(string, "arch=amd64")
    revision    = optional(number)
    base        = optional(string, "ubuntu@22.04")
    units       = optional(number, 3)
  })
}

variable "wazuh_server" {
  type = object({
    app_name    = optional(string, "wazuh-server")
    channel     = optional(string, "4.9/edge")
    config      = optional(map(string), {})
    constraints = optional(string, "arch=amd64")
    revision    = optional(number)
    base        = optional(string, "ubuntu@22.04")
    units       = optional(number, 1)
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

variable "self_signed_certificates" {
  type = object({
    app_name    = optional(string, "self-signed-certificates")
    channel     = optional(string, "latest/stable")
    config      = optional(map(string), {})
    constraints = optional(string, "arch=amd64")
    revision    = optional(number)
    base        = optional(string, "ubuntu@24.04")
    units       = optional(number, 1)
    storage     = optional(map(string), {})
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
