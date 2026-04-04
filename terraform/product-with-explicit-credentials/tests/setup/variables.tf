# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

variable "lxd_controller_addresses" {
  description = "Juju controller API endpoint(s) for the LXD controller (concierge-lxd), comma-separated"
  type        = string
}

variable "lxd_ca_certificate" {
  description = "CA certificate for the LXD controller (concierge-lxd)"
  type        = string
  sensitive   = true
}

variable "lxd_username" {
  description = "Username for the LXD controller (concierge-lxd)"
  type        = string
}

variable "lxd_password" {
  description = "Password for the LXD controller (concierge-lxd)"
  type        = string
  sensitive   = true
}

variable "k8s_controller_addresses" {
  description = "Juju controller API endpoint(s) for the K8s controller (concierge-k8s), comma-separated"
  type        = string
}

variable "k8s_ca_certificate" {
  description = "CA certificate for the K8s controller (concierge-k8s)"
  type        = string
  sensitive   = true
}

variable "k8s_username" {
  description = "Username for the K8s controller (concierge-k8s)"
  type        = string
}

variable "k8s_password" {
  description = "Password for the K8s controller (concierge-k8s)"
  type        = string
  sensitive   = true
}
