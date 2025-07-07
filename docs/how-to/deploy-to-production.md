# How to deploy to production

This page describes a typical deployment to production.

## Prerequisites

Create the two required models:
- `wazuh-indexer`: a machine model
- `wazuh-server`: a Kubernetes model

Open network accesses:
- To the `wazuh-dashboard` through `https`
  - For the users who will need to access the dashboard.
- To the `wazuh-server` through port `6514`
  - For the rsyslog server who will send their logs to Wazuh.
- To the `wazuh-indexer` through port `9200`
  - For `wazuh-server` to interact with `opensearch`

## Deploy the project

The full stack can be deployed using the terraform module hosted at [https://github.com/canonical/wazuh-server-operator/terraform/product/](https://github.com/canonical/wazuh-server-operator/terraform/product/).

A typical deployment would be configured like this:
```
locals {
  juju_indexer_model_name = "wazuh-indexer"
  juju_server_model_name  = "wazuh-server"
}

data "juju_model" "wazuh_server" {
  name = local.juju_server_model_name
}

module "wazuh" {
  source        = "git::https://github.com/canonical/wazuh-server-operator//terraform/product?ref=4.11/stable"
  model         = local.juju_server_model_name
  indexer_model = local.juju_indexer_model_name

  wazuh_indexer = {
    channel = "4.11/stable"
  }

  wazuh_dashboard = {
    channel = "4.11/stable"
  }

  wazuh_server = {
    channel = "4.11/stable"
  }

  traefik_k8s = {
  }

  self_signed_certificates = {
    channel = "1/stable"
  }

  providers = {
    juju               = juju
    juju.wazuh_indexer = juju.wazuh_indexer
  }
}
```