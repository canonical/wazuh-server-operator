# Wazuh server Terraform module

This folder contains a base [Terraform][Terraform] module for the Wazuh server charm.

The module uses the [Terraform Juju provider][Terraform Juju provider] to model the charm
deployment onto any Kubernetes environment managed by [Juju][Juju].

## Module structure

- **main.tf** - Defines the Juju application to be deployed.
- **variables.tf** - Allows customization of the deployment. Also models the charm configuration, 
  except for exposing the deployment options (Juju model name, channel or application name).
- **output.tf** - Integrates the module with other Terraform modules, primarily
  by defining potential integration endpoints (charm integrations), but also by exposing
  the Juju application name.
- **versions.tf** - Defines the Terraform provider version.

## Using wazuh-server base module in higher level modules

If you want to use `wazuh-server` base module as part of your Terraform module, import it
like shown below:

```text
data "juju_model" "my_model" {
  name = var.model
}

module "wazuh_server" {
  source = "git::https://github.com/canonical/wazuh-server-operator//terraform"
  
  model = juju_model.my_model.name
  # (Customize configuration variables here if needed)
}
```

Create integrations, for instance:

```text
resource "juju_integration" "wazuh-server-traefik" {
  model = juju_model.my_model.name
  application {
    name     = module.wazuh_server.app_name
    endpoint = module.wazuh_server.requires.ingress
  }
  application {
    name     = "traefik-k8s"
    endpoint = "traefik-route"
  }
}
```

The complete list of available integrations can be found [in the Integrations tab][wazuh-server-integrations].

[Terraform]: https://www.terraform.io/
[Terraform Juju provider]: https://registry.terraform.io/providers/juju/juju/latest
[Juju]: https://juju.is
[wazuh-server-integrations]: https://charmhub.io/wazuh-server/integrations
