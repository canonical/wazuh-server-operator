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

## Using `wazuh-server` base module in higher level modules

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

<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | >= 1.6.6 |
| <a name="requirement_juju"></a> [juju](#requirement\_juju) | ~> 1.1.0 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_juju"></a> [juju](#provider\_juju) | ~> 1.1.0 |

## Modules

No modules.

## Resources

| Name | Type |
|------|------|
| [juju_application.wazuh_server](https://registry.terraform.io/providers/juju/juju/latest/docs/resources/application) | resource |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_app_name"></a> [app\_name](#input\_app\_name) | Name of the application in the Juju model. | `string` | `"wazuh-server"` | no |
| <a name="input_base"></a> [base](#input\_base) | The operating system on which to deploy | `string` | `"ubuntu@22.04"` | no |
| <a name="input_channel"></a> [channel](#input\_channel) | The channel to use when deploying a charm. | `string` | `"4.11/edge"` | no |
| <a name="input_config"></a> [config](#input\_config) | Application config. Details about available options can be found at https://charmhub.io/wazuh-server/configurations. | `map(string)` | `{}` | no |
| <a name="input_constraints"></a> [constraints](#input\_constraints) | Juju constraints to apply for this application. | `string` | `""` | no |
| <a name="input_model_uuid"></a> [model\_uuid](#input\_model\_uuid) | Reference to a `juju_model`. | `string` | `""` | no |
| <a name="input_revision"></a> [revision](#input\_revision) | Revision number of the charm | `number` | `null` | no |
| <a name="input_storage"></a> [storage](#input\_storage) | Storage used by the application | `map(string)` | n/a | yes |
| <a name="input_units"></a> [units](#input\_units) | Number of units to deploy | `number` | `1` | no |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_app_name"></a> [app\_name](#output\_app\_name) | Name of the deployed application. |
| <a name="output_provides"></a> [provides](#output\_provides) | n/a |
| <a name="output_requires"></a> [requires](#output\_requires) | n/a |
<!-- END_TF_DOCS -->