# Terraform modules

This project contains the [Terraform][Terraform] modules to deploy the 
[Wazuh server charm][Wazuh server charm] with its dependencies.

The modules use the [Terraform Juju provider][Terraform Juju provider] to model
the bundle deployment onto any Kubernetes environment managed by [Juju][Juju].

## Module structure

- **main.tf** - Defines the Juju application to be deployed.
- **variables.tf** - Allows customization of the deployment including Juju model name, charm's channel and configuration.
- **output.tf** - Responsible for integrating the module with other Terraform modules, primarily by defining potential integration endpoints (charm integrations).
- **versions.tf** - Defines the Terraform provider.

[Terraform]: https://www.terraform.io/
[Terraform Juju provider]: https://registry.terraform.io/providers/juju/juju/latest
[Juju]: https://juju.is
[Wazuh server charm]: https://charmhub.io/wazuh-server

<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | >= 1.7.2 |
| <a name="requirement_juju"></a> [juju](#requirement\_juju) | >= 0.19.0 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_juju"></a> [juju](#provider\_juju) | >= 0.19.0 |
| <a name="provider_juju.wazuh_dashboard"></a> [juju.wazuh\_dashboard](#provider\_juju.wazuh\_dashboard) | >= 0.19.0 |
| <a name="provider_juju.wazuh_indexer"></a> [juju.wazuh\_indexer](#provider\_juju.wazuh\_indexer) | >= 0.19.0 |

## Modules

| Name | Source | Version |
|------|--------|---------|
| <a name="module_wazuh_dashboard"></a> [wazuh\_dashboard](#module\_wazuh\_dashboard) | git::https://github.com/canonical/wazuh-dashboard-operator//terraform/product | rev17&depth=1 |
| <a name="module_wazuh_indexer"></a> [wazuh\_indexer](#module\_wazuh\_indexer) | git::https://github.com/canonical/wazuh-indexer-operator//terraform/product | rev9&depth=1 |
| <a name="module_wazuh_indexer_backup"></a> [wazuh\_indexer\_backup](#module\_wazuh\_indexer\_backup) | ./modules/s3-integrator | n/a |
| <a name="module_wazuh_server"></a> [wazuh\_server](#module\_wazuh\_server) | ../charm | n/a |

## Resources

| Name | Type |
|------|------|
| [juju_access_offer.self_signed_certificates](https://registry.terraform.io/providers/juju/juju/latest/docs/resources/access_offer) | resource |
| [juju_access_offer.wazuh_indexer](https://registry.terraform.io/providers/juju/juju/latest/docs/resources/access_offer) | resource |
| [juju_access_offer.wazuh_server_api](https://registry.terraform.io/providers/juju/juju/latest/docs/resources/access_offer) | resource |
| [juju_application.data_integrator](https://registry.terraform.io/providers/juju/juju/latest/docs/resources/application) | resource |
| [juju_application.self_signed_certificates](https://registry.terraform.io/providers/juju/juju/latest/docs/resources/application) | resource |
| [juju_application.traefik_k8s](https://registry.terraform.io/providers/juju/juju/latest/docs/resources/application) | resource |
| [juju_integration.wazuh_dashboard_certificates](https://registry.terraform.io/providers/juju/juju/latest/docs/resources/integration) | resource |
| [juju_integration.wazuh_indexer_backup](https://registry.terraform.io/providers/juju/juju/latest/docs/resources/integration) | resource |
| [juju_integration.wazuh_indexer_certificates](https://registry.terraform.io/providers/juju/juju/latest/docs/resources/integration) | resource |
| [juju_integration.wazuh_indexer_dashboard](https://registry.terraform.io/providers/juju/juju/latest/docs/resources/integration) | resource |
| [juju_integration.wazuh_indexer_data_integrator](https://registry.terraform.io/providers/juju/juju/latest/docs/resources/integration) | resource |
| [juju_integration.wazuh_server_api](https://registry.terraform.io/providers/juju/juju/latest/docs/resources/integration) | resource |
| [juju_integration.wazuh_server_certificates](https://registry.terraform.io/providers/juju/juju/latest/docs/resources/integration) | resource |
| [juju_integration.wazuh_server_indexer](https://registry.terraform.io/providers/juju/juju/latest/docs/resources/integration) | resource |
| [juju_integration.wazuh_server_traefik_ingress](https://registry.terraform.io/providers/juju/juju/latest/docs/resources/integration) | resource |
| [juju_offer.self_signed_certificates](https://registry.terraform.io/providers/juju/juju/latest/docs/resources/offer) | resource |
| [juju_offer.wazuh_indexer](https://registry.terraform.io/providers/juju/juju/latest/docs/resources/offer) | resource |
| [juju_offer.wazuh_server_api](https://registry.terraform.io/providers/juju/juju/latest/docs/resources/offer) | resource |
| [juju_model.wazuh_dashboard](https://registry.terraform.io/providers/juju/juju/latest/docs/data-sources/model) | data source |
| [juju_model.wazuh_indexer](https://registry.terraform.io/providers/juju/juju/latest/docs/data-sources/model) | data source |
| [juju_model.wazuh_server](https://registry.terraform.io/providers/juju/juju/latest/docs/data-sources/model) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_dashboard_model"></a> [dashboard\_model](#input\_dashboard\_model) | Reference to the VM Juju model to deploy the dashboard charms to. | `string` | n/a | yes |
| <a name="input_indexer_controller"></a> [indexer\_controller](#input\_indexer\_controller) | Reference to the Juju controller where Wazuh indexer is deploy. | `string` | n/a | yes |
| <a name="input_indexer_model"></a> [indexer\_model](#input\_indexer\_model) | Reference to the VM Juju model to deploy the indexer charms to. | `string` | n/a | yes |
| <a name="input_self_signed_certificates"></a> [self\_signed\_certificates](#input\_self\_signed\_certificates) | n/a | <pre>object({<br/>    app_name    = optional(string, "self-signed-certificates")<br/>    channel     = optional(string, "latest/stable")<br/>    config      = optional(map(string), {})<br/>    constraints = optional(string, "arch=amd64")<br/>    revision    = optional(number)<br/>    base        = optional(string, "ubuntu@24.04")<br/>    units       = optional(number, 1)<br/>    storage     = optional(map(string), {})<br/>  })</pre> | n/a | yes |
| <a name="input_server_controller"></a> [server\_controller](#input\_server\_controller) | Reference to the Juju controller where Wazuh server is deployed. | `string` | n/a | yes |
| <a name="input_server_model"></a> [server\_model](#input\_server\_model) | Reference to the k8s Juju model to deploy Wazuh server to. | `string` | n/a | yes |
| <a name="input_sysconfig"></a> [sysconfig](#input\_sysconfig) | n/a | <pre>object({<br/>    app_name = optional(string, "sysconfig")<br/>    channel  = optional(string, "latest/stable")<br/>    revision = optional(number)<br/>  })</pre> | n/a | yes |
| <a name="input_traefik_k8s"></a> [traefik\_k8s](#input\_traefik\_k8s) | n/a | <pre>object({<br/>    app_name    = optional(string, "traefik-k8s")<br/>    channel     = optional(string, "latest/edge")<br/>    config      = optional(map(string), {})<br/>    constraints = optional(string, "arch=amd64")<br/>    revision    = optional(number)<br/>    base        = optional(string, "ubuntu@20.04")<br/>    units       = optional(number, 1)<br/>    storage     = optional(map(string), {})<br/>  })</pre> | n/a | yes |
| <a name="input_wazuh_dashboard"></a> [wazuh\_dashboard](#input\_wazuh\_dashboard) | n/a | <pre>object({<br/>    app_name    = optional(string, "wazuh-dashboard")<br/>    channel     = optional(string, "4.11/edge")<br/>    config      = optional(map(string), {})<br/>    constraints = optional(string, "arch=amd64")<br/>    revision    = optional(number)<br/>    base        = optional(string, "ubuntu@22.04")<br/>    units       = optional(number, 3)<br/>  })</pre> | n/a | yes |
| <a name="input_wazuh_dashboard_grafana_agent"></a> [wazuh\_dashboard\_grafana\_agent](#input\_wazuh\_dashboard\_grafana\_agent) | n/a | <pre>object({<br/>    app_name = optional(string, "grafana-agent")<br/>    channel  = optional(string, "latest/stable")<br/>    config   = optional(map(string), {})<br/>    revision = optional(number)<br/>  })</pre> | n/a | yes |
| <a name="input_wazuh_indexer"></a> [wazuh\_indexer](#input\_wazuh\_indexer) | n/a | <pre>object({<br/>    app_name    = optional(string, "wazuh-indexer")<br/>    channel     = optional(string, "4.11/edge")<br/>    config      = optional(map(string), {})<br/>    constraints = optional(string, "arch=amd64")<br/>    revision    = optional(number)<br/>    base        = optional(string, "ubuntu@22.04")<br/>    units       = optional(number, 3)<br/>  })</pre> | n/a | yes |
| <a name="input_wazuh_indexer_backup"></a> [wazuh\_indexer\_backup](#input\_wazuh\_indexer\_backup) | n/a | <pre>object({<br/>    app_name    = optional(string, "wazuh_indexer_backup")<br/>    channel     = optional(string, "latest/edge")<br/>    config      = optional(map(string), {})<br/>    constraints = optional(string, "arch=amd64")<br/>    revision    = optional(number)<br/>    base        = optional(string, "ubuntu@22.04")<br/>    units       = optional(number, 1)<br/>  })</pre> | n/a | yes |
| <a name="input_wazuh_indexer_grafana_agent"></a> [wazuh\_indexer\_grafana\_agent](#input\_wazuh\_indexer\_grafana\_agent) | n/a | <pre>object({<br/>    app_name = optional(string, "grafana-agent")<br/>    channel  = optional(string, "latest/stable")<br/>    config   = optional(map(string), {})<br/>    revision = optional(number)<br/>  })</pre> | n/a | yes |
| <a name="input_wazuh_server"></a> [wazuh\_server](#input\_wazuh\_server) | n/a | <pre>object({<br/>    app_name    = optional(string, "wazuh-server")<br/>    channel     = optional(string, "4.11/edge")<br/>    config      = optional(map(string), {})<br/>    constraints = optional(string, "arch=amd64")<br/>    revision    = optional(number)<br/>    base        = optional(string, "ubuntu@22.04")<br/>    units       = optional(number, 1)<br/>  })</pre> | n/a | yes |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_traefik_name"></a> [traefik\_name](#output\_traefik\_name) | Name of the deployed Traefik application. |
| <a name="output_traefik_provides"></a> [traefik\_provides](#output\_traefik\_provides) | n/a |
| <a name="output_traefik_requires"></a> [traefik\_requires](#output\_traefik\_requires) | n/a |
| <a name="output_wazuh_dashboard_grafana_agent_name"></a> [wazuh\_dashboard\_grafana\_agent\_name](#output\_wazuh\_dashboard\_grafana\_agent\_name) | Name of the deployed Grafana agent for the Wazuh dashboard application. |
| <a name="output_wazuh_dashboard_grafana_agent_provides"></a> [wazuh\_dashboard\_grafana\_agent\_provides](#output\_wazuh\_dashboard\_grafana\_agent\_provides) | n/a |
| <a name="output_wazuh_dashboard_grafana_agent_requires"></a> [wazuh\_dashboard\_grafana\_agent\_requires](#output\_wazuh\_dashboard\_grafana\_agent\_requires) | n/a |
| <a name="output_wazuh_dashboard_name"></a> [wazuh\_dashboard\_name](#output\_wazuh\_dashboard\_name) | Name of the deployed Wazuh dashboard application. |
| <a name="output_wazuh_dashboard_requires"></a> [wazuh\_dashboard\_requires](#output\_wazuh\_dashboard\_requires) | n/a |
| <a name="output_wazuh_indexer_grafana_agent_name"></a> [wazuh\_indexer\_grafana\_agent\_name](#output\_wazuh\_indexer\_grafana\_agent\_name) | Name of the deployed Grafana agent for the Wazuh indexer application. |
| <a name="output_wazuh_indexer_grafana_agent_provides"></a> [wazuh\_indexer\_grafana\_agent\_provides](#output\_wazuh\_indexer\_grafana\_agent\_provides) | n/a |
| <a name="output_wazuh_indexer_grafana_agent_requires"></a> [wazuh\_indexer\_grafana\_agent\_requires](#output\_wazuh\_indexer\_grafana\_agent\_requires) | n/a |
| <a name="output_wazuh_indexer_name"></a> [wazuh\_indexer\_name](#output\_wazuh\_indexer\_name) | Name of the deployed Wazuh indexer application. |
| <a name="output_wazuh_server_name"></a> [wazuh\_server\_name](#output\_wazuh\_server\_name) | Name of the deployed Wazuh server application. |
| <a name="output_wazuh_server_provides"></a> [wazuh\_server\_provides](#output\_wazuh\_server\_provides) | n/a |
| <a name="output_wazuh_server_requires"></a> [wazuh\_server\_requires](#output\_wazuh\_server\_requires) | n/a |
<!-- END_TF_DOCS -->