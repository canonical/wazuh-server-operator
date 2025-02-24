# Deploy the Wazuh Server charm for the first time

## What you’ll do
- Deploy the Wazuh Server charm.
- Integrate with the Wazuh Indexer charm.
- Integrate with the elf Signed X.509 Certificates charm.
- Integrate with the Traefik charm.

## Requirements

* A working station, e.g., a laptop, with amd64 architecture.
* Juju 3 installed and bootstrapped to a MicroK8s and to an LXD controller. You can accomplish
this process by using a [Multipass](https://multipass.run/) VM as outlined in this guide: [Set up / Tear down your test environment](https://juju.is/docs/juju/set-up--tear-down-your-test-environment)
* A deployed Wazij Indexer. For instructions to deploy the Wazuh Indexer, check [its documentation](https://charmhub.io/wazuh-indexer).

:warning: When using a Multipass VM, make sure to replace IP addresses with the
VM IP in steps that assume you're running locally. To get the IP address of the
Multipass instance run ```multipass info my-juju-vm```.

## Set up a Tutorial Model

To manage resources effectively and to separate this tutorial's workload from
your usual work, create a new model using the following command.

```bash
juju add-model wazuh-tutorial
```

## Deploy the Wazuh Server charm
Synapse requires connections to Wazuh indexer, Traefik and a charm implementing the TLS certificates relation.
For this tutorial we will be using Self Signed X.509 Certificates.

### Deploy and integrate the charms

```bash
juju deploy wazuh-server
juju deploy self-signed-certificates
juju deploy traefik-k8s --trust
```

To connect the agents, you'll need to configure the agent password. For that,
create a secret and set it in the Wazuh server configuration:
```bash
juju add-secret agent-password value=<agent-password>
juju grant-secret agent-password wazuh-server
juju config wazuh-server agent-password=<secret-id>
```
where `<agent-password>` is the password you want to configure and`<secret-id>` is the ID of the secret containing the password.

Run `juju status` to see the current status of the deployment. Wazuh server unit should be in `waiting status`.

Provide the integrations between the Wazuh Server and the other charms:
```bash
juju integrate wazuh-server self-signed-certificates
juju integrate wazuh-server traefik-k8s
# Note that the indexer is deployed in a machine model in another controller
juju integrate wazuh-server <offer-url>
```

Note that `<offer-url>` is the Juju offer for the Wazuh Indexer.


Monitor the deployment using `juju status` until the output looks similar to the following one:
```bash
SAAS                             Status  Store                           URL
wazuh-indexer-opensearch-client  active  juju-controller-lxd             admin/wazuh.wazuh-indexer-opensearch-client

App           Version  Status  Scale  Charm                     Channel        Rev  Address        Exposed  Message
certificates           active      1  self-signed-certificates  latest/stable  155  10.87.137.125  no       
traefik       2.11.0   active      1  traefik-k8s               latest/edge    233  10.87.242.226  no       Serving at 10.142.2.62
wazuh-server           active      1  wazuh-server              latest/edge     39  10.87.248.244  no     
```

The deployment is complete when the status is `Active`.

## Clean up the Environment

Well done! You've successfully completed the Wazuh Server tutorial. To remove the
model environment you created during this tutorial, use the following command.

```bash
juju destroy-model wazuh-tutorial
```