# Deploy the Wazuh Server charm for the first time

## What you’ll do
- Deploy the Wazuh Server charm.
- Integrate with the Wazuh Indexer charm.
- Integrate with the Wazuh Dashboard charm.
- Integrate with the self Signed X.509 Certificates charm.
- Integrate with the Traefik charm.

## Requirements

* A working station, e.g., a laptop, with amd64 architecture.
* Juju 3 installed and bootstrapped to an LXD controller. You can accomplish
this process by using a [Multipass](https://multipass.run/) VM as outlined in this guide: [How to manage your deployment](https://documentation.ubuntu.com/juju/3.6/howto/manage-your-deployment/). 
[note]
The [How to manage your deployment](https://documentation.ubuntu.com/juju/3.6/howto/manage-your-deployment/) tutorial provides documentation for both manual and automatic deployment management. You would have to follow the manual steps only to avoid installing MicroK8s in your setup.
[/note]
* A deployed Wazuh Indexer. For instructions to deploy the Wazuh Indexer, check [its documentation](https://charmhub.io/wazuh-indexer).
* A deployed Wazuh Dashboard. For instructions to deploy the Wazuh Dashboard, check [its documentation](https://charmhub.io/wazuh-dashboard).

:warning: When using a Multipass VM, make sure to replace IP addresses with the
VM IP in steps that assume you're running locally. To get the IP address of the
Multipass instance run ```multipass info my-juju-vm```.

## Set up Canonical Kubernetes

### Install Canonical Kubernetes

Install, bootstrap, and check the status of Canonical Kubernetes:

```bash
sudo snap install k8s --edge --classic
sudo k8s bootstrap
sudo k8s status --wait-ready
```

Once Canonical Kubernetes is up and running, enable the following core cluster features:

```bash
sudo k8s enable network dns load-balancer local-storage gateway
sudo k8s status --wait-ready
```

### Bootstrap a controller

Bootstrap the Juju controller:

```bash
juju add-k8s ck8s --client --context-name="k8s"
juju bootstrap ck8s
```

## Set up a tutorial model

To manage resources effectively and to separate this tutorial's workload from
your usual work, create a new model using the following command.

```bash
juju add-model wazuh-tutorial
```

## Deploy the Wazuh Server charm

Wazuh requires connections to Wazuh indexer, Traefik and a charm implementing the TLS certificates relation.
For this tutorial we will be using Self Signed X.509 Certificates.

### Deploy and integrate the charms

```bash
juju deploy wazuh-server
juju deploy self-signed-certificates
juju deploy traefik-k8s --trust
```

<!--
To connect the agents, you'll need to configure the agent password. For that,
create a secret and set it in the Wazuh server configuration:
```bash
juju add-secret agent-password value=<agent-password>
juju grant-secret agent-password wazuh-server
juju config wazuh-server agent-password=<secret-id>
```
where `<agent-password>` is the password you want to configure and`<secret-id>` is the ID of the secret containing the password.
-->

Run `juju status` to see the current status of the deployment. Wazuh server unit should be in `waiting status`.

Provide the integrations between the Wazuh Server and the other charms:
```bash
juju integrate wazuh-server self-signed-certificates
juju integrate wazuh-server traefik-k8s
juju integrate wazuh-server <indexer-offer-url>
juju integrate wazuh-server <dashboard-offer-url>
```

Note that `<indexer-offer-url>` and `<dashboard-offer-url>` are the Juju offers for the Wazuh Indexer and Dashboard, respectively,
which deployed in a machine model in another controller.


Monitor the deployment using `juju status` until the output looks similar to the following one:
```bash
SAAS             Status  Store                           URL
wazuh-indexer    active  juju-controller-lxd             admin/wazuh.wazuh-indexer
wazuh-dashboard  active  juju-controller-lxd             admin/wazuh.wazuh-dashboard

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