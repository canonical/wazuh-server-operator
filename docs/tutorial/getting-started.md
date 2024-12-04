# Deploy the Wazuh server charm for the first time

## What you’ll do

## Requirements

* A working station, e.g., a laptop, with amd64 architecture.
* Juju 3 installed and bootstrapped to a MicroK8s and to an LXD controller. You can accomplish
this process by using a [Multipass](https://multipass.run/) VM as outlined in this guide: [Set up / Tear down your test environment](https://juju.is/docs/juju/set-up--tear-down-your-test-environment)

:warning: When using a Multipass VM, make sure to replace IP addresses with the
VM IP in steps that assume you're running locally. To get the IP address of the
Multipass instance run ```multipass info my-juju-vm```.

## Set up a Tutorial Model

To manage resources effectively and to separate this tutorial's workload from
your usual work, create a new model using the following command.

```
juju add-model wazuh-tutorial
```

## Deploy the Wazuh server charm
Synapse requires connections to Wazuh indexer, Traefik and a charm implementing the TLS certificates relation,
for this tutorial we will be using Self Signed X.509 Certificates. Deploy all these charm applications.

### Deploy and integrate the charms


## Clean up the Environment

Well done! You've successfully completed the Wazuh server tutorial. To remove the
model environment you created during this tutorial, use the following command.

```
juju destroy-model wazuh-tutorial
```