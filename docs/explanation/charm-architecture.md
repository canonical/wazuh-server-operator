# Charm architecture

Wazuh is a security platform that provides unified XDR and SIEM protection for endpoints and cloud workloads. The solution is composed of a single universal agent and three central components: the Wazuh Server, the Wazuh indexer, and the Wazuh dashboard. This charm corresponds to the Wazuh Server.

The charm design leverages the [sidecar](https://kubernetes.io/blog/2015/06/the-distributed-system-toolkit-patterns/#example-1-sidecar-containers) pattern to allow multiple containers in each pod
with [Pebble](https://juju.is/docs/sdk/pebble) running as the workload
container’s entrypoint.

Pebble is a lightweight, API-driven process supervisor that is responsible for
configuring processes to run in a container and controlling those processes
throughout the workload lifecycle.

Pebble `services` are configured through [layers](https://github.com/canonical/pebble#layer-specification),
and the following containers each represent a layer that forms the effective
Pebble configuration, or `plan`:

1. A [Wazuh Server](https://www.nginx.com/) container itself, which
has Wazuh Server installed and configured.

As a result, if you run a `kubectl get pods` on a namespace named for the Juju
model you've deployed the Synapse charm into, you'll see something like the
following:

```bash
NAME                             READY   STATUS    RESTARTS   AGE
wazuh-server-0                    2/2     Running   0         6h4m
```

This shows there are 2 containers - the one named above, as well as a container
for the charm code itself.

All containers will have the command `/charm/bin/pebble`. Pebble is responsible for service management, as explained above.
processes startup as explained above.

## OCI images

We use [Rockcraft](https://canonical-rockcraft.readthedocs-hosted.com/en/latest/)
to build OCI Image for Wazuh Server.
The image is defined in [Wazuh Server rock](https://github.com/canonical/wazuh-server-operator/tree/main/rockcraft.yaml) and is published to [Charmhub](https://charmhub.io/), the official repository
of charms.
This is done by publishing a resource to Charmhub as described in the
[Juju SDK How-to guides](https://juju.is/docs/sdk/publishing).

### Wazuh Server

Wazuh Server is an application controlled by the `/var/ossec/bin/wazuh-control` script.

Wazuh Server listens on ports 1514, 1515 and 55000; the first two serving the services for the agents to connect, and the last one serving the API.

The workload that this container is running is defined in the [Wazuh Server rock](https://github.com/canonical/wazuh-server-operator/tree/main/rockcraft.yaml).

## Integrations

See [Integrations](https://charmhub.io/synapse/docs/reference/integrations).

## Charm code overview

The `src/charm.py` is the default entry point for a charm and has the
`WazuhOperatorCharm` Python class which inherits from the `CharmBase`.

CharmBase is the base class from which all Charms are formed, defined by [Ops](https://juju.is/docs/sdk/ops)
(Python framework for developing charms).

See more information in [Charm](https://juju.is/docs/sdk/constructs#heading--charm).

The `__init__` method guarantees that the charm observes all events relevant to
its operation and handles them.

Take, for example, when a configuration is changed by using the CLI.

1. User runs the command
```bash
juju config wazuh-server custom-config-repository=git+hhtp://github.com/sample-repository.git
```
2. A `config-changed` event is emitted
3. Event handlers are defined in the charm's framework observers. An example looks like the following:
```python
self.framework.observe(self.on.config_changed, self._on_config_changed)
4. The method `_on_config_changed` will take the necessary actions. 
The actions include waiting for all the relations to be ready and then configuring
the container.
