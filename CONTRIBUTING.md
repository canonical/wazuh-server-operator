# Contributing

To make contributions to this charm, you'll need a working [development setup](https://documentation.ubuntu.com/juju/latest/howto/manage-your-deployment/manage-your-deployment-environment/index.html).

## Developing

The code for this charm can be downloaded as follows:

```bash
git clone https://github.com/canonical/wazuh-server-operator
```

You can use the environments created by `tox` for development:

```shell
tox --notest -e unit
source .tox/unit/bin/activate
```

## Testing

This project uses `tox` for managing test environments. There are some pre-configured environments
that can be used for linting and formatting code when you're preparing contributions to the charm:

```shell
tox run -e fmt        # update your code according to linting rules
tox run -e lint       # code style
tox run -e static     # other checks such as `bandit` for security issues.
tox run -e unit       # unit tests
tox                   # runs 'format', 'lint', 'static' and 'unit' environments
```

### Integration tests

To run the integration tests, you need to:

- Build the charm.
- Build the rock.
- Add the rock to the Kubernetes registry.

#### Build charm

Build the charm in this git repository using:

```shell
charmcraft pack
```

#### Build rock

Build the rock using:

```shell
cd rock
rockcraft pack
```

#### Add rock to registry

The [Wazuh Server](https://github.com/canonical/wazuh-server-operator/tree/main/rockcraft.yaml) image needs to be pushed to MicroK8s for the tests to run. It should be tagged as `localhost:32000/wazuh-server:latest` so that Kubernetes knows how to pull them from the MicroK8s repository.

Note that the MicroK8s registry needs to be enabled using `microk8s enable registry`.

To add the image to the registry:

```shell
    skopeo --insecure-policy copy oci-archive:wazuh_server_1.0_amd64.rock docker-daemon:localhost:32000/wazuh-server:latest
```

#### Run the integration tests

You can run the tests with:

```shell
tox run -e integration -- --charm-file=wazuh-server_ubuntu-22.04-amd64.charm --wazuh-server-image localhost:5000/wazuh-server:latest
```

By default, this will create 3 `wazuh-indexer` nodes. This should be fine with 32 GB of RAM. If you have less, you can run a single node indexer with:

```shell
tox run -e integration -- --charm-file=wazuh-server_ubuntu-22.04-amd64.charm --wazuh-server-image localhost:5000/wazuh-server:latest --single-node-indexer
```

To get faster test results, you may want to reuse your integration environments. To do so, you can initially run:

```shell
tox run -e integration -- --charm-file=wazuh-server_ubuntu-22.04-amd64.charm --wazuh-server-image localhost:5000/wazuh-server:latest --single-node-indexer --model test-wazuh --keep-models
```

And then use the following command for the next runs:

```shell
tox run -e integration -- --charm-file=wazuh-server_ubuntu-22.04-amd64.charm --wazuh-server-image localhost:5000/wazuh-server:latest --single-node-indexer --model test-wazuh --keep-models --no-deploy
```

### Deploy

A typical deployment would look like:

```bash
# Create a model
juju add-model wazuh-server-dev
# Enable DEBUG logging
juju model-config logging-config="<root>=INFO;unit=DEBUG"
# Deploy the charm (assuming you're on amd64)
juju deploy ./wazuh_server_ubuntu-22.04-amd64.charm \
  --resource wazuh-server-image=localhost:32000/wazuh-server:latest
```
