# Contributing

To make contributions to this charm, you'll need a working development setup with the following requirements met:
* Juju 3 installed and bootstrapped to an LXD controller. You can accomplish
this process by using a [Multipass](https://multipass.run/) VM as outlined in this guide: [How to manage your deployment](https://documentation.ubuntu.com/juju/3.6/howto/manage-your-deployment/). Note that this tutorial provides documentation for both manual and automatic deployment management. You would have to follow the manual steps only to avoid installing MicroK8s in your setup.
* Canonical Kubernetes installed and bootstrapped to Juju. This can be accomplished by following the [Setup Canonical Kubernetes](https://charmhub.io/wazuh-server/docs/tutorial-getting-started#p-38194-set-up-canonical-kubernetes) section in the getting started tutorial for Wazuh server.

## Set up Docker

Docker is required to upload rocks and test changes to the image locally. 

### Install Docker and set up add Docker's GPG key

```bash
sudo apt-get update
sudo apt-get install ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```

### Set up a local registry

Start a registry container:
```bash
sudo docker run -d -p 5000:5000 --restart always --name registry registry:2
```

Add the following configuration in `/etc/docker/daemon.json`. Change `ubuntu` to your host name:
```
{ "insecure-registries": ["ubuntu.local:5000"] }
```

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

The [Wazuh Server](https://github.com/canonical/wazuh-server-operator/tree/main/rockcraft.yaml) image needs to be pushed to Docker for the tests to run. It should be tagged as `localhost:5000/wazuh-server:latest` so that Kubernetes knows how to pull them from the Docker registry.

To add the image to the registry:

```shell
    skopeo --insecure-policy copy oci-archive:wazuh-server_1.0_amd64.rock docker://localhost:5000/wazuh-server:latest
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
  --resource wazuh-server-image=localhost:5000/wazuh-server:latest
```

## How to upgrade Wazuh version

The Wazuh product is deployed using three charms:
- `wazuh-server`: this repository.
- [`wazuh-indexer`](https://github.com/canonical/wazuh-indexer-operator/): a fork of [`opensearch-operator`](https://github.com/canonical/opensearch-operator) relying on [`opensearch-snap`](https://github.com/canonical/opensearch-snap)
- [`wazuh-dashboard`](https://github.com/canonical/wazuh-dashboard-operator/): a fork of [`opensearch-dashboards-operator`](https://github.com/canonical/opensearch-dashboards-operator) relying on [`opensearch-dashboards-snap`](https://github.com/canonical/opensearch-dashboards-snap)

To upgrade the Wazuh version, the snaps and charms must be updated in the following order:

1. `wazuh-indexer-snap`: merge upstream changes, then upgrade Wazuh version.
2. `wazuh-dashboard-snap`: merge upstream changes, then upgrade Wazuh version.
3. `wazuh-indexer-operator`: merge upstream changes, then upgrade Wazuh version.
4. `wazuh-dashboard-operator`: merge upstream changes, then upgrade Wazuh version.
5. `wazuh-server-operator`: upgrade Wazuh version.


> [!IMPORTANT]
> GitHub incorrectly shows that the forks are based on the `main` branch of the `opensearch` snaps and charms. It's a known issue when an upstream project renames its default branch after a fork and the fork doesn't. Unfortunately, the upstream branch cannot be updated on the fork.
> They are based on the `2/edge` branch.

### How to merge upstream changes

This is the generic approach to merge upstream changes using the example for `wazuh-indexer-snap`. Specific details for each repository are provided in the following sections.

#### Prepare

- Clone the repository: `git clone https://github.com/canonical/wazuh-indexer-snap.git`
- Prepare your working branch: `git checkout -b chore/merge_upstream`
- To ensure that no external dependency is breaking the CI, it's safer to run it before changing anything. You can trigger the CI with an empty commit: `git commit --allow-empty -m 'Trigger CI' && git push -u origin chore/merge_upstream`.
- Fetch the upstream branch:

```shell
git remote add upstream https://github.com/canonical/opensearch-dashboards-operator.git
git fetch upstream 2/edge
```

#### Merge

Start the merge with `git merge upstream/2/edge`.

There will be conflicts, try to minimize them for future merges :

- Reflect all changes, even comments.
- Propose changes upstream that would simplify future merges (use of constants instead of hard coded strings for instance).

Here are few tips to fix the conflicts:

- Keep the changes where `opensearch` is replaced by `wazuh`.
- Keep the changes referring to Wazuh channels, revisions or versions.
- Keep the changes explicitly mentioning `wazuh` (including comments).

When all conflicts are resolved and the merge is completed, run the CI to ensure all tests pass.

#### Extra checks

See if the skipped tests are still relevant. You can list them with `grep -ri 'skip.*wazuh' tests/`.

### How to upgrade Wazuh version

All repositories must be updated to the same Wazuh version.

For Wazuh, we currently have a track for the minor version (e.g. `4.11/edge`) as we have seen some breaking changes between minor versions in the past. We may switch back to a track per major version in the future (e.g. `5/edge`).

## `wazuh-indexer-snap`

- Look for references to the previous version: `grep -r 4.11`.
- Update them to the version you want to deploy.

## `wazuh-dashboard-snap`

- Look for references to the previous version: `grep -r 4.11`.
- Update them to the version you want to deploy.
- Update `workflows/ci.yaml`, to use the latest `wazuh-indexer` release.

If the Wazuh team has implemented a variable to refer to the Wazuh configuration, you may replace the last four lines in `snapcraft.yaml` which are temporary workarounds.

## `wazuh-indexer-operator`

- Look for references to the previous version: `grep -r 4.11`.
- Update them to the version you want to deploy.
- Update `OPENSEARCH_SNAP_REVISION` in `lib/charms/opensearch/v0/constants_charm.py`

## `wazuh-dashboard-operator`

- Look for references to the previous version: `grep -r 4.11`.
- Update them to the version you want to deploy.
- Update `OPENSEARCH_DASHBOARDS_SNAP_REVISION` in `src/literals.py`.

## `wazuh-server-operator`

- Look for references to the previous version: `grep -r 4.11`.
- Update them to the version you want to deploy.
