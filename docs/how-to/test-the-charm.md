# How to test the charm

The integration tests for this charm are designed to be run by
[canonical/operator-workflows/integration_test](https://github.com/canonical/operator-workflows/blob/main/.github/workflows/integration_test.yaml).

To run them locally, your environment should be as similar as possible to the
one created on the GitHub actions runner.

## Development environment setup

Starting from a fresh Ubuntu 24.04 LTS (Noble Numbat) virtual machine, follow
these instructions:

[note]
`sudo` has been omitted from all commands, though many of the below
commands require root access.
[/note]

### Clone the repository

```bash
git clone git+ssh://git@github.com:canonical/wazuh-server-operator.git ~/wazuh-server-operator
cd wazuh-sever-operator
```

### Install Charmcraft

```bash
snap install charmcraft --classic
```

### Install tox

```bash
if ! (which pipx &> /dev/null); then
    apt update && apt install -y pipx
    pipx ensurepath
    export PATH="${PATH}:${HOME}/.local/bin"
fi
pipx install tox
```

### Install LXD

```bash
snap install lxd
newgrp lxd
lxd init --auto
```

<!-- vale Canonical.007-Headings-sentence-case = NO -->
### Install Canonical Kubernetes
<!-- vale Canonical.007-Headings-sentence-case = YES -->

```bash
snap install k8s --classic
```

[note]
If you encounter an error running the next command, log out and log back
in.
[/note]

```bash
cat << EOF | k8s bootstrap --file -
containerd-base-dir: /opt/containerd
EOF

k8s enable network dns local-storage gateway
k8s status --wait-ready --timeout 5m

mkdir -p ~/.kube
k8s config > ~/.kube/config
```

#### Configure Kubernetes load-balancer

The following commands will configure the Kubernetes `metallb` plugin to use IP addresses
between .225 and .250 on the machine's 'real' subnet. If this creates IP
address conflict(s) in your environment, please modify the commands.

```bash
k8s enable load-balancer

IPADDR=$(ip -4 -j route get 2.2.2.2 | jq -r '.[] | .prefsrc')
LB_FIRST_ADDR="$(echo "${IPADDR}" | awk -F'.' '{print $1,$2,$3,225}' OFS='.')"
LB_LAST_ADDR="$(echo "${IPADDR}" | awk -F'.' '{print $1,$2,$3,250}' OFS='.')"
LB_ADDR_RANGE="${LB_FIRST_ADDR}-${LB_LAST_ADDR}"

k8s set \
  load-balancer.cidrs=$LB_ADDR_RANGE \
  load-balancer.enabled=true \
  load-balancer.l2-mode=true
```

### Install kubectl

```bash
snap install kubectl --classic
```

### Install Juju

```bash
snap install juju
```

### Bootstrap the Kubernetes controller

```bash
juju bootstrap k8s
```

### Run the pre-run script

```bash
bash -xe ~/wazuh-server-operator/tests/integration/pre_run_script.sh
```

<!-- vale Canonical.007-Headings-sentence-case = NO -->
### (Optional) Install rock dependencies
<!-- vale Canonical.007-Headings-sentence-case = YES -->

If you anticipate changing the rock container image, follow these additional
steps:

#### Install Rockcraft

```bash
snap install rockcraft --classic
```

#### Install and configure Docker

```bash
apt install -y docker.io
echo '{ "insecure-registries": ["localhost:5000"] }' > /etc/docker/daemon.json
systemctl restart docker
```

#### Install skopeo

```bash
apt install -y skopeo
```

## Testing

This project uses `tox` for managing test environments. There are some
pre-configured environments that can be used for linting and formatting code
when you're preparing contributions to the charm:

* ``tox``: Executes all of the basic checks and tests (``lint``, ``unit``, ``static``, and ``format``).
* ``tox run -e fmt``: Update your code according to linting rules.
* ``tox run -e lint``: Runs a range of static code analysis to check the code.
* ``tox run -e static``: Runs other checks such as ``bandit`` for security issues.
* ``tox run -e unit``: Runs unit tests.

## Integration testing

Integration testing is a multi-step process that requires:

1. Building the charm
1. (Optionally) building the rock
1. Running the tests

#### Build the charm

```bash
cd ~/wazuh-server-operator
charmcraft pack
```

<!-- vale Canonical.007-Headings-sentence-case = NO -->
#### (Optional) Build the rock
<!-- vale Canonical.007-Headings-sentence-case = YES -->

If you have not made any changes to the rock, you do not need to rebuild it.

The GitHub integration test workflow builds and uploads the rock to `ghcr.io`
for its own tests. If you haven't changed the rock since the last GitHub action
run, you might as well reuse that artifact.

Check
[here](https://github.com/canonical/wazuh-server-operator/pkgs/container/wazuh-server)
for the latest build's tag.

If you **did** change the rock configuration:

```bash
cd ~/wazuh-server-operator/rock
rockcraft pack
```

Upload the rock into a local registry:

```bash
docker run -d -p 5000:5000 --restart always --name registry registry:2
skopeo --insecure-policy copy --dest-tls-verify=false \
    oci-archive:wazuh-server_1.0_amd64.rock \
    docker://localhost:5000/wazuh-server:latest
```

#### Set the container location

If you rebuilt the rock:

```bash
export IMAGE_URL="localhost:5000/wazuh-server:latest"
```

If you did not rebuild the rock:

```bash
# find latest tag here:
# https://github.com/canonical/wazuh-server-operator/pkgs/container/wazuh-server
export IMAGE_URL="ghcr.io/canonical/wazuh-server:a063aca515693126206e4dfa6ba6eba4bac43698-_1.0_amd64"
```

#### Run tests

##### With three `wazuh-indexer` nodes

_minimum 32 GB of RAM suggested_

```bash
tox run -e integration -- \
    --charm-file=wazuh-server_ubuntu-22.04-amd64.charm \
    --wazuh-server-image $IMAGE_URL \
    --controller k8s --model test-wazuh
```

##### With a single `wazuh-indexer` node

```bash
tox run -e integration -- \
    --charm-file=wazuh-server_ubuntu-22.04-amd64.charm \
    --wazuh-server-image $IMAGE_URL \
    --single-node-indexer \
    --controller k8s --model test-wazuh
```

##### Reuse environments

To get faster test results over multiple iterations you may want to reuse your
integration environments. To do so, you can initially run:

```bash
tox run -e integration -- \
    --charm-file=wazuh-server_ubuntu-22.04-amd64.charm \
    --wazuh-server-image $IMAGE_URL \
    --single-node-indexer --keep-models \
    --controller k8s --model test-wazuh
```

For subsequent runs:

```bash
tox run -e integration -- \
    --charm-file=wazuh-server_ubuntu-22.04-amd64.charm \
    --wazuh-server-image $IMAGE_URL \
    --single-node-indexer --keep-models \
    --controller k8s --model test-wazuh \
    --no-deploy
```
