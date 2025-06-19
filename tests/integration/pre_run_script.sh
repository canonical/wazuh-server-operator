#!/bin/bash

# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

# Pre-run script for integration test operator-workflows action.
# https://github.com/canonical/operator-workflows/blob/main/.github/workflows/integration_test.yaml

# OpenSearch charms are deployed on lxd and Wazuh Server charm is deployed on Canonical K8S.

set -euo pipefail

TESTING_MODEL="$(juju switch)"

# lxd should be install and init by a previous step in integration test action.
echo "bootstrapping lxd juju controller"
juju bootstrap localhost localhost

echo "Switching to testing model"
juju switch "$TESTING_MODEL"

# https://charmhub.io/opensearch/docs/t-set-up#set-parameters-on-the-host-machine
sudo tee -a /etc/sysctl.conf > /dev/null <<EOT
vm.max_map_count=262144
vm.swappiness=0
net.ipv4.tcp_retries2=5
fs.file-max=1048576
EOT

sudo sysctl -p

