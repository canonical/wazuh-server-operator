#!/bin/bash

# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

# Pre-run script for integration test operator-workflows action.
# https://github.com/canonical/operator-workflows/blob/main/.github/workflows/integration_test.yaml

# Jenkins machine agent charm is deployed on lxd and Jenkins-k8s server charm is deployed on
# microk8s.

# lxd should be install and init by a previous step in integration test action.
echo "bootstrapping lxd juju controller"
sg snap_microk8s -c "microk8s status --wait-ready"
sg snap_microk8s -c "juju bootstrap localhost localhost"

# https://charmhub.io/opensearch/docs/t-set-up#set-parameters-on-the-host-machine
sudo tee -a /etc/sysctl.conf > /dev/null <<EOT
vm.max_map_count=262144
vm.swappiness=0
net.ipv4.tcp_retries2=5
fs.file-max=1048576
EOT

sudo sysctl -p
