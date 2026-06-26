#!/bin/bash

# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

# Pre-run script for integration tests.
# OpenSearch charms are deployed on lxd and Wazuh Server charm is deployed on Canonical K8S.

set -euo pipefail

TESTING_MODEL="$(juju switch)"

# Bootstrap the localhost (LXD) controller only if it doesn't already exist.
if ! juju show-controller localhost &>/dev/null; then
  echo "bootstrapping lxd juju controller"
  sudo lxd init --auto || true
  # Disable IPv6 on the LXD bridge so all containers get IPv4 addresses only.
  sudo lxc network set lxdbr0 ipv6.address none ipv6.dhcp false || true
  juju bootstrap localhost localhost
else
  echo "lxd juju controller already exists, skipping bootstrap"
fi

echo "Switching to testing model"
juju switch "$TESTING_MODEL"

# https://charmhub.io/opensearch/docs/t-set-up#set-parameters-on-the-host-machine
# Append only if not already set.
if ! grep -q "vm.max_map_count=262144" /etc/sysctl.conf; then
  sudo tee -a /etc/sysctl.conf > /dev/null <<EOT
vm.max_map_count=262144
vm.swappiness=0
net.ipv4.tcp_retries2=5
fs.file-max=1048576
EOT
fi

sudo sysctl -p
