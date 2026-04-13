#!/bin/bash

# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

# Pre-run script for terraform test operator-workflows action.

set -euo pipefail

# https://charmhub.io/opensearch/docs/t-set-up#set-parameters-on-the-host-machine
sudo tee -a /etc/sysctl.conf > /dev/null <<EOT
vm.max_map_count=262144
vm.swappiness=0
net.ipv4.tcp_retries2=5
fs.file-max=1048576
EOT

sudo sysctl -p

terraform init
# Prevent destroy would block the teardown
sed -i .terraform/modules/wazuh_indexer/terraform/charm/main.tf -e 's/prevent_destroy = true/prevent_destroy = false/'
