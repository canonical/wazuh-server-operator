#!/bin/bash

# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

# Pre-run script for integration tests.
# OpenSearch charms are deployed on lxd and Wazuh Server charm is deployed on Canonical K8S.

set -euo pipefail

# https://charmhub.io/opensearch/docs/t-set-up#set-parameters-on-the-host-machine
# Applied temporarily — no reboot expected.
sudo sysctl -w vm.max_map_count=262144
sudo sysctl -w vm.swappiness=0
sudo sysctl -w net.ipv4.tcp_retries2=5
sudo sysctl -w fs.file-max=1048576
