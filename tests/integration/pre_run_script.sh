#!/bin/bash

# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

# Pre-run script for integration test operator-workflows action.
# https://github.com/canonical/operator-workflows/blob/main/.github/workflows/integration_test.yaml

# OpenSearch charms are deployed on lxd and Wazuh server charm is deployed on microk8s.

TESTING_MODEL="$(juju switch)"

# lxd should be install and init by a previous step in integration test action.
echo "bootstrapping lxd juju controller"
# Change microk8s default file limits
sed -i 's/ulimit -n 65536 || true/ulimit -n 655360 || true/g' /var/snap/microk8s/current/args/containerd-env
sudo snap restart microk8s
sg snap_microk8s -c "microk8s status --wait-ready"
sg snap_microk8s -c "juju bootstrap localhost localhost"

echo "Switching to testing model"
sg snap_microk8s -c "juju switch $TESTING_MODEL"


IPADDR=$(ip -4 -j route get 2.2.2.2 | jq -r '.[] | .prefsrc')
sudo microk8s enable metallb:$IPADDR-$IPADDR

# https://charmhub.io/opensearch/docs/t-set-up#set-parameters-on-the-host-machine
sudo tee -a /etc/sysctl.conf > /dev/null <<EOT
vm.max_map_count=262144
vm.swappiness=0
net.ipv4.tcp_retries2=5
fs.file-max=1048576
EOT

sudo sysctl -p

# Launch a wazuh agent
MICROK8s_IP = $(ip route | grep default | cut -d ' ' -f3)
sudo snap install multipass
multipass launch --name wazuh-agent
multipass exec wazuh-agent -- curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg
multipass exec wazuh-agent -- echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list
multipass exec wazuh-agent -- apt update
multipass exec wazuh-agent -- apt install -y gnupg apt-transport-https
multipass exec wazuh-agent -- curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add -
multipass exec wazuh-agent -- WAZUH_MANAGER="10.0.0.2" apt-get install wazuh-agentecho "deb https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list
echo "$MICROK8s_IP wazuh-server.local" >> /etc/hosts
WAZUH_MANAGER="wazuh-server.local" apt-get install wazuh-agent
