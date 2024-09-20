#!/bin/bash

# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

IPADDR=$(ip -4 -j route get 2.2.2.2 | jq -r '.[] | .prefsrc')

sudo snap install multipass
multipass launch --name wazuh-agent
multipass exec wazuh-agent -- sudo bash -c "curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg"
multipass exec wazuh-agent -- sudo bash -c "echo 'deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main' | tee -a /etc/apt/sources.list.d/wazuh.list"
multipass exec wazuh-agent -- sudo apt update
multipass exec wazuh-agent -- sudo apt install -y gnupg apt-transport-https
multipass exec wazuh-agent -- sudo bash -c "curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add -"
multipass exec wazuh-agent -- sudo bash -c "echo $IPADDR wazuh-server.local >> /etc/hosts"
multipass exec wazuh-agent -- sudo bash -c "WAZUH_MANAGER=$IPADDR apt-get install wazuh-agent"
multipass exec wazuh-agent -- sudo systemctl daemon-reload
multipass exec wazuh-agent -- sudo systemctl enable wazuh-agent
multipass exec wazuh-agent -- sudo systemctl start wazuh-agent
