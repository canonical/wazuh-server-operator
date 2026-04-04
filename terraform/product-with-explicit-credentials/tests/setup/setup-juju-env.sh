#!/bin/bash
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

# Populates TF_VAR_* environment variables for the tests/setup Terraform configuration
# by reading Juju controller information from the local Juju client.
#
# Usage: source setup-juju-env.sh [<lxd-controller>] [<k8s-controller>]
#
# Defaults:
#   lxd-controller: concierge-lxd   (hosts wazuh-indexer and wazuh-dashboard models)
#   k8s-controller: concierge-k8s   (hosts wazuh-server model)

#set -euo pipefail

LXD_CONTROLLER="${1:-concierge-lxd}"
K8S_CONTROLLER="${2:-concierge-k8s}"

_get_addresses() {
    local controller="$1"
    juju show-controller "$controller" --format json \
        | python3 -c "
import json, sys
controller = sys.argv[1]
data = json.load(sys.stdin)
endpoints = data[controller]['details']['api-endpoints']
print(','.join(endpoints))
" "$controller"
}

_get_ca_cert() {
    local controller="$1"
    juju show-controller "$controller" --format json \
        | python3 -c "
import json, sys
controller = sys.argv[1]
data = json.load(sys.stdin)
print(data[controller]['details']['ca-cert'])
" "$controller"
}

_get_username() {
    local controller="$1"
    juju show-controller "$controller" --format json \
        | python3 -c "
import json, sys
controller = sys.argv[1]
data = json.load(sys.stdin)
user = data[controller].get('account', {}).get('user', 'admin')
# Strip the @local suffix if present
print(user.split('@')[0])
" "$controller"
}

_get_password() {
    local controller="$1"
    local accounts_file="${JUJU_DATA:-$HOME/.local/share/juju}/accounts.yaml"
    python3 -c "
import sys, yaml
controller = sys.argv[1]
accounts_file = sys.argv[2]
with open(accounts_file) as f:
    accounts = yaml.safe_load(f)
controllers = accounts.get('controllers', {})
if controller not in controllers:
    sys.exit(f'Controller {controller!r} not found in {accounts_file!r}')
password = controllers[controller].get('password', '')
if not password:
    sys.exit(f'No password stored for controller {controller!r} in {accounts_file!r}')
print(password)
" "$controller" "$accounts_file"
}

echo "Fetching info for LXD controller: $LXD_CONTROLLER"
LXD_ADDRESSES=$(_get_addresses "$LXD_CONTROLLER")
LXD_CA_CERT=$(_get_ca_cert "$LXD_CONTROLLER")
LXD_USERNAME=$(_get_username "$LXD_CONTROLLER")
LXD_PASSWORD=$(_get_password "$LXD_CONTROLLER")

echo "Fetching info for K8s controller: $K8S_CONTROLLER"
K8S_ADDRESSES=$(_get_addresses "$K8S_CONTROLLER")
K8S_CA_CERT=$(_get_ca_cert "$K8S_CONTROLLER")
K8S_USERNAME=$(_get_username "$K8S_CONTROLLER")
K8S_PASSWORD=$(_get_password "$K8S_CONTROLLER")

export TF_VAR_lxd_controller_addresses="$LXD_ADDRESSES"
export TF_VAR_lxd_ca_certificate="$LXD_CA_CERT"
export TF_VAR_lxd_username="$LXD_USERNAME"
export TF_VAR_lxd_password="$LXD_PASSWORD"

export TF_VAR_k8s_controller_addresses="$K8S_ADDRESSES"
export TF_VAR_k8s_ca_certificate="$K8S_CA_CERT"
export TF_VAR_k8s_username="$K8S_USERNAME"
export TF_VAR_k8s_password="$K8S_PASSWORD"

echo "Environment variables exported:"
echo "  TF_VAR_lxd_controller_addresses=$TF_VAR_lxd_controller_addresses"
echo "  TF_VAR_lxd_username=$TF_VAR_lxd_username"
echo "  TF_VAR_k8s_controller_addresses=$TF_VAR_k8s_controller_addresses"
echo "  TF_VAR_k8s_username=$TF_VAR_k8s_username"
