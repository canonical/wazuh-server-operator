#!/bin/bash
#
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.
#
# When run with --single-index-node parameter, integration tests need 
# opensearch to be configured in a specific way.
#

MACHINE_MODEL="$1"
set -euo pipefail

CURRENT_MODEL="$(juju switch)"

date
sleep 2
juju switch "$MACHINE_MODEL"
if ! juju show-application wazuh-indexer &>/dev/null; then
	echo "No wazuh-indexer found (are you on the right model?)"
	exit 1
fi

echo "Fetching admin password through secrets as the get-password action would fail if the charm is blocked"
PASSWORD=$(for secret in $(juju secrets | tail +2 | awk '{print $1}'); do juju show-secret "$secret" --reveal; done | awk '/admin-password:/{print $2}')
CREDS="admin:$PASSWORD"

echo "Retrieving unit IP"
IP=$(juju show-unit wazuh-indexer/0 | grep 'public-address:' | awk '{print $2}')

echo "Updating cluster to not have replicates for new indices"
REQ='{ "index_patterns": ["*"], "template": { "settings": { "number_of_replicas": 0 } } }'
curl -k -u "$CREDS" -X PUT "https://$IP:9200/_index_template/charmed-index-tpl" -H "Content-Type: application/json" -d "$REQ"
echo

echo "Updating existing indices"
for index in $(curl -k -u "$CREDS" "https://$IP:9200/_cat/indices"  | awk '{print $3}' | grep -v .opendistro_security); do
	echo "$index"
	curl -k -u "$CREDS" -X PUT "https://$IP:9200/$index/_settings" -H "Content-Type: application/json" -d '{ "index": { "number_of_replicas": 0 } }'
	echo
done

echo "Waiting 5s for health to turn green"
sleep 5
curl -k -u "$CREDS" "https://$IP:9200/_cat/indices" -H "Content-Type: application/json"

sleep 2
juju switch "$CURRENT_MODEL"
date
