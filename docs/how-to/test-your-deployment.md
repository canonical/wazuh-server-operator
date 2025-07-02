# How to test your deployment

In this document, we describe the main tests to ensure your deployment is working properly.

All actions should be performed after your deployment is successful.
A successful deployment is one where all units and apps are in active and idle state.

## Test the dashboard

### Retrieve dashboard credentials

- Go to the model where your `wazuh-indexer` is deployed: `juju switch <wazuh-indexer-model>`.
- Get the `username` and `password` with the following command:

```shell
juju run data-integrator/leader get-credentials --format=json | \
  jq -r '.[].results.opensearch | "username: \(.username)\npassword: \(.password)"'
```

### Access the dashboard

- Go to the model where your `wazuh-dashboard` is deployed: `juju switch <wazuh-dashboard-model>`.
- Retrieve the public IP address for one of the units.

```
juju status wazuh-dashboard --format=json | \
  jq -r '.applications["wazuh-dashboard"].units | to_entries[0].value["public-address"]'
```

[note]
If you deployed Wazuh with a self-signed-certificate, you will have to accept a security exception in your browser in the following step.
[/note]

- Connect from your browser to `https://<public-ip>:5601`.
- You should see "Wazuh... loading" for a few seconds followed by a prompt for credentials.
- Enter the `username` and `password` from the first step.
- You should see "Wazuh... loading" again, and then you should have access to the dashboard.

### Verify Wazuh is working properly

- Unfold the navigation bar with the icon on the top-left corner.
- Go to `Dashboard management > Server APIs`. Your `wazuh` cluster should be reported as "Online".
- Go to `Explore > Discover`. In the top-left drop-down, check that you see the 4 following indexes:
  - `wazuh-alerts-*`
  - `wazuh-monitoring-*`
  - `wazuh-statistic-*`
  - `wazuh-archives-*` 
  
[note]
You will need to send some logs first to see `wazuh-archives-*` listed in the `Discover` section. See the next section for more details.
[/note]

## Test the logs

First, let's monitor the logs:

- Go to the model where your `wazuh-server` is deployed: `juju switch <wazuh-server-model>`
- Open a shell on the leader unit:
```
juju ssh --container wazuh-server wazuh-server/leader
```
- Monitor the logs: `tail -f /var/log/collectors/rsyslog/rsyslog.log`

In parallel, open another terminal to send some traffic to Wazuh:

- Fetch your public IP for `rsyslog`:
```shell
kubectl get svc traefik-k8s-lb -o jsonpath='{.status.loadBalancer.ingress[0].ip}'
```
- Send some data to the public IP obtained from the previous step:

```shell
echo "Hi" | openssl s_client -connect <public-ip>:6514
```

- You should see some logs on the server, especially: `... did not provide a certificate, not permitted to talk to it ...`

You should now be able to send logs with a certificate issued by the CA configured in `logs-ca-cert`:

```shell
echo "TEST123" | openssl s_client -connect $your_ip:6514 -cert good-client.crt -key good-client.key
```

You should see `TEST123` in the logs on the server.

After landing in `rsyslog.log`, your log should be processed by Wazuh. To confirm this, run `cat /var/ossec/logs/archives/archives.log | grep "TEST123"`.

From there, they should be processed by `filebeat` and `filebeat` will send them to `wazuh-indexer`. To check:

- Go to the Wazuh dashboard with your browser.
- Go to `Indexer management > Dev Tools`.
- Enter the following query: 

```
GET wazuh-archives-*/_search
{
  "query": {
    "query_string": {
      "query": "TEST123"
    }
  }
}
```

- Run the query. It should return at least one document.

When you have some logs available, you can configure the `index-pattern` as described in [Wazuh's documentation](https://documentation.wazuh.com/current/user-manual/wazuh-indexer/wazuh-indexer-indices.html#the-wazuharchives-indices) to see them in the "Discover" page.

## Test the backups

### Create a backup

- Go to the model where your `wazuh-indexer` is deployed.
- Run `juju run wazuh-indexer/leader create-backup` to check that you can create backups. It should return `status: Backup is running.`.
- Run `juju run wazuh-indexer/leader list-backups` to check that backups are accessible. It should return at least a backup timestamp with a `success` status:

```text
Running operation 174 with 1 task
  - task 175 on unit-wazuh-indexer-1

Waiting for task 175...
backups: |1-
   backup-id           | backup-status
  ------------------------------------
  2025-06-30T12:28:27Z | success
```

### Restore a backup

Run `juju run wazuh-indexer/leader restore backup-id="<backup-id-from-the-list>"`.
You should get something like:

```test
Running operation 182 with 1 task
  - task 183 on unit-wazuh-indexer-1

Waiting for task 183...
backup-id: "2025-06-30T12:28:27Z"
closed-indices: '{''.wazuh-dashboard'', ''wazuh-statistics-2025.27w'', ''.plugins-ml-config'',
  ''.kibana_1'', ''wazuh-monitoring-2025.26w'', ''.opensearch-sap-log-types-config'',
  ''placeholder'', ''wazuh-archives-4.x-2025.06.30'', ''wazuh-monitoring-2025.27w'',
  ''.kibana_244217601_opensearchclient527_1'', ''wazuh-statistics-2025.26w'', ''.ql-datasources'',
  ''wazuh-alerts-4.x-2025.06.30''}'
status: Restore is complete
```
