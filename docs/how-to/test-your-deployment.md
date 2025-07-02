# How to test your deployment

In this document, we describe the main tests to ensure your deployment is working properly.

All actions should be performed after your deployment is successful: all units and apps should be in active and idle state.

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
- Retrieve one of the units' public IP address.

```
juju status wazuh-dashboard --format=json | \
  jq -r '.applications["wazuh-dashboard"].units | \
  to_entries[0].value["public-address"]'
```

> [!NOTE]
> If you deployed Wazuh with a self-signed-certificate, you will have to accept a security exception in your browser.

- Connect from your browser to `https://<public-ip>:5601`.
- You should see "Wazuh... loading" for a few seconds and then be prompted for credentials.
- Enter the `username` and `password` from the first step.
- You should see "Wazuh... loading" again, and then you should have access to the dashboard.

### Verify Wazuh is working properly

- Unfold the navigation bar with the icon on the top-left corner.
- Go to "Dashboard management > Server APIs": your `wazuh` cluster should be reported as "Online".
- Go to `Explore > Discover`, in the top-left drop-down, check that you see the 4 following indexes:
  - `wazuh-alerts-*`
  - `wazuh-monitoring-*`
  - `wazuh-statistic-*`
  - `wazuh-archives-*` 
  
> [!NOTE]
> You will need to send some logs first to see `wazuh-archives-*` listed in the `Discover` section. See the next section for more details.

## Test logs processing

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

After landing in `rsyslog.log`, your log should be processed by Wazuh. To confirm the same, run `cat /var/ossec/logs/archives/archives.log | grep "TEST123"` to verify if the log is processed.

From there, they should be processed by `filebeat` and sent to `wazuh-indexer`. To check:

- Go to the Wazuh dashboard with your browser.
- Go to `Indexer management > Dev Tools`.
- Enter the following query (update with your test string if necessary): 

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

- Run the query.
- It should return at least one document.

When you have some logs available, you can configure the `index-pattern` as described in [Wazuh's documentation](https://documentation.wazuh.com/current/user-manual/wazuh-indexer/wazuh-indexer-indices.html#the-wazuharchives-indices) to see them in the "Discover" page.

## Test your backups

- Go to the model where your `wazuh-indexer` is deployed.
- Run `juju run wazuh-indexer/leader create-backup` to check that you can create backups. It should return `status: Backup is running.`.
- Run `juju run wazuh-indexer/leader list-backups` to check that backups are accessible. It should return at least a backup timestamp with a `success` status:

```text
$ juju run wazuh-indexer/1 list-backups
Running operation 174 with 1 task
  - task 175 on unit-wazuh-indexer-1

Waiting for task 175...
backups: |1-
   backup-id           | backup-status
  ------------------------------------
  2025-06-30T12:28:27Z | success
```
