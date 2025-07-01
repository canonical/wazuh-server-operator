# How to test your deployment

In this document, we describe the main tests to ensure your deployment is working properly.

All actions should be performed after your deployment is successful: all units and apps should be in active and idle state.

## Test the dashboard

First retrieve valid credentials:

- Go to the environment where your `wazuh-indexer` is deployed: `juju switch <wazuh-indexer-model>`.
- Get the `username` and `password` with the following command:

```shell
juju run data-integrator/leader get-credentials --format=json | \
jq -r '.[].results.opensearch | "username: \(.username)\npassword: \(.password)"'
```

### Access the dashboard

- Go to the environment where your `wazuh-dashboard` is deployed: `juju switch <wazuh-dashboard-model>`.
- Retrieve one of the units public IP address.
- Connect from your browser to `https://<public-ip>:5601`.
- If you deployed Wazuh with a self-signed-certificate, you will have to accept the security exception.
- You should see "Wazuh... loading" for a few seconds and then be prompted for credentials.
- Enter the `username` and `password` from the first step.
- You should see "Wazuh... loading" again, and then you should have access to the dashboard.

Ensure that eveything is working properly:

- Unfold the navigation bar with the icon on the top-left corner.
- Go to "Dashboard management > Server APIs": everything should be green.
- Go to "Explore > Discover", in the top-left drop-down, check that you see the 4 following indexes:
  - `wazuh-alerts-*`
  - `wazuh-monitoring-*`
  - `wazuh-statistic-*`
  - `wazuh-archives-*` (you will need to send some logs first, see next section)

## Test logs processing

First, let's monitor the logs:

- Go to the environment where your `wazuh-server` is deployed.
- Open a shell on the leader unit `juju ssh --container wazuh-server wazuh-server/leader`.
- Monitor the logs: `tail -f /var/log/collectors/rsyslog/rsyslog.log`

In parallel, send some traffic:

- Fetch your public IP for `rsyslog`. This is the external IP from the `kubectl get services traefik-k8s-lb` output.
- Send some data to the public IP obtained from the previous step: `echo "Hi" | openssl s_client -connect <public-ip>:6514`.
- You should see some logs on the server, especially: `... did not provide a certificate, not permitted to talk to it ...`

If everything is ok, you should be able to send logs with a certificate issued by the CA configured in `logs-ca-cert`.

- Run the following command on your client: `echo "TEST123" | openssl s_client -connect <public-ip>:6514 -cert good-client.crt -key good-client.key`
- You should see "TEST123" in the logs on the server.

After landing in `rsyslog.log`, your log should be processed by Wazuh. To confirm it, look in `/var/ossec/logs/archives/archives.log` where you should see them.

From there, they should be processed by `filebeat` and sent to `wazuh-indexer`. To check:

- Go to the Wazuh dashboard with your browser.
- Go to "Indexer management > Dev Tools".
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

- Go to the environment where your `wazuh-indexer` is deployed.
- Run `juju run wazuh-indexer/leader create-backup` to check that you can create backups. It should return `status: Backup is running.`.
- Run `juju run wazuh-indexer/leader list-backups` to check that backups are accessible. It should return at least a backup timestamp with a `success` status.
