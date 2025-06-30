# How to test your deployment

In this document, we describe the main tests to ensure your deployment is working properly.

All actions should be performed after your deployment is successful (all units and apps in `idle` state).

## Test the dashboard

First retrieve valid credentials:

- Go to the environment where your `wazuh-indexer` is deployed.
- Run `juju run data-integrator/leader get-credentials` and write down the `username` and `password`.

Then access the dashboard:

- Go to the environment where your `wazuh-dashboard` is deployed.
- Retrieve the leader IP address.
- Connect from your browser to `https://$leader_ip:5601`.
- Accept the security exception.
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
  - `wazuh-archives-*`

## Test logs processing

- TODO: we should describe here a setup where we send some logs from a rsyslog client and check that they reach the indexer and the dashboard

## Test your backups

- Go to the environment where your `wazuh-indexer` is deployed.
- Run `juju run wazuh-indexer-v5/leader create-backup` to check that you can create backups.
- Run `juju run wazuh-indexer-v5/leader create-backup` to check that backups are accessible.
