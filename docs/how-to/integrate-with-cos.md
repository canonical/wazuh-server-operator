# How to integrate with Canonical Observability Stack

## Deploy COS lite
Create a Juju model and deploy the Canonical Observability Stack bundle [cos-lite](https://charmhub.io/topics/canonical-observability-stack) to this model:

```bash
juju add-model cos-lite
juju deploy cos-lite --trust
```

## Expose the application relation endpoints
Once all the COS Lite applications are deployed and settled down (you can monitor this by using `juju status --watch 2s`), expose the relation points for Prometheus, Loki and Grafana:

```bash
juju offer prometheus:metrics-endpoint
juju offer loki:logging
juju offer grafana:grafana-dashboard
```

Validate that the offers have been successfully created by running:

```bash
juju find-offers cos-lite
```

You should see something similar to the output below:

```bash
Store                 URL                        Access  Interfaces
tutorial-controller  admin/cos-lite.loki        admin   loki_push_api:logging
tutorial-controller  admin/cos-lite.prometheus  admin   prometheus_scrape:metrics-endpoint
tutorial-controller  admin/cos-lite.grafana     admin   grafana_dashboard:grafana-dashboard
```

## Integrate the Wazuh server

Switch back to the charm model and integrate your charm with the exposed endpoints:

```bash
juju switch <Wazuh server charm model>
juju integrate wazuh-server admin/cos-lite.grafana
juju integrate wazuh-server admin/cos-lite.loki
juju integrate wazuh-server admin/cos-lite.prometheus
```

Ensure that Wazuh server and the COS Lite applications have settled down (you can monitor this by using `juju status --watch 2s`).

Obtain the Grafana dashboard credentials by running the `get-admin-password` action:

```bash
juju switch cos-lite
juju run grafana/0 get-admin-password
```

This action returns the URL and the admin password to access the Wazuh server dashboard. Now, on your host machine, open a web browser, enter the Grafana URL, and use the username “admin” and your Grafana password to log in. Under **Home > Dashboards**, you should be able to see the Wazuh server dashboard listed.

This integrates your application with Prometheus, Loki, and Grafana.
