# How to perform a minor upgrade

**Example**: Wazuh 4.9 -> Wazuh 4.10.

```{Important}
Workload's versions are pinned in the charms. Not automatic upgrades will happen if not triggered at the charm level.
```

## Wazuh Server

The Wazuh server has a stateless workload, and can safely be upgradaed through `juju refresh`.

```{Note}
While the workload is stateless, some data are temporarily stored on disk before being sent to Wazuh Indexer. So you should not destroy/recreate the application and/or the units.
```

## Wazuh Dashboards

The Wazuh dashboards charm has a stateless workload. It can safely be upgraded through `juju refresh`.

## Wazuh Indexer

This is where all data are persisted so upgrades should be done carefully.

The recommendation is to follow the [Upgrade guide](https://charmhub.io/opensearch/docs/h-minor-upgrade) from the OpenSearch charm documentation.
