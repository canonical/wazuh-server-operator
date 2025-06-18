# How to perform a minor upgrade

**Example**: Wazuh 4.9 -> Wazuh 4.11.

```{important}
The workload's versions are pinned in the charms.
No automatic upgrades will happen if they're not triggered at the charm level.
```

## Wazuh server

The Wazuh server has a stateless workload. It can safely be upgraded through `juju refresh`.

```{note}
While the workload is stateless, some data are temporarily stored on disk before being sent
to Wazuh indexer. So you should not destroy or recreate the application and/or the units.
```

## Wazuh dashboards

The Wazuh dashboards charm has a stateless workload. It can safely be upgraded through `juju refresh`.

## Wazuh indexer

```{important}
This is where all data are persisted so upgrades should be done carefully.
```

The recommendation is to follow the [Upgrade guide](https://charmhub.io/opensearch/docs/h-minor-upgrade) from the OpenSearch charm documentation.
