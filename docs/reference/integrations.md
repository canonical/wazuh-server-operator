# Integrations

### ingress

_Interface_: traefik_route  
_Supported charms_: [Traefik Ingress Operator](https://charmhub.io/traefik-k8s)

Ingress manages external http/https access to services in a kubernetes cluster.

Example ingress integrate command: 
```
juju integrate wazuh-server traefik-k8s
```

### logging

_Interface_: loki_push_api    
_Supported charms_: [loki-k8s](https://charmhub.io/loki-k8s)

Logging relation provides a way to scrape logs produced from the Wazuh Server charm. The Wazuh 
Server logs are stored at `/var/ossec/logs/`. A promtail worker is spawned and will periodically push logs to
Loki.

Example loki_push_api integrate command: 
```bash
juju integrate wazuh-server loki-k8s
```

### metrics-endpoint

_Interface_: [prometheus_scrape](https://charmhub.io/interfaces/prometheus_scrape-v0)

_Supported charms_: [prometheus-k8s](https://charmhub.io/prometheus-k8s)

Metrics-endpoint relation allows scraping the `/metrics` endpoint provided by
[Wazuh Prometheus exporter](https://github.com/pyToshka/wazuh-prometheus-exporter). The metrics are exposed in the [open metrics format](https://github.com/OpenObservability/OpenMetrics/blob/main/specification/OpenMetrics.md#data-model) and will only be scraped by Prometheus once the
relation becomes active

Example metrics-endpoint integrate command: 
```bash
juju integrate wazuh-server prometheus-k8s
```

### opensearch-client

_Interface_: opensearch_client  
_Supported charms_: [OpenSearch](https://charmhub.io/opensearch), [Wazuh Indexer](https://charmhub.io/wazuh-indexer)

OpenSearch integration is a required relation for the Wazuh Server charm to supply data
storage for Wazuh.

Example opensearch-client integrate command: 

```
juju integrate wazuh-server wazuh-indexer:opensearch-client
```

See more information in [Charm Architecture](https://charmhub.io/wazuh-server/docs/explanation-charm-architecture).
