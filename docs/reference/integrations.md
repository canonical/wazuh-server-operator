# Integrations

### ingress

_Interface_: traefik_route  
_Supported charms_: [Traefik Ingress Operator](https://charmhub.io/traefik-k8s)

Ingress manages external http/https access to services in a kubernetes cluster.

Example ingress integrate command: 
```
juju integrate wazuh-server traefik-k8s
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
