[![CharmHub Badge](https://charmhub.io/indico/badge.svg)](https://charmhub.io/wazuh-server)
[![Publish to edge](https://github.com/canonical/wazuh-server-operator/actions/workflows/publish_charm.yaml/badge.svg)](https://github.com/canonical/wazuh-server-operator/actions/workflows/publish_charm.yaml)
[![Promote charm](https://github.com/canonical/wazuh-server-operator/actions/workflows/promote_charm.yaml/badge.svg)](https://github.com/canonical/wazuh-server-operator/actions/workflows/promote_charm.yaml)
[![Discourse Status](https://img.shields.io/discourse/status?server=https%3A%2F%2Fdiscourse.charmhub.io&style=flat&label=CharmHub%20Discourse)](https://discourse.charmhub.io)

<!-- vale Canonical.007-Headings-sentence-case = NO -->
# Wazuh Server operator
<!-- vale Canonical.007-Headings-sentence-case = YES -->

A Juju charm deploying and managing Wazuh Server on Kubernetes. Wazuh is an
open-source XDR and SIEM tool to protect endpoints and cloud workloads. It allows for deployment 
on various [Kubernetes platforms](https://ubuntu.com/kubernetes) offered by Canonical.

Like any Juju charm, this charm supports one-line deployment, configuration, integration, scaling, and more.

For information about how to deploy, integrate, and manage this charm, see the Official [Wazuh Server Operator Documentation](https://charmhub.io/wazuh-server/docs).


## Get started

You can follow the tutorial [here](https://charmhub.io/wazuh-server/docs/tutorial-getting-started).

## Integrations

This charm can be integrated with other Juju charms and services:
- [Wazuh Indexer](https://charmhub.io/wazuh-indexer): Wazuh indexer is a highly scalable, full-text search and analytics engine forked from OpenSearch.
- [Traefik](https://charmhub.io/traefik-k8s): Traefik is an application proxy that providers routing and load balancing of microservices.
- [Certificates](https://github.com/canonical/charm-relation-interfaces/blob/main/interfaces/tls_certificates/v1/README.md): Any provider charm compliant with the `tls-certificates/v1` interface, providing TLS certificates.

You can find the full list of integrations [here](https://charmhub.io/wazuh-server/integrations).

## Learn more
* [Read more](https://charmhub.io/wazuh-server) <!--Link to the charm's official documentation-->
* [Developer documentation](https://documentation.wazuh.com/) <!--Link to any developer documentation-->
* [Official webpage](https://wazuh.com/) <!--(Optional) Link to official webpage/blog/marketing content-->
* [Troubleshooting](https://matrix.to/#/#charmhub-charmdev:ubuntu.com) <!--(Optional) Link to a page or section about troubleshooting/FAQ-->
## Project and community
* [Issues](https://github.com/canonical/wazuh-server-operator/issues) <!--Link to GitHub issues (if applicable)-->
* [Contributing](https://charmhub.io/wazuh-server/docs/how-to-contribute) <!--Link to any contribution guides-->
* [Matrix](https://matrix.to/#/#charmhub-charmdev:ubuntu.com) <!--Link to contact info (if applicable), e.g. Matrix channel-->
