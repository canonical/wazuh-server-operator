# How to redeploy Wazuh

This guide provides the necessary steps for migrating an existing Wazuh deployment to a new environment.

<!-- vale Canonical.007-Headings-sentence-case = NO -->
## Migrate the Indexer data
<!-- vale Canonical.007-Headings-sentence-case = YES -->

Follow the instructions in [the OpenSearch charm migration documentation](https://github.com/canonical/opensearch-operator/blob/main/docs/how-to/h-migrate-cluster.md) to migrate the data stored in the Wazuh Indexer.
