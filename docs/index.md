<!-- vale Canonical.007-Headings-sentence-case = NO -->
# Wazuh Server operator
<!-- vale Canonical.007-Headings-sentence-case = YES -->

A Juju charm deploying and managing the Wazuh Server on Kubernetes. Wazuh is an
open-source XDR and SIEM tool to protect endpoints and cloud workloads. It allows for deployment on
various [Kubernetes platforms](https://ubuntu.com/kubernetes) offered by Canonical.

Like any Juju charm, this charm supports one-line deployment, configuration, integration, scaling, and more.

For security and DevOps teams, this charm makes operating a self-hosted Wazuh Server
straightforward through the clean interface of Juju. It collects logs from remote systems over mutual
TLS and integrates with the Wazuh Indexer, the Wazuh Dashboard, and OpenCTI.

## In this documentation

|                  |                                                                                                                                                                                                                                                                   |
|------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Get started**  | [Deploy the Wazuh Server charm](tutorial/getting-started.md)                                                                                                                                                                                                      |
| **Deployment**   | [Deploy to production](how-to/deploy-to-production.md) \| [Test your deployment](how-to/test-your-deployment.md) \| [Redeploy](how-to/redeploy.md)                                                                                                                 |
| **Operations**   | [Customize configuration](how-to/configure.md) \| [Actions](reference/actions.md) \| [Configurations](reference/configurations.md) \| [Integrate with COS](how-to/integrate-with-cos.md) \| [Back up and restore](how-to/backup-restore.md) \| [Upgrade](how-to/upgrade.md) |
| **Data sources** | [Collect remote logs](how-to/collect-logs.md) \| [Integrate with OpenCTI](how-to/integrate-with-opencti.md)                                                                                                                                                        |
| **Design**       | [Architecture overview](explanation/architecture-overview.md) \| [Charm architecture](reference/charm-architecture.md) \| [Relation endpoints](reference/integrations.md) \| [External access](reference/external-access.md) \| [Security](explanation/security.md) |
| **Development**  | [Contribute](how-to/contribute.md) \| [Run integration tests](how-to/run-integration-tests.md) \| [Run manual tests](how-to/run-manual-tests.md)                                                                                                                    |

## How this documentation is organized

This documentation uses the [Diátaxis documentation structure](https://diataxis.fr/).

- The [Tutorial](tutorial) takes you step-by-step through deploying the Wazuh Server charm and
  integrating it with the Wazuh Indexer, the Wazuh Dashboard, and the other charms it depends on.
- The [How-to guides](how-to) cover practical tasks such as deploying to production, collecting
  remote logs, integrating with other charms, upgrading, and contributing to the charm.
- [Reference](reference) provides technical details on actions, configurations, relation
  endpoints, and the charm architecture.
- [Explanation](explanation) includes context on the overall Wazuh architecture and on security.

## Contributing to this documentation

Documentation is an important part of this project, and we take the same open-source approach to the documentation as the code. As such, we welcome community contributions, suggestions and constructive feedback on our documentation. Our documentation is hosted on the [Charmhub forum](https://discourse.charmhub.io/t/wazuh-server-documentation-overview/16070) to enable easy collaboration. Please use the "Help us improve this documentation" links on each documentation page to either directly change something you see that's wrong, ask a question, or make a suggestion about a potential change in the comments section.

If there's a particular area of documentation that you'd like to see that's missing, please [file a bug](https://github.com/canonical/wazuh-server-operator/issues).

## Project and community

The Wazuh Server Operator is a member of the Ubuntu family. It's an open-source project that warmly welcomes community projects, contributions, suggestions, fixes, and constructive feedback.

- [Code of conduct](https://ubuntu.com/community/code-of-conduct)
- [Get support](https://discourse.charmhub.io/)
- [Join our online chat](https://matrix.to/#/#charmhub-charmdev:ubuntu.com)
- [Contribute](https://charmhub.io/wazuh-server/docs/how-to-contribute)

Thinking about using the Wazuh Server Operator for your next project? [Get in touch](https://matrix.to/#/#charmhub-charmdev:ubuntu.com)!

# Contents

1. [Tutorial](tutorial)
  1. [Deploy the Wazuh Server charm for the first time](tutorial/getting-started.md)
1. [How to](how-to)
  1. [Back up and restore](how-to/backup-restore.md)
  1. [Collect logs](how-to/collect-logs.md)
  1. [Configure](how-to/configure.md)
  1. [Contribute](how-to/contribute.md)
  1. [Deploy to production](how-to/deploy-to-production.md)
  1. [Integrate with COS](how-to/integrate-with-cos.md)
  1. [Integrate with OpenCTI](how-to/integrate-with-opencti.md)
  1. [Redeploy](how-to/redeploy.md)
  1. [Upgrade](how-to/upgrade.md)
  1. [Run integration tests](how-to/run-integration-tests.md)
  1. [Run manual tests](how-to/run-manual-tests.md)
  1. [Test your deployment](how-to/test-your-deployment.md)
1. [Reference](reference)
  1. [Actions](reference/actions.md)
  1. [Charm architecture](reference/charm-architecture.md)
  1. [Configurations](reference/configurations.md)
  1. [External access](reference/external-access.md)
  1. [Integrations](reference/integrations.md)
1. [Explanation](explanation)
  1. [Architecture overview](explanation/architecture-overview.md)
  1. [Security](explanation/security.md)
1. [Changelog](changelog.md)
