# Wazuh Server Operator

A Juju charm deploying and managing the Wazuh Server on Kubernetes. Wazuh is an
open-source XDR and SIEM tool to protect endpoints and cloud workloads. It allows for deployment on
various [Kubernetes platforms](https://ubuntu.com/kubernetes) offered by Canonical.

Like any Juju charm, this charm supports one-line deployment, configuration, integration, scaling, and more.

For information about how to deploy, integrate, and manage this charm, see the Official [Wazuh Server Operator Documentation](https://charmhub.io/wazuh-server/docs).

## In this documentation

| | |
|--|--|
|  [Tutorials](https://charmhub.io/wazuh-server/docs/tutorial)</br>  Get started - a hands-on introduction to using the Charmed Wazuh Server operator for new users </br> |  [How-to guides](https://charmhub.io/wazuh-server/docs/how-to-contribute) </br> Step-by-step guides covering key operations and common tasks |
| [Reference](https://charmhub.io/wazuh-server/docs/reference-actions) </br> Technical information - specifications, APIs, architecture | [Explanation](https://charmhub.io/wazuh-server/docs/explanation-charm-architecture) </br> Concepts - discussion and clarification of key topics  |

## Contributing to this documentation

Documentation is an important part of this project, and we take the same open-source approach to the documentation as the code. As such, we welcome community contributions, suggestions and constructive feedback on our documentation. Our documentation is hosted on the [Charmhub forum](https://discourse.charmhub.io/t/wazuh-server-documentation-overview/16070) to enable easy collaboration. Please use the "Help us improve this documentation" links on each documentation page to either directly change something you see that's wrong, ask a question, or make a suggestion about a potential change via the comments section.

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
  1. [Test the charm](how-to/test-the-charm.md)
1. [Reference](reference)
  1. [Actions](reference/actions.md)
  1. [Configurations](reference/configurations.md)
  1. [External access](reference/external-access.md)
  1. [Integrations](reference/integrations.md)
1. [Explanation](explanation)
  1. [Architecture overview](explanation/architecture-overview.md)
  1. [Charm architecture](explanation/charm-architecture.md)
  1. [Security](explanation/security.md)
1. [Changelog](changelog.md)
