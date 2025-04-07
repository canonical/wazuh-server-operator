# Security in Wazuh charms

This document covers the security aspects of the Wazuh charm itself.

For all use cases and configurations related to the Wazuh product, please refer to the [official documentation](https://documentation.wazuh.com/current/index.html).

## Good practices

### Distribute the Certification Authority (CA) to users

The charm deploys Wazuh components with a `self-signed-certificate` CA.

For users to be able to access Wazuh dashboard without any warning, they must install the CA certificate in their browser:

1. Extract the certificate with the `juju run self-signed-certificates/leader get-ca-certificate` and save the content to a `PEM` file.
2. Distribute the file to your users.
3. Install the certificate in your browser. For Chrome, you should go to "Settings > Privacy and security > Security > Manage certificates > Custom > Installed by you > Trusted Certificates > Import" and import the `PEM` file.

### Restrict access

The charm exposes `wazuh-dashboard` directly to users with a local authentication system. It's recommended to keep this service private by restricting the access to known users (typically through a VPN).

If you cannot restrict the access through a VPN, it's recommended to put a web application firewall to restrict who can access the service.

## Risks

Wazuh collects logs from different services, and these logs may contain sensitive information.

You should limit who has access to the service (typically to your security team).

You should pay attention to your backups.

## Security related how-to guides

The following guides cover security related topics:

- [How to backup and restore](../how-to/backup-restore.md)
- [How to collect remote logs](../how-to/collect-logs.md)
