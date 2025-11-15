# How to customize configuration

The configuration of Wazuh is described in the
[User Manual](https://documentation.wazuh.com/current/user-manual/).

To customize the configuration of your charmed Wazuh, use the
`custom-config-repository` configuration option to reference the repository
where your configuration is stored.

## Configure a custom configuration repository

The URL of this repository should be in the form `git+ssh://git@yourepo@yourref`
where:

- `yourrepo` is the address of your repository.
- `yourref` is a Git reference, typically a tag, to specify the version you want
  to deploy.

For the Wazuh server to be able to retrieve the configuration, we're using the
concept of a deploy key:

1. Create a SSH key pair.
2. Add the private key as a Juju secret and retrieve the secret ID:

```
juju add-secret my-custom-config-ssh-key value=<ssh-key>
juju grant-secret my-custom-config-ssh-key wazuh-server
```

3. Configure your deployment to reference this secret with the
   `custom-config-ssh-key` option.
4. Deploy the public key on your Git server. On GitHub, this can be done in your
   project's `Settings > Security > Deploy Keys`.

## Set up repository content

Your repository should contain configuration files under the same paths you
would expect them to appear on a live server. The following paths are checked:

- `var/ossec`
  - `etc/*.conf` (will delete)
  - `etc/decoders/` (recursively, will delete)
  - `etc/rules/` (recursively, will delete)
  - `etc/shared/*.conf` (will delete)
  - `etc/shared/**/*.conf` (will delete)
  - `integrations/` (recursively, will delete)
  - `ruleset/` (recursively)
- `etc/rsyslog.conf`
- `etc/rsyslog.d/` (recursively)
- `usr/share/filebeat/` (recursively)
- `etc/filebeat/` (recursively)

Files in the repository will be created or will overwrite existing files by the
same path on the container filesystem.

For paths marked "will delete" in the list above, pre-existing files on the
container filesystem will be deleted if they are not in the repository. For all
other paths, pre-existing files will not be deleted - though they may be
overwritten.

## Deploy a new configuration

The Wazuh server charm is not watching the repository for changes.

The recommended way to enforce a configuration update on the server is to update
the `custom-config-repository` with the new Git reference to use.

```{note}
While Wazuh server is not watching the repository for changes,
it may pull the repository on specific events, such as a restarts.

That's why it's recommended to refer to an fixed Git reference
to avoid unexpected configuration changes on your deployment.
```
