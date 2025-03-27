# How to customize configuration

The configuration of Wazuh is described in the [User Manual](https://documentation.wazuh.com/current/user-manual/).

To customize the configuration of your charmed Wazuh, use the `custom-config-repository` configuration option to reference the repository where your configuration is stored.

## Configure a custom configuration repository

The URL of this repository should be in the form `git+http://yourepo?ref=yourref` where:

- `yourrepo` is the address of your repository.
- `yourref` is a Git reference, typically a tag, to specify the version you want to deploy.

For the Wazuh server to be able to retrieve the configuration, we're using the concept of a deploy key:

1. Create a SSH key pair.
2. Add the private key as a Juju secret and retrieve the secret ID: `juju add-secret my-custom-config-ssh-key value=<ssh-key> && juju grant-secret my-custom-config-ssh-key wazuh-server`.
3. Configure your deployment to reference this secret with the `custom-config-ssh-key` option.
4. Deploy the public key on your Git server. On Github, this can be done in your project's `Settings > Security > Deploy Keys`.

## Set up repository content

You repository should mimic the layout of the Wazuh server configuration with a `var/ossec` folder.

All files in the following sub-folders will be copied to the Wazuh server:

- `etc/*.conf`
- `etc/decoders/` recursively
- `etc/rules/` recursively
- `etc/shared/*.conf`
- `etc/shared/**/*.conf`
- `integrations/` recursively

## Deploy a new configuration

The Wazuh server charm is not watching the repository for changes.

The recommended way to enforce a configuration update on the server is to update the `custom-config-repository` with the new Git reference to use.

```{note}
While Wazuh server is not watching the repository for changes,
it may pull the repository on specific events, such as a restarts.

That's why it's recommended to refer to an fixed Git reference
to avoid unexpected configuration changes on your deployment.
```

