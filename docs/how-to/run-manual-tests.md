# How to run manual tests

The source code for this charm comes with several integration tests that cover
basic functionality. However, for testing updates to complex functions, such as
those that may affect the custom configuration repository feature, or for
testing the affects of particular Wazuh and rsyslog configurations stored in a
custom configuration repository, manual testing may be required.

This guide provides the steps to deploy a local testing environment for manual
tests.

## Follow the integration test setup

The 'how-to' guide for
[running the integration tests](./run-the-integration-tests.md) provides
instructions for setting up LXD, Kubernetes, and Juju controllers on a Ubuntu
virtual machine.

## Run the integration tests

To bootstrap your environment, run the integration tests once with the
`--keep-models` argument, as described in the 'Reuse environments' section of
the integration test how-to guide.

## (Optional) Create configuration secrets

If you wish to test the wazuh-server charm with the optional `agent-password` or
`custom-config-ssh-key` configuration items, create the secrets now. Make note
of the secret URIs, as these should be the value of the corresponding
configuration items.

```bash
juju switch k8s:admin/test-wazuh

juju add-secret agent-password value="password"

juju add-secret deploy-key value="$(cat PATH_TO_DEPLOY_KEY)"
```

## Deploy the wazuh-server charm

The integration tests do not retain the wazuh-server charm, so you will need to
re-deploy the version of the charm that you wish to test.

From the root directory of the charm source code, run `charmcraft pack`. This
will take several minutes on the first run, and will take significantly less
time on all subsequent runs.

As described in the '(Optional) Build the rock' and 'Set the container location'
sections of the integration test guide, either rebuild and upload the rock, or
identify a Github Container Repository (GHCR) image for use and set the
`IMAGE_URL` variable.

The latest available GHCR images can be identified
[here](https://github.com/canonical/wazuh-server-operator/pkgs/container/wazuh-server)

```bash
export IMAGE_URL="ghcr.io/canonical/wazuh-server:a063aca515693126206e4dfa6ba6eba4bac43698-_1.0_amd64"
```

Deploy the charm.

```bash
juju deploy ./wazuh-server_ubuntu-22.04-amd64.charm \
  --resource wazuh-server-image=$IMAGE_URL
```

If you created the optional secrets:

```bash
juju grant-secret deploy-key wazuh-server
juju grant-secret agent-password wazuh-server
```

Create the necessary relations.

```bash
juju integrate \
  localhost:admin/test-wazuh-machine.wazuh-indexer \
  wazuh-server

juju integrate \
  localhost:admin/test-wazuh-machine.self-signed-certificates \
  wazuh-server

juju integrate traefik-k8s wazuh-server

juju integrate any-opencti wazuh-server:opencti-connector
```

Deploy the desired charm configuration values. No configuration items are
mandatory. Configuration items may be specified one-by-one on the command-line
or via a YAML file.

Refer to `juju config`
[documentation](https://documentation.ubuntu.com/juju/3.6/reference/juju-cli/list-of-juju-cli-commands/config/).

```bash
juju config wazuh-server --file=~/wazuh-conf.yml
```

## (Optional) Deploy the dashboard charm

The integration tests do not deploy the dashboard charm by default. If your
manual testing would benefit from access to the Wazuh user interface, you may
deploy the dashboard with the following commands:

```bash
juju switch k8s:admin/test-wazuh

juju offer wazuh-server:wazuh-api

juju switch localhost:admin/test-wazuh-machine

juju deploy wazuh-dashboard --channel 4.11/edge
juju integrate wazuh-dashboard wazuh-indexer
juju integrate wazuh-dashboard self-signed-certificates
juju integrate wazuh-dashboard k8s:admin/test-wazuh.wazuh-server
juju expose wazuh-dashboard
```

To retrieve credentials for the dashboard, you may either follow the
instructions in the 'Retrieve dashboard credentials' section of the
[Test your deployment](./test-your-deployment.md) how-to guide, or you may
retrieve the indexer's admin credentials:

```bash
juju switch localhost:admin/test-wazuh-machine
juju run wazuh-indexer/leader get-password
```

## Teardown

To remove the wazuh-server charm:

```bash
juju switch localhost:admin/test-wazuh-machine

juju remove-saas wazuh-server

juju switch k8s:admin/test-wazuh

juju remove-offer wazuh-server --force --yes

kubectl -n test-wazuh delete statefulset wazuh-server

juju remove-application wazuh-server \
  --destroy-storage --force \
  --no-wait --no-prompt
```
