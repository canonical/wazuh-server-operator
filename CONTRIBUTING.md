# Contributing

Contributions to this repository are welcome.

## Developing

The code for this charm can be downloaded as follows:

```bash
git clone https://github.com/canonical/wazuh-server-operator
```

You can use the environments created by `tox` for development:

```shell
tox --notest -e unit
source .tox/unit/bin/activate
```

## Testing

To test this charm, you'll need a working development setup.

A full setup guide is provided [here](/docs/how-to/development-env-setup.md).

Alternatively, the following external documentation should cover all
requirements:

- Juju 3 installed and bootstrapped to an LXD controller. You can accomplish
  this process by using a [Multipass](https://multipass.run/) VM as outlined in
  this guide:
  [How to manage your deployment](https://documentation.ubuntu.com/juju/3.6/howto/manage-your-deployment/).
  Note that this tutorial provides documentation for both manual and automatic
  deployment management. You would have to follow the manual steps only to avoid
  installing MicroK8s in your setup.
- Canonical Kubernetes installed and bootstrapped to Juju. This can be
  accomplished by following the
  [Setup Canonical Kubernetes](https://charmhub.io/wazuh-server/docs/tutorial-getting-started#p-38194-set-up-canonical-kubernetes)
  section in the getting started tutorial for Wazuh server.

Note that if you follow the external documentation, you must still refer to the
local documentation for (optionally) building the rock and running the tests.

## Deploy

A typical deployment would look like:

```bash
# Create a model
juju add-model wazuh-server-dev
# Enable DEBUG logging
juju model-config logging-config="<root>=INFO;unit=DEBUG"
# Deploy the charm (assuming you're on amd64)
juju deploy ./wazuh_server_ubuntu-22.04-amd64.charm \
  --resource wazuh-server-image=localhost:5000/wazuh-server:latest
```

## How to upgrade Wazuh version

The Wazuh product is deployed using three charms:

- `wazuh-server`: this repository.
- [`wazuh-indexer`](https://github.com/canonical/wazuh-indexer-operator/): a
  fork of
  [`opensearch-operator`](https://github.com/canonical/opensearch-operator)
  relying on [`opensearch-snap`](https://github.com/canonical/opensearch-snap)
- [`wazuh-dashboard`](https://github.com/canonical/wazuh-dashboard-operator/): a
  fork of
  [`opensearch-dashboards-operator`](https://github.com/canonical/opensearch-dashboards-operator)
  relying on
  [`opensearch-dashboards-snap`](https://github.com/canonical/opensearch-dashboards-snap)

To upgrade the Wazuh version, the snaps and charms must be updated in the
following order:

1. `wazuh-indexer-snap`: merge upstream changes, then upgrade Wazuh version.
1. `wazuh-dashboard-snap`: merge upstream changes, then upgrade Wazuh version.
1. `wazuh-indexer-operator`: merge upstream changes, then upgrade Wazuh version.
1. `wazuh-dashboard-operator`: merge upstream changes, then upgrade Wazuh
   version.
1. `wazuh-server-operator`: upgrade Wazuh version.

> [!IMPORTANT] GitHub incorrectly shows that the forks are based on the `main`
> branch of the `opensearch` snaps and charms. It's a known issue when an
> upstream project renames its default branch after a fork and the fork doesn't.
> Unfortunately, the upstream branch cannot be updated on the fork. They are
> based on the `2/edge` branch.

### How to merge upstream changes

This is the generic approach to merge upstream changes using the example for
`wazuh-indexer-snap`. Specific details for each repository are provided in the
following sections.

#### Prepare

- Clone the repository:
  `git clone https://github.com/canonical/wazuh-indexer-snap.git`
- Prepare your working branch: `git checkout -b chore/merge_upstream`
- To ensure that no external dependency is breaking the CI, it's safer to run it
  before changing anything. You can trigger the CI with an empty commit:
  `git commit --allow-empty -m 'Trigger CI' && git push -u origin chore/merge_upstream`.
- Fetch the upstream branch:

```shell
git remote add upstream https://github.com/canonical/opensearch-dashboards-operator.git
git fetch upstream 2/edge
```

#### Merge

Start the merge with `git merge upstream/2/edge`.

There will be conflicts, try to minimize them for future merges :

- Apply all upstream changes to the Wazuh repository, even comments.
- Propose changes upstream that would simplify future merges (use of constants
  instead of hard coded strings for instance).

Here are few tips to fix the conflicts:

- Keep the changes where `opensearch` is replaced by `wazuh`.
- Keep the changes referring to Wazuh channels, revisions or versions.
- Keep the changes explicitly mentioning `wazuh` (including comments).

When all conflicts are resolved and the merge is completed, run the CI to ensure
all tests pass.

#### Extra checks

See if the skipped tests are still relevant. You can list them with
`grep -ri 'skip.*wazuh' tests/`.

### How to upgrade Wazuh version

All repositories must be updated to the same Wazuh version.

For Wazuh, we currently have a track for the minor version (e.g. `4.11/edge`) as
we have seen some breaking changes between minor versions in the past. We may
switch back to a track per major version in the future (e.g. `5/edge`).

## `wazuh-indexer-snap`

- Look for references to the previous version: `grep -r 4.11`.
- Update them to the version you want to deploy.

## `wazuh-dashboard-snap`

- Look for references to the previous version: `grep -r 4.11`.
- Update them to the version you want to deploy.
- Update `workflows/ci.yaml`, to use the latest `wazuh-indexer` release.

If the Wazuh team has implemented a variable to refer to the Wazuh
configuration, you may replace the last four lines in `snapcraft.yaml` which are
temporary workarounds.

## `wazuh-indexer-operator`

- Look for references to the previous version: `grep -r 4.11`.
- Update them to the version you want to deploy.
- Update `OPENSEARCH_SNAP_REVISION` in
  `lib/charms/opensearch/v0/constants_charm.py`

## `wazuh-dashboard-operator`

- Look for references to the previous version: `grep -r 4.11`.
- Update them to the version you want to deploy.
- Update `OPENSEARCH_DASHBOARDS_SNAP_REVISION` in `src/literals.py`.

## `wazuh-server-operator`

- Look for references to the previous version: `grep -r 4.11`.
- Update them to the version you want to deploy.
