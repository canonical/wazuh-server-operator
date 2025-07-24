# How to contribute

Our documentation is hosted on [Discourse](https://discourse.charmhub.io/t/wazuh-server-documentation-overview/16070) to enable collaboration. Please use the "Help us improve this documentation" links on each documentation page to either directly change something you see that's wrong, ask a question, or make a suggestion about a potential change via the comments section.

Our documentation is also available alongside the [source code on GitHub](https://github.com/canonical/wazuh-server-operator/).
You may open a pull request with your documentation changes, or you can
[file a bug](https://github.com/canonical/wazuh-server-operator/issues) to provide constructive feedback or suggestions.

See [CONTRIBUTING.md](https://github.com/canonical/wazuh-server-operator/blob/main/CONTRIBUTING.md)
for information on contributing to the source code.

## How to upgrade Wazuh version

The Wazuh product is deployed using three charms:
- `wazuh-server`: this repository.
- [`wazuh-indexer`](https://github.com/canonical/wazuh-indexer-operator/): a fork of [`opensearch-operator`](https://github.com/canonical/opensearch-operator) relying on [`opensearch-snap`](https://github.com/canonical/opensearch-snap)
- [`wazuh-dashboard`](https://github.com/canonical/wazuh-dashboard-operator/): a fork of [`opensearch-dashboards-operator`](https://github.com/canonical/opensearch-dashboards-operator) relying on [`opensearch-dashboards-snap`](https://github.com/canonical/opensearch-dashboards-snap)

To upgrade the Wazuh version, the snaps and charms must be updated in the following order:

1. `wazuh-indexer-snap`: merge upstream changes, then upgrade Wazuh version.
2. `wazuh-dashboard-snap`: merge upstream changes, then upgrade Wazuh version.
3. `wazuh-indexer-operator`: merge upstream changes, then upgrade Wazuh version.
4. `wazuh-dashboard-operator`: merge upstream changes, then upgrade Wazuh version.
5. `wazuh-server-operator`: upgrade Wazuh version.


> [!IMPORTANT]
> GitHub incorrectly shows that the forks are based on the `main` branch of the `opensearch` snaps and charms (it's a known issue when an upstream project renames its default branch after a fork and the fork doesn't. Unfortunately, the upstream branch cannot be updated on the fork.).
> They are based on the `2/edge` branch.

### How to merge upstream changes

This is the generic approach to merge upstream changes using the example for `wazuh-indexer-snap`. Specific details for each repository are provided in the following sections.

#### Prepare

- Clone the repository: `git clone https://github.com/canonical/wazuh-indexer-snap.git`
- Prepare your working branch: `git checkout -b chore/merge_upstream`
- To ensure that no external dependency is breaking the CI, it's safer to run it before changing anything. You can trigger the CI with an empty commit: `git commit --allow-empty -m 'Trigger CI' && git push -u origin chore/merge_upstream`.
- Fetch the upstream branch:

```shell
git remote add upstream https://github.com/canonical/opensearch-dashboards-operator.git
git fetch upstream 2/edge
```

#### Merge

Start the merge with `git merge upstream/2/edge`.

There will be conflicts, try to minimize them for future merges :

- Reflect all changes, even comments.
- Propose changes upstream that would simplify future merges (use of constants instead of hard coded strings for instance).

Here are few tips to fix the conflicts:

- Keep the changes where `opensearch` is replaced by `wazuh`.
- Keep the changes referring to Wazuh channels, revisions or versions.
- Keep the changes explicitly mentioning `wazuh` (including comments).

When all conflicts are resolved and the merge is completed, run the CI to ensure all tests pass.

#### Extra checks

See if the skipped tests are still relevant. You can list them with `grep -ri 'skip.*wazuh' tests/`.

### How to upgrade Wazuh version

All repositories must be updated to the same Wazuh version.

For Wazuh, we currently have a track for the minor version (e.g. 4.11/edge) as we have seen some breaking changes between minor versions in the past. We may switch back to a track per major version in the future (e.g. 5/edge).

## `wazuh-indexer-snap`

- Look for references to the previous version: `grep -r 4.11`.
- Update them to the version you want to deploy.

## `wazuh-dashboard-snap`

- Look for references to the previous version: `grep -r 4.11`.
- Update them to the version you want to deploy.
- Update `workflows/ci.yaml`, to use the latest `wazuh-indexer` release.

If Wazuh team has implemented a variable to refer to the Wazuh configuration, you may replace the last for lines in `snapcraft.yaml` which are temporary workarounds.

## `wazuh-indexer-operator`

- Look for references to the previous version: `grep -r 4.11`.
- Update them to the version you want to deploy.
- Update `OPENSEARCH_SNAP_REVISION` in `lib/charms/opensearch/v0/constants_charm.py`

## `wazuh-dashboard-operator`

- Look for references to the previous version: `grep -r 4.11`.
- Update them to the version you want to deploy.
- Update `OPENSEARCH_DASHBOARDS_SNAP_REVISION` in `src/literals.py`.

## `wazuh-server-operator`

- Look for references to the previous version: `grep -r 4.11`.
- Update them to the version you want to deploy.
