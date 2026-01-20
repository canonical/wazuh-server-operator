# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

Each revision is versioned by the date of the revision.

## 2025-01-20

- Mount storage for /var/ossec/logs
- Remove storage for /var/log/collectors since nothing is written in this path anymore

## 2025-01-09

- Store the complete certificate chain CA certificate from the Wazuh indexer.
- Upgrade the Wazuh Indexer TF module to rev12.

## 2025-12-19

- Add the self-signed-certificates outputs to the Terraform product.

## 2025-12-17

- Moved charm-architecture.md from Explanation to Reference category.

## 2025-11-14

- Upgrade the Juju Terraform provider to version 1.

## 2025-11-14

- Added enable-vulnerability-detection config option.

## 2025-10-15

### Updated

- Remove secret containing the CSR when the certificate integration breaks.

## 2025-10-01

### Updated
<!-- vale Canonical.400-Enforce-inclusive-terms = NO -->
- Use only the master node as backend for API and agent enrollment.
<!-- vale Canonical.400-Enforce-inclusive-terms = YES -->

## 2025-10-14

### Updated

- Export the certificates integration in the TF product.

## 2025-09-16

### Removed

- Support for cross controller relations in the TF product.

## 2025-09-11

### Updated

- Use Juju TF provider 0.22.0.

## 2025-09-10

### Added

- Added clustering support.

### Updated

- Fix an issue causing the rock not to be built.
- Update the Wazuh Grafana dashboard to the one created by @Chiori-Ndukwe.

## 2025-08-25

### Updated

- Lint dependencies.

## 2025-08-20

### Added

- New documentation checks workflow.

## 2025-07-22

### Added

- Loki alert rules.
- Prometheus alert rules.


## 2025-07-17

### Added

- Add terraform output for Open Authorization integration.

## 2025-07-16

### Added

- Adding Grafana dashboard.

## 2025-07-04

### Added

- Adding documentation on how to integrate with COS.
- Adding alive pebble check for the Prometheus exporter.

### Updated

- Update the Prometheus exporter

## 2025-06-30

### Added

- Adding `<endpoint>-relation-departed` hooks for `opensearch_observer`, 
`opencti_connector`, `wazuh_api` and `wazuh_peer` integrations.

## 2025-06-24

### Added

- How to redeploy documentation.

### Updated

- Updated the documentation to reference Canonical Kubernetes instead of MicroK8s.
- Moved the charm status setting logic to the reconcile loop.

## 2025-06-23

### Updated

- Changed exception to blocked status for missing OpenCTI integration.

## 2025-06-19

### Updated

- Modified the CI and `pre_run_script.sh` to use Canonical K8s instead of MicroK8s.

## 2025-06-16

### Updated

- Architecture documentation for clearer diagrams.

### Updated

- Modified the `rsync` command to prevent deletion of excluded directories. 
- Modified the `rsync` command to change ownership to `root:wazuh`. 

## 2025-06-12

### Added

- OpenCTI integration documentation.

## 2025-06-06

### Removed

- All references to `src-docs`.

### Updated

- `CODEOWNERS` file to only have the `/docs` directory monitored by the technical authors.

### Added

- OpenCTI integration with Wazuh server.

## 2025-03-18

### Added

- Changelog added for tracking changes.
