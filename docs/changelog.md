# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

Each revision is versioned by the date of the revision.

## 2025-06-24

### Updated

- Moved the charm status setting logic to the reconcile loop.

## 2025-06-23

### Updated

- Changed exception to blocked status for missing OpenCTI integration.

## 2025-06-19

### Updated

- Modified the CI and `pre_run_script.sh` to use Canonical K8s instead of Microk8s.

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
