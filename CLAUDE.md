# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

This is a Juju Kubernetes charm that deploys and manages the [Wazuh Server](https://wazuh.com/) (XDR/SIEM). It uses the `ops` framework and follows Canonical's charm development patterns.

## Development Setup

```bash
# Install uv
sudo snap install astral-uv --classic

# Install tox and set up environment
uv tool install tox --with tox-uv
uv tool update-shell
uv sync --all-groups
source .venv/bin/activate
```

## Common Commands

```bash
tox                    # Run all checks (lint, unit, static, coverage-report)
tox -e fmt             # Auto-format code (ruff)
tox -e lint            # Lint: codespell, ruff, mypy
tox -e lint-fix        # Auto-fix lint issues
tox -e static          # Security scan (bandit)
tox -e unit            # Run unit tests with coverage
tox -e integration     # Integration tests (requires live K8s cluster)

# Run specific unit tests
tox -e unit -- tests/unit/test_charm.py
tox -e unit -- -k "test_name" -vvs

# Build
charmcraft pack
```

## Architecture

### Core Pattern: State-Driven Reconciliation

All events funnel into a single `reconcile()` method in [src/charm.py](src/charm.py). Before executing, `reconcile()` calls `_get_state()` which builds a validated `State` object from [src/state.py](src/state.py). If state construction fails, the charm sets the appropriate status and returns early.

Three exception types in `state.py` drive different recovery paths:
- `InvalidStateError` — unrecoverable config issue (blocked status)
- `RecoverableStateError` — operator can fix it (blocked status)
- `IncompleteStateError` — temporary/auto-recovering (waiting status)

### Observer Pattern

Each external relation is managed by its own observer class that hooks into charm events and delegates to `reconcile()`:

| File | Relation |
|------|----------|
| [src/certificates_observer.py](src/certificates_observer.py) | TLS certificates (rsyslog) |
| [src/traefik_route_observer.py](src/traefik_route_observer.py) | Ingress via Traefik |
| [src/opensearch_observer.py](src/opensearch_observer.py) | Wazuh Indexer (OpenSearch) |
| [src/opencti_connector_observer.py](src/opencti_connector_observer.py) | OpenCTI threat intel |
| [src/observability.py](src/observability.py) | Grafana, Prometheus, Loki |

### Pebble Services

The charm manages four services inside the container:
- `wazuh` — Wazuh manager
- `filebeat` — ships logs to the indexer
- `rsyslog` — receives logs from syslog clients (with TLS)
- `prometheus_exporter` — exposes metrics

All service configuration is handled in [src/wazuh.py](src/wazuh.py), which is the largest file (~1000 LOC) and contains file templating, API authentication, and service lifecycle logic.

### Charm Library

[lib/charms/wazuh_server/v0/wazuh_api.py](lib/charms/wazuh_server/v0/wazuh_api.py) is a publishable charm library providing the `wazuh-api` relation interface for consumers.

## Code Style

- Line length: 99 characters
- Docstrings: Google style (enforced by ruff D rules)
- Type hints: required everywhere in `src/` (mypy strict); optional in tests
- Copyright header: `# Copyright 2025 Canonical Ltd.` required in all files
- Import style: enforced by ruff I (isort)

## Testing

Unit tests use `ops.testing` harness with mocked relations. Integration tests require a live Kubernetes cluster with Juju and deploy the actual charm. The `tests/benchmark/` suite measures charm reconciliation time and can export OpenTelemetry traces.

Integration test flags: `--charm-file`, `--wazuh-server-image`, `--kube-config`, `--single-node-indexer`.
