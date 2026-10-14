# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

[private]
default:
    @just --list --unsorted

[group('Setup')]
install-requirements:
    uv tool install tox --with tox-uv
    uv tool install prek
    prek install

[group('Testing & Quality Assurance')]
lint:
    uv tool run --with tox-uv tox run -e lint

[group('Testing & Quality Assurance')]
static:
    uv tool run --with tox-uv tox run -e static

[group('Testing & Quality Assurance')]
test *args:
    uv tool run --with tox-uv tox run -e unit -- {{args}}

[group('Testing & Quality Assurance')]
test-library python='.tox/unit/bin/python':
    env PYTHONPATH=lib {{python}} -m pytest -q tests/unit/test_library_wazuh_api.py

[group('Testing & Quality Assurance')]
test-integ *args:
    uv tool run --with tox-uv tox run -e integration -- {{args}}

[group('Operations & Deployment')]
ops:
    charmcraft pack
