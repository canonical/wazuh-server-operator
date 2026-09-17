# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

from pathlib import Path


def test_integration_waits_for_traefik_before_application_uses_fixture() -> None:
    source = Path("tests/integration/conftest.py").read_text()
    fixture = source[source.index("async def traefik_fixture(") :]
    fixture = fixture[: fixture.index("\n\n@pytest_asyncio.fixture", 1)]

    readiness_wait = fixture.find("await model.wait_for_idle(")
    assert readiness_wait != -1
    assert readiness_wait < fixture.index("yield application")


def test_benchmark_waits_for_traefik_before_integrating_wazuh() -> None:
    source = Path("tests/benchmark/benchmark.py").read_text()
    deployment = source[source.index('logger.info("Deploying traefik-k8s")') :]

    assert deployment.index("await model.wait_for_idle(") < deployment.index(
        'await model.integrate("traefik-k8s", WAZUH_SERVER_APP)'
    )


def test_filebeat_restart_uses_literal_kubectl_for_flag() -> None:
    source = Path("tests/integration/test_charm.py").read_text()
    test = source[source.index("async def test_filebeat_data_persists_across_pod_restart(") :]

    assert '"--for=condition=Ready"' in test
