# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

run "setup_tests" {
  module {
    source = "./tests/setup"
  }
}

run "basic_deploy" {
  variables {
    model_uuid = run.setup_tests.model_uuid
    channel    = "4.11/edge"
    # renovate: depName="wazuh-server"
    revision = 250
    storage  = {}
  }

  assert {
    condition     = output.app_name == "wazuh-server"
    error_message = "wazuh-server app_name did not match expected"
  }
}
