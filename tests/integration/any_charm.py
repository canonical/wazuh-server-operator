# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

# This Python script is designed to be loaded into any-charm. Some lint checks do not apply
# pylint: disable=import-error,too-few-public-methods

"""This code snippet is used to be loaded into any-charm which is used for integration tests."""
import jwt
from any_charm_base import AnyCharmBase


class AnyCharm(AnyCharmBase):
    """Any charm that requires an OpenCTI connector relation."""

    def __init__(self, *args, **kwargs):
        """Initialize the AnyCharm class.

        Args:
            args: Variable list of positional arguments passed to the parent constructor.
            kwargs: Variable list of positional keyword arguments passed to the parent constructor.
        """
        super().__init__(*args, **kwargs)
        self.framework.observe(self.on.require_opencti_connector_relation_joined, self._reconcile)
        self.framework.observe(self.on.require_opencti_connector_relation_changed, self._reconcile)

    def _reconcile(self, event) -> None:
        """Provide sample OpenCTI URL and token to the relation.

        Args:
            event: The event that triggered the method.
        """
        relation = event.relation
        relation.data[self.app][
            "opencti_url"
        ] = f"http://{self.app.name}-endpoints.{self.model.name}.svc:8080"
        sample_token = jwt.encode({"sub": "sample-user"}, "sample-key", algorithm="HS256")
        opencti_token_id = relation.data[self.app].get("opencti_token")
        if not opencti_token_id:
            secret = self.app.add_secret(content={"token": sample_token})
            secret.grant(relation)
            relation.data[self.app]["opencti_token"] = str(secret.id)
        else:
            secret = self.model.get_secret(id=opencti_token_id)
            if secret.get_content(refresh=True)["token"] != sample_token:
                secret.set_content({"token": sample_token})
