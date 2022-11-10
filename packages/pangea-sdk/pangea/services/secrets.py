# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation

from typing import Dict, List

from pangea.response import PangeaResponse

from .base import ServiceBase

# FIXME: update this SDK once service is ready


class Secrets(ServiceBase):
    """Secrets service client.

    Provides methods to interact with Pangea Secrets Store Service:

    The following information is needed:
        PANGEA_TOKEN - service token which can be found on the Pangea User
            Console at [https://console.pangea.cloud/project/tokens](https://console.pangea.cloud/project/tokens)

    Examples:
        import os

        # Pangea SDK
        from pangea.config import PangeaConfig
        from pangea.services import Secrets

        token = os.getenv("PANGEA_TOKEN")
        config_id = os.getenv("AUDIT_CONFIG_ID")
        config = PangeaConfig(domain="pangea.cloud", config_id=config_id)

        # Setup Pangea Secrets service
        secrets = Secrets(token, config=config)
    """

    service_name = "secretstore"
    version = "v1"

    def get(self, secret_id: str, secret_version: str = None) -> PangeaResponse:
        """
        Secrets

        Get a Secret from the Secret Store.

        Args:
            secret_id (str): Secret Id.
            secret_version (str) - (Optional): Secret Version.

        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse.

        Examples:
            response = secrets.get("test-a-secret-2", "AF7A1D2A-3A86-4142-A862-B5EE66C4474D")
            response = secrets.get("test-a-secret-2")

            \"\"\"
            response contains:
            {
                {
                    "request_id": "UNKNOWN",
                    "request_time",
                    "response_time",
                    "status": ["success", "failed"],
                    "summary": ["secret found", "secret not found"],
                    "result": {
                        [
                            {"secret_id",
                            "secret_value",
                            "secret_version"},
                            null
                        ]
                    }
                }
            }
            \"\"\"
        """

        return self.request.post("get", data={"secret_id": secret_id, "secret_version": secret_version})

    def add(self, secret_id: str, secret_value: str) -> PangeaResponse:
        """
        Secrets

        Adds a Secret in the Secret Store.

        Args:
            secret_id (str): Secret Id.
            secret_value (str): Secret Value.

        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse.

        Examples:
            response = secrets.add("test-a-secret-5", "test-secret-5_value")

            \"\"\"
            response contains:
            {
                "request_id": "UNKNOWN",
                "request_time": "",
                "response_time",
                "status": ["success", "failed"],
                "summary": ["secret added", "awsmanager.AddSecret: unknown error kind"]
                "result": {
                    [
                        {"secret_id",
                        "secret_version"},
                        "errors": [
                            "code",
                            "detail",
                            "source"
                        ]
                    }]
            }
            \"\"\"
        """

        return self.request.post("add", data={"secret_id": secret_id, "secret_value": secret_value})

    def update(self, secret_id: str, secret_value: str) -> PangeaResponse:
        """
        Secrets

        Update a Secret in the Secret Store.

        Args:
            secret_id (str): Secret Id.
            secret_value (str): Secret Value.

        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse.

        Examples:
            response = secrets.update("test-a-secret-5", "test-secret-5_value_updated")

            \"\"\"
            response contains:
            {
                {
                    "request_id": "UNKNOWN",
                    "request_time",
                    "response_time",
                    "status": ["success" ,"failed"],
                    "summary": ["secret updated", "awsmanager.UpdateSecret: unknown error kind"],
                    "result": {
                        [
                            {"secret_id",
                            "secret_version"},
                            null
                        ]
                    }
                }
            }
            \"\"\"
        """

        return self.request.post("update", data={"secret_id": secret_id, "secret_value": secret_value})
