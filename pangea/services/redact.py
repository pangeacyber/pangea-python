# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation

import enum
import typing as t

from pangea.response import PangeaResponse

from .base import ServiceBase

ConfigIDHeaderName = "X-Pangea-Redact-Config-ID"


class RedactFormat(str, enum.Enum):
    JSON = "json"


class Redact(ServiceBase):
    """
    Examples:
        import os

        # Pangea SDK
        from pangea.config import PangeaConfig
        from pangea.services import Redact

        PANGEA_TOKEN = os.getenv("PANGEA_TOKEN")
        REDACT_CONFIG_ID = os.getenv("REDACT_CONFIG_ID")

        redact_config = PangeaConfig(base_domain="dev.pangea.cloud", config_id=REDACT_CONFIG_ID)

        # Setup Pangea Redact service
        redact = Redact(token=PANGEA_TOKEN, config=redact_config)
    """

    service_name = "redact"
    version = "v1"
    config_id_header = "X-Pangea-Redact-Config-ID"

    def __init__(self, token, config=None):
        super().__init__(token, config)

        if self.config.config_id:
            self.request.set_extra_headers({ConfigIDHeaderName: self.config.config_id})

    def redact(self, text: str, debug=False) -> PangeaResponse:
        """
        Redacts text

        :param text: The text to be redacted
        :param debug: Return debug output?

        :returns: Pangea Response with redacted text

        :examples: response = redact.redact("Jenny Jenny... 415-867-5309")
        """
        return self.request.post("redact", data={"text": text, "debug": debug})

    def redact_structured(
        self, obj: t.Any, redact_format: RedactFormat = RedactFormat.JSON, debug=False
    ) -> PangeaResponse:
        """
        Redacts text within a structured object

        :param obj: The object that should be redacted
        :param redact_format: The format of the passed data
        :param debug: Return debug output?

        :returns: Pangea Response with redacted data

        :examples: response = redact.redact_structured(obj={ "number": "415-867-5309", "ip": "1.1.1.1" }, redact_format="json")
        """
        return self.request.post(
            "redact_structured",
            data={"data": obj, "format": redact_format, "debug": debug},
        )
