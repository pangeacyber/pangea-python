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
    service_name = "redact"
    version = "v1"

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
        """
        if self.config.config_id:
            self.request.set_extra_headers({ConfigIDHeaderName: self.config.config_id})
        return self.request.post("redact", data={"text": text, "debug": debug})

    def redact_structured(
        self, obj: t.Any, format: RedactFormat = RedactFormat.JSON, debug=False
    ) -> PangeaResponse:
        """
        Redacts text within a structured object

        :param data: The data that should be redacted
        :param format: The format of the passed data
        :param debug: Return debug output?

        :returns: Pangea Response with redacted data
        """
        return self.request.post(
            "redact_structured", data={"data": obj, "format": format, "debug": debug}
        )
