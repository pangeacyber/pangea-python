# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation

import enum
import typing as t

from pangea.response import PangeaResponse
from .base import ServiceBase


class RedactFormat(str, enum.Enum):
    JSON = "json"


class Redact(ServiceBase):
    service_name = "redact"
    version = "v1"
    config_id_header = "X-Pangea-Redact-Config-ID"

    def redact(self, text: str, debug=False) -> PangeaResponse:
        """
        Redacts text

        :param text: The text to be redacted
        :param debug: Return debug output?

        :returns: Pangea Response with redacted text
        """
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
