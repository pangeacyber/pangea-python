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
    """Redact service client.

    Provides the methods to interact with the Pangea Redact Service:
        [https://docs.dev.pangea.cloud/docs/api/redact](https://docs.dev.pangea.cloud/docs/api/redact)

    The following information is needed:
        PANGEA_TOKEN - service token which can be found on the Pangea User
            Console at [https://console.dev.pangea.cloud/project/tokens](https://console.dev.pangea.cloud/project/tokens)
        REDACT_CONFIG_ID - Configuration ID which can be found on the Pangea
            User Console at [https://console.dev.pangea.cloud/service/redact](https://console.dev.pangea.cloud/service/redact)

    Examples:
        import os

        # Pangea SDK
        from pangea.config import PangeaConfig
        from pangea.services import Redact

        PANGEA_TOKEN = os.getenv("PANGEA_TOKEN")
        REDACT_CONFIG_ID = os.getenv("REDACT_CONFIG_ID")

        redact_config = PangeaConfig(base_domain="dev.pangea.cloud", config_id=REDACT_CONFIG_ID)

        # Setup Pangea Redact service client
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
        Redact
        
        Redacts the content of a single text string.

        Args:
            text (str): The text to be redacted
            debug (bool, optional): Return debug output

        Returns:
            Pangea Response with redacted text in the response.result property,
                available response fields can be found at:
                [https://docs.dev.pangea.cloud/docs/api/redact#redact](https://docs.dev.pangea.cloud/docs/api/redact#redact)

        Examples:
            response = redact.redact("Jenny Jenny... 415-867-5309")

            \"\"\"
            response contains:
            {
                "request_id": "prq_2aonw26nr3n5hjovo476252npmekem4u",
                "request_time": "2022-07-06T23:34:46.666Z",
                "response_time": "2022-07-06T23:34:46.679Z",
                "status_code": 200,
                "status": "success",
                "result": {
                    "redacted_text": "\"<PERSON>... <PHONE_NUMBER>\""
                },
                "summary": "Success. Redacted 2 item(s) from text"
            }
            \"\"\"
        """
        return self.request.post("redact", data={"text": text, "debug": debug})

    def redact_structured(
        self, obj: t.Any, redact_format: RedactFormat = RedactFormat.JSON, debug=False
    ) -> PangeaResponse:
        """
        Redact structured

        Redacts text within a structured object.

        Args:
            obj (obj): The object that should be redacted
            redact_format (RedactFormat, optional): The format of the passed data
            debug (bool, optional): Return debug output

        Returns:
            Pangea Response with redacted data in the response.result field,
                available response fields can be found at:
                [https://docs.dev.pangea.cloud/docs/api/redact#redact](https://docs.dev.pangea.cloud/docs/api/redact#redact)

        Examples:
            response = redact.redact_structured(obj={ "number": "415-867-5309", "ip": "1.1.1.1" }, redact_format="json")

            \"\"\"
            response contains:
            {
                "request_id": "prq_m2z76gv4mcsbysy4ssu4covympg3sske",
                "request_time": "2022-07-06T23:35:41.524Z",
                "response_time": "2022-07-06T23:35:41.543Z",
                "status_code": 200,
                "status": "success",
                "result": {
                    "redacted_data": {
                    "number": "<PHONE_NUMBER>",
                    "ip": "<IP_ADDRESS>"
                    }
                },
                "summary": "Success. Redacted 2 item(s) from data"
            }
            \"\"\"
        """
        return self.request.post(
            "redact_structured",
            data={"data": obj, "format": redact_format, "debug": debug},
        )
