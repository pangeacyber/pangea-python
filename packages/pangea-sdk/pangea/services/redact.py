# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation

import enum
from typing import Dict, List, Optional, Union

from pangea.response import APIRequestModel, APIResponseModel, PangeaResponse, PangeaResponseResult

from .base import ServiceBase


class RedactFormat(str, enum.Enum):
    JSON = "json"


class RedactRequest(APIRequestModel):
    """
    Input class to make a redact request

    Arguments:
    text -- Text to apply redact functionality
    debug -- Setting this value to true will provide a detailed analysis of the redacted data and the rules that caused redaction.
    """

    text: str
    debug: bool = False


class RecognizerResult(APIResponseModel):
    """
    TODO: complete

    Arguments:
    field_type --
    score --
    text --
    start --
    end --
    redacted --
    data_ket --
    """

    field_type: str
    score: int
    text: str
    start: int
    end: int
    redacted: bool
    data_key: Optional[str] = None


class DebugReport(APIResponseModel):
    """
    TODO: complete

    """

    summary_counts: Dict[str, int]
    recognizer_results: List[RecognizerResult]


class RedactResult(PangeaResponseResult):
    """
    Result class after a redact request

    Arguments:
    redact_text -- Redacted text result
    report -- TODO: complete
    """

    redacted_text: str
    report: Optional[DebugReport] = None


class StructuredRequest(APIRequestModel):
    """
    Class input to redact structured data request

    Arguments:
    data -- Structured data to redact
    jsonp -- JSON path(s) used to identify the specific JSON fields to redact in the structured data. Note: If jsonp parameter is used, the data parameter must be in JSON format.
    format -- The format of the structured data to redact. (default is JSON)
    debug -- Setting this value to true will provide a detailed analysis of the redacted data and the rules that caused redaction.
    """

    data: Union[Dict, str]
    jsonp: Optional[List[str]] = None
    format: Optional[RedactFormat] = None
    debug: Optional[bool] = None


class StructuredResult(PangeaResponseResult):
    """
    TODO: complete

    """

    redacted_data: Union[Dict, str]  # FIXME: this should be raw json
    report: Optional[DebugReport] = None


class RedactFormat(str, enum.Enum):
    JSON = "json"


class Redact(ServiceBase):
    """Redact service client.

    Provides the methods to interact with the Pangea Redact Service:
        [https://pangea.cloud/docs/api/redact](https://pangea.cloud/docs/api/redact)

    The following information is needed:
        PANGEA_TOKEN - service token which can be found on the Pangea User
            Console at [https://console.pangea.cloud/project/tokens](https://console.pangea.cloud/project/tokens)

    Examples:
        import os

        # Pangea SDK
        from pangea.config import PangeaConfig
        from pangea.services import Redact

        PANGEA_TOKEN = os.getenv("PANGEA_REDACT_TOKEN")

        redact_config = PangeaConfig(domain="aws.us.pangea.cloud")

        # Setup Pangea Redact service client
        redact = Redact(token=PANGEA_TOKEN, config=redact_config)
    """

    service_name = "redact"
    version = "v1"

    def __init__(self, token, config=None):
        super().__init__(token, config)

    def redact(self, text: str, debug: bool = False) -> PangeaResponse[RedactResult]:
        """
        Redact

        Redacts the content of a single text string.

        Args:
            text (str): The text to be redacted
            debug (bool, optional): Return debug output

        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            Pangea Response with redacted text in the response.result property,
                available response fields can be found in our
                [API Documentation](https://pangea.cloud/docs/api/redact#redact).

        Examples:
            response = redact.redact(RedactInput(text="Jenny Jenny... 415-867-5309"))

            \"\"\"
            response contains:
            {
                "request_id": "prq_2aonw26nr3n5hjovo476252npmekem4u",
                "request_time": "2022-07-06T23:34:46.666Z",
                "response_time": "2022-07-06T23:34:46.679Z",
                "status": "success",
                "result": {
                    "redacted_text": "\"<PERSON>... <PHONE_NUMBER>\""
                },
                "summary": "Success. Redacted 2 item(s) from text"
            }
            \"\"\"
        """
        input = RedactRequest(text=text, debug=debug)
        response = self.request.post("redact", data=input.dict(exclude_none=True))
        response.result = RedactResult(**response.raw_result)
        return response

    def redact_structured(
        self,
        data: Union[Dict, str],
        jsonp: Optional[List[str]] = None,
        format: Optional[RedactFormat] = None,
        debug: Optional[bool] = None,
    ) -> PangeaResponse[StructuredResult]:
        """
        Redact structured

        Redacts text within a structured object.

        Args:
            obj (obj): The object that should be redacted
            redact_format (RedactFormat, optional): The format of the passed data
            debug (bool, optional): Return debug output

        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            Pangea Response with redacted data in the response.result field,
                available response fields can be found in our
                [API Documentation](https://pangea.cloud/docs/api/redact#redact-structured)

        Examples:
            response = redact.redact_structured(obj={ "number": "415-867-5309", "ip": "1.1.1.1" }, redact_format="json")

            \"\"\"
            response contains:
            {
                "request_id": "prq_m2z76gv4mcsbysy4ssu4covympg3sske",
                "request_time": "2022-07-06T23:35:41.524Z",
                "response_time": "2022-07-06T23:35:41.543Z",
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
        input = StructuredRequest(data=data, jsonp=jsonp, format=format, debug=debug)
        response = self.request.post("redact_structured", data=input.dict(exclude_none=True))
        response.result = StructuredResult(**response.raw_result)
        return response
