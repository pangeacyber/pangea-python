# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation

import enum
from typing import Dict, List, Optional, Union

from pangea.response import APIRequestModel, APIResponseModel, PangeaResponse, PangeaResponseResult
from pangea.services.base import ServiceBase


class RedactFormat(str, enum.Enum):
    """Structured data format."""

    JSON = "json"
    """JSON format."""


class RedactRequest(APIRequestModel):
    """
    Input class to make a redact request
    """

    text: str
    debug: Optional[bool] = None
    rules: Optional[List[str]] = None
    rulesets: Optional[List[str]] = None
    return_result: Optional[bool] = None


class RecognizerResult(APIResponseModel):
    """
    The scoring result of a rule

    Arguments:
    field_type: The entity name
    score: The certainty score that the entity matches this specific snippet
    text: The text snippet that matched
    start: The starting index of a snippet
    end: The ending index of a snippet
    redacted: Indicates if this rule was used to anonymize a text snippet
    data_key: If this result relates to a specific structured text field, the key pointing to this text will be provided
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
    Describes the decision process for redactions
    """

    summary_counts: Dict[str, int]
    recognizer_results: List[RecognizerResult]


class RedactResult(PangeaResponseResult):
    """
    Result class after a redact request

    Arguments:
    redact_text: Redacted text result
    count: Number of redactions present in the text
    report: Describes the decision process for redactions
    """

    redacted_text: Optional[str] = None
    count: int
    report: Optional[DebugReport] = None


class StructuredRequest(APIRequestModel):
    """
    Class input to redact structured data request

    Arguments:
    data: Structured data to redact
    jsonp: JSON path(s) used to identify the specific JSON fields to redact in the structured data. Note: If jsonp parameter is used, the data parameter must be in JSON format.
    format: The format of the structured data to redact. (default is JSON)
    debug: Setting this value to true will provide a detailed analysis of the redacted data and the rules that caused redaction.
    """

    data: Union[Dict, str]
    jsonp: Optional[List[str]] = None
    format: Optional[RedactFormat] = None
    debug: Optional[bool] = None
    rules: Optional[List[str]] = None
    rulesets: Optional[List[str]] = None
    return_result: Optional[bool] = None


class StructuredResult(PangeaResponseResult):
    """
    Result class after a structured redact request

    """

    redacted_data: Optional[Union[Dict, str]] = None
    count: int
    report: Optional[DebugReport] = None


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

    def __init__(self, token, config=None, logger_name="pangea", config_id: Optional[str] = None):
        super().__init__(token, config, logger_name, config_id=config_id)

    def redact(
        self,
        text: str,
        debug: Optional[bool] = None,
        rules: Optional[List[str]] = None,
        rulesets: Optional[List[str]] = None,
        return_result: Optional[bool] = None,
    ) -> PangeaResponse[RedactResult]:
        """
        Redact

        Redact sensitive information from provided text.

        OperationId: redact_post_v1_redact

        Args:
            text (str): The text data to redact
            debug (bool, optional): Setting this value to true will provide a detailed analysis of
                the redacted data and the rules that caused redaction
            rules (list[str], optional): An array of redact rule short names
            rulesets (list[str], optional): An array of redact rulesets short names
            return_result(bool, optional): Setting this value to false will omit the redacted result only returning count

        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            Pangea Response with redacted text in the response.result property,
                available response fields can be found in our
                [API Documentation](https://pangea.cloud/docs/api/redact#redact).

        Examples:
            response = redact.redact(text="Jenny Jenny... 555-867-5309")
        """

        input = RedactRequest(text=text, debug=debug, rules=rules, rulesets=rulesets, return_result=return_result)
        return self.request.post("v1/redact", RedactResult, data=input.dict(exclude_none=True))

    def redact_structured(
        self,
        data: Union[Dict, str],
        jsonp: Optional[List[str]] = None,
        format: Optional[RedactFormat] = None,
        debug: Optional[bool] = None,
        rules: Optional[List[str]] = None,
        rulesets: Optional[List[str]] = None,
        return_result: Optional[bool] = None,
    ) -> PangeaResponse[StructuredResult]:
        """
        Redact structured

        Redact sensitive information from structured data (e.g., JSON).

        OperationId: redact_post_v1_redact_structured

        Args:
            data (dict, str): Structured data to redact
            jsonp (list[str]): JSON path(s) used to identify the specific JSON fields to redact in
                the structured data. Note: If jsonp parameter is used, the data parameter must be
                in JSON format.
            format (RedactFormat, optional): The format of the passed data. Default: "json"
            debug (bool, optional): Setting this value to true will provide a detailed analysis of
                the redacted data and the rules that caused redaction
            rules (list[str], optional): An array of redact rule short names
            rulesets (list[str], optional): An array of redact rulesets short names
            return_result(bool, optional): Setting this value to false will omit the redacted result only returning count

        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            Pangea Response with redacted data in the response.result field,
                available response fields can be found in our
                [API Documentation](https://pangea.cloud/docs/api/redact#redact-structured)

        Examples:
            data = {
                "number": "555-867-5309",
                "ip": "1.1.1.1",
            }

            response = redact.redact_structured(data=data, redact_format="json")
        """

        input = StructuredRequest(
            data=data,
            jsonp=jsonp,
            format=format,
            debug=debug,
            rules=rules,
            rulesets=rulesets,
            return_result=return_result,
        )
        return self.request.post("v1/redact_structured", StructuredResult, data=input.dict(exclude_none=True))
