# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation
from __future__ import annotations

import enum
from typing import Dict, List, Optional, Union

from pangea.config import PangeaConfig
from pangea.response import APIRequestModel, APIResponseModel, PangeaResponse, PangeaResponseResult
from pangea.services.base import ServiceBase


class RedactFormat(str, enum.Enum):
    """Structured data format."""

    JSON = "json"
    """JSON format."""


class RedactType(str, enum.Enum):
    MASK = "mask"
    PARTIAL_MASKING = "partial_masking"
    REPLACEMENT = "replacement"
    DETECT_ONLY = "detect_only"
    HASH = "hash"
    FPE = "fpe"


class FPEAlphabet(str, enum.Enum):
    NUMERIC = "numeric"
    ALPHANUMERICLOWER = "alphanumericlower"
    ALPHANUMERIC = "alphanumeric"


class MaskingType(str, enum.Enum):
    MASK = "mask"
    UNMASK = "unmask"


class PartialMasking(APIRequestModel):
    masking_type: Optional[MaskingType] = None
    unmasked_from_left: Optional[int] = None
    unmasked_from_right: Optional[int] = None
    masked_from_left: Optional[int] = None
    masked_from_right: Optional[int] = None
    chars_to_ignore: Optional[List[str]] = None
    masking_char: Optional[List[str]] = None


class RedactionMethodOverrides(APIRequestModel):
    redaction_type: RedactType
    hash: Optional[Dict] = None
    fpe_alphabet: Optional[FPEAlphabet] = None
    partial_masking: Optional[PartialMasking] = None
    redaction_value: Optional[str] = None


class RedactRequest(APIRequestModel):
    """
    Input class to make a redact request
    """

    text: str
    debug: Optional[bool] = None
    rules: Optional[List[str]] = None
    rulesets: Optional[List[str]] = None
    return_result: Optional[bool] = None
    redaction_method_overrides: Optional[RedactionMethodOverrides] = None
    vault_parameters: Optional[VaultParameters] = None
    llm_request: Optional[bool] = None
    """Is this redact call going to be used in an LLM request?"""


class VaultParameters(APIRequestModel):
    fpe_key_id: Optional[str] = None
    """A vault key ID of an exportable key used to redact with FPE instead of using the service config default."""

    salt_secret_id: Optional[str] = None
    """A vault secret ID of a secret used to salt a hash instead of using the service config default."""


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
    fpe_context: FPE context used to encrypt and redact data
    """

    redacted_text: Optional[str] = None
    count: int
    report: Optional[DebugReport] = None
    fpe_context: Optional[str] = None


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
    redaction_method_overrides: Optional[RedactionMethodOverrides] = None
    vault_parameters: Optional[VaultParameters] = None
    llm_request: Optional[bool] = None
    """Is this redact call going to be used in an LLM request?"""


class StructuredResult(PangeaResponseResult):
    """
    Result class after a structured redact request

    """

    redacted_data: Optional[Union[Dict, str]] = None
    count: int
    report: Optional[DebugReport] = None


class UnredactRequest(APIRequestModel):
    """
    Class input to unredact data request

    Arguments:
    redacted_data: Data to unredact
    fpe_context (base64): FPE context used to decrypt and unredact data

    """

    redacted_data: RedactedData
    fpe_context: str


RedactedData = Union[str, Dict]


class UnredactResult(PangeaResponseResult):
    """
    Result class after an unredact request

    """

    data: RedactedData


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

    def __init__(
        self, token: str, config: PangeaConfig | None = None, logger_name: str = "pangea", config_id: str | None = None
    ) -> None:
        """
        Redact client

        Initializes a new Redact client.

        Args:
            token: Pangea API token.
            config: Configuration.
            logger_name: Logger name.
            config_id: Configuration ID.

        Examples:
             config = PangeaConfig(domain="pangea_domain")
             redact = Redact(token="pangea_token", config=config)
        """
        super().__init__(token, config, logger_name, config_id=config_id)

    def redact(
        self,
        text: str,
        debug: Optional[bool] = None,
        rules: Optional[List[str]] = None,
        rulesets: Optional[List[str]] = None,
        return_result: Optional[bool] = None,
        redaction_method_overrides: Optional[RedactionMethodOverrides] = None,
        llm_request: Optional[bool] = None,
        vault_parameters: Optional[VaultParameters] = None,
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
            redaction_method_overrides: A set of redaction method overrides for any enabled rule. These methods override the config declared methods
            llm_request: Boolean flag to enable FPE redaction for LLM requests
            vault_parameters: A set of vault parameters to use for redaction

        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            Pangea Response with redacted text in the response.result property,
                available response fields can be found in our
                [API Documentation](https://pangea.cloud/docs/api/redact#redact).

        Examples:
            response = redact.redact(text="Jenny Jenny... 555-867-5309")
        """

        input = RedactRequest(
            text=text,
            debug=debug,
            rules=rules,
            rulesets=rulesets,
            return_result=return_result,
            redaction_method_overrides=redaction_method_overrides,
            llm_request=llm_request,
            vault_parameters=vault_parameters,
        )
        return self.request.post("v1/redact", RedactResult, data=input.model_dump(exclude_none=True))

    def redact_structured(
        self,
        data: Union[Dict, str],
        jsonp: Optional[List[str]] = None,
        format: Optional[RedactFormat] = None,
        debug: Optional[bool] = None,
        rules: Optional[List[str]] = None,
        rulesets: Optional[List[str]] = None,
        return_result: Optional[bool] = None,
        redaction_method_overrides: Optional[RedactionMethodOverrides] = None,
        llm_request: Optional[bool] = None,
        vault_parameters: Optional[VaultParameters] = None,
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
            redaction_method_overrides: A set of redaction method overrides for any enabled rule. These methods override the config declared methods
            llm_request: Boolean flag to enable FPE redaction for LLM requests
            vault_parameters: A set of vault parameters to use for redaction

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
            redaction_method_overrides=redaction_method_overrides,
            llm_request=llm_request,
            vault_parameters=vault_parameters,
        )
        return self.request.post("v1/redact_structured", StructuredResult, data=input.model_dump(exclude_none=True))

    def unredact(self, redacted_data: RedactedData, fpe_context: str) -> PangeaResponse[UnredactResult]:
        """
        Unredact

        Decrypt or unredact fpe redactions

        OperationId: redact_post_v1_unredact

        Args:
            redacted_data: Data to unredact
            fpe_context (base64): FPE context used to decrypt and unredact data

        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            Pangea Response with redacted data in the response.result field,
                available response fields can be found in our
                [API Documentation](https://pangea.cloud/docs/api/redact#unredact)
        """
        input = UnredactRequest(redacted_data=redacted_data, fpe_context=fpe_context)
        return self.request.post("v1/unredact", UnredactResult, data=input.model_dump(exclude_none=True))
