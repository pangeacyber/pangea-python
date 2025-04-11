# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation
from __future__ import annotations

import enum
from collections.abc import Mapping, Sequence
from typing import Dict, List, Optional, Union, cast, overload

from pydantic import Field, TypeAdapter
from typing_extensions import Annotated, Literal

from pangea.config import PangeaConfig
from pangea.response import APIRequestModel, APIResponseModel, PangeaResponse, PangeaResponseResult
from pangea.services.base import ServiceBase

MatcherType = Literal[
    "CREDIT_CARD",
    "CRYPTO",
    "DATE_TIME",
    "EMAIL_ADDRESS",
    "IBAN_CODE",
    "IP_ADDRESS",
    "NRP",
    "LOCATION",
    "PERSON",
    "PHONE_NUMBER",
    "MEDICAL_LICENSE",
    "URL",
    "US_BANK_NUMBER",
    "US_DRIVER_LICENSE",
    "US_ITIN",
    "US_PASSPORT",
    "US_SSN",
    "UK_NHS",
    "NIF",
    "FIN/NRIC",
    "AU_ABN",
    "AU_ACN",
    "AU_TFN",
    "AU_MEDICARE",
    "FIREBASE_URL",
    "RSA_PRIVATE_KEY",
    "SSH_DSA_PRIVATE_KEY",
    "SSH_EC_PRIVATE_KEY",
    "PGP_PRIVATE_KEY_BLOCK",
    "AMAZON_AWS_ACCESS_KEY_ID",
    "AMAZON_AWS_SECRET_ACCESS_KEY",
    "AMAZON_MWS_AUTH_TOKEN",
    "FACEBOOK_ACCESS_TOKEN",
    "GITHUB_ACCESS_TOKEN",
    "JWT_TOKEN",
    "GOOGLE_API_KEY",
    "GOOGLE_CLOUD_PLATFORM_API_KEY",
    "GOOGLE_DRIVE_API_KEY",
    "GOOGLE_CLOUD_PLATFORM_SERVICE_ACCOUNT",
    "GOOGLE_GMAIL_API_KEY",
    "YOUTUBE_API_KEY",
    "MAILCHIMP_API_KEY",
    "MAILGUN_API_KEY",
    "MONEY",
    "BASIC_AUTH",
    "PICATIC_API_KEY",
    "SLACK_TOKEN",
    "SLACK_WEBHOOK",
    "STRIPE_API_KEY",
    "STRIPE_RESTRICTED_API_KEY",
    "SQUARE_ACCESS_TOKEN",
    "SQUARE_OAUTH_SECRET",
    "TWILIO_API_KEY",
    "PANGEA_TOKEN",
    "PROFANITY",
]


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
    masking_char: Optional[str] = Field(min_length=1, max_length=1)


class Redaction(APIRequestModel):
    redaction_type: RedactType
    hash: Optional[Dict] = None
    fpe_alphabet: Optional[FPEAlphabet] = None
    partial_masking: Optional[PartialMasking] = None
    redaction_value: Optional[str] = None


class RedactionMethodOverrides(Redaction):
    """This field allows users to specify the redaction method per rule and its various parameters."""


class RedactRequest(APIRequestModel):
    """
    Input class to make a redact request
    """

    text: str
    debug: Optional[bool] = None
    rules: Optional[List[str]] = None
    rulesets: Optional[List[str]] = None
    return_result: Optional[bool] = None
    redaction_method_overrides: Optional[Mapping[str, RedactionMethodOverrides]] = None
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
    redaction_method_overrides: Optional[Mapping[str, RedactionMethodOverrides]] = None
    vault_parameters: Optional[VaultParameters] = None
    llm_request: Optional[bool] = None
    """Is this redact call going to be used in an LLM request?"""


class StructuredResult(PangeaResponseResult):
    """
    Result class after a structured redact request
    """

    redacted_data: Optional[Union[Dict, str]] = None
    """Redacted data result"""

    count: int
    """Number of redactions present in the text"""

    report: Optional[DebugReport] = None
    """Describes the decision process for redactions"""

    fpe_context: Optional[str] = None
    """FPE context used to encrypt and redact data"""


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


class Matcher(APIResponseModel):
    match_type: str
    match_value: str
    match_score: float


class RuleV1(APIResponseModel):
    entity_name: str
    matchers: Union[List[Matcher], MatcherType]
    ruleset: str

    match_threshold: Optional[float] = None
    context_values: Optional[List[str]] = None
    name: Optional[str] = None
    description: Optional[str] = None


class RuleV2(APIResponseModel):
    entity_name: str
    matchers: Union[List[Matcher], MatcherType]

    match_threshold: Optional[float] = None
    context_values: Optional[List[str]] = None
    negative_context_values: Optional[List[str]] = None
    name: Optional[str] = None
    description: Optional[str] = None


class RulesetV1(APIResponseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    rules: List[str]


class RulesetV2(APIResponseModel):
    name: Optional[str] = None
    description: Optional[str] = None


class ServiceConfigV1(PangeaResponseResult):
    version: Literal["1.0.0"] = "1.0.0"
    id: str
    name: str
    updated_at: str
    enabled_rules: List[str]

    redactions: Optional[Dict[str, Redaction]] = None

    vault_service_config_id: Optional[str] = None
    """Service config used to create the secret"""

    salt_vault_secret_id: Optional[str] = None
    """Pangea only allows hashing to be done using a salt value to prevent brute-force attacks."""

    rules: Optional[Dict[str, RuleV1]] = None
    rulesets: Optional[Dict[str, RulesetV1]] = None
    supported_languages: Optional[List[Literal["en"]]] = None


class ServiceConfigV2(PangeaResponseResult):
    version: Literal["2.0.0"] = "2.0.0"
    id: str
    name: str
    updated_at: str
    enabled_rules: List[str]

    enforce_enabled_rules: Optional[bool] = None
    """Always run service config enabled rules across all redact calls regardless of flags?"""

    redactions: Optional[Dict[str, Redaction]] = None

    vault_service_config_id: Optional[str] = None
    """Service config used to create the secret"""

    salt_vault_secret_id: Optional[str] = None
    """Pangea only allows hashing to be done using a salt value to prevent brute-force attacks."""

    fpe_vault_secret_id: Optional[str] = None
    """The ID of the key used by FF3 Encryption algorithms for FPE."""

    rules: Optional[Dict[str, RuleV2]] = None
    rulesets: Optional[Dict[str, RulesetV2]] = None
    supported_languages: Optional[List[Literal["en"]]] = None


ServiceConfigResult = Annotated[Union[ServiceConfigV1, ServiceConfigV2], Field(discriminator="version")]


class ServiceConfigFilter(APIRequestModel):
    id: Optional[str] = None
    """Only records where id equals this value."""

    id__contains: Optional[Sequence[str]] = None
    """Only records where id includes each substring."""

    id__in: Optional[Sequence[str]] = None
    """Only records where id equals one of the provided substrings."""

    created_at: Optional[str] = None
    """Only records where created_at equals this value."""

    created_at__gt: Optional[str] = None
    """Only records where created_at is greater than this value."""

    created_at__gte: Optional[str] = None
    """Only records where created_at is greater than or equal to this value."""

    created_at__lt: Optional[str] = None
    """Only records where created_at is less than this value."""

    created_at__lte: Optional[str] = None
    """Only records where created_at is less than or equal to this value."""

    updated_at: Optional[str] = None
    """Only records where updated_at equals this value."""

    updated_at__gt: Optional[str] = None
    """Only records where updated_at is greater than this value."""

    updated_at__gte: Optional[str] = None
    """Only records where updated_at is greater than or equal to this value."""

    updated_at__lt: Optional[str] = None
    """Only records where updated_at is less than this value."""

    updated_at__lte: Optional[str] = None
    """Only records where updated_at is less than or equal to this value."""


class ServiceConfigListResult(PangeaResponseResult):
    count: int
    """The total number of service configs matched by the list request."""

    last: str
    """Used to fetch the next page of the current listing when provided in a repeated request's last parameter."""

    items: Sequence[ServiceConfigResult]


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
        redaction_method_overrides: Optional[Mapping[str, RedactionMethodOverrides]] = None,
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
        redaction_method_overrides: Mapping[str, RedactionMethodOverrides] | None = None,
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

    def get_service_config(self, config_id: str) -> PangeaResponse[ServiceConfigResult]:
        """
        Get a service config.


        OperationId: redact_post_v1beta_config
        """
        response = self.request.post("v1beta/config", PangeaResponseResult, data={"id": config_id})
        response.result = TypeAdapter(ServiceConfigResult).validate_python(response.json["result"])
        return cast(PangeaResponse[ServiceConfigResult], response)

    @overload
    def create_service_config(
        self,
        name: str,
        *,
        version: Literal["1.0.0"],
        enabled_rules: Sequence[str] | None = None,
        redactions: Mapping[str, Redaction] | None = None,
        vault_service_config_id: str | None = None,
        salt_vault_secret_id: str | None = None,
        rules: Mapping[str, RuleV1] | None = None,
        rulesets: Mapping[str, RulesetV1] | None = None,
        supported_languages: Sequence[Literal["en"]] | None = None,
    ) -> PangeaResponse[ServiceConfigResult]:
        """
        Create a v1.0.0 service config.

        OperationId: redact_post_v1beta_config_create

        Args:
            vault_service_config_id: Service config used to create the secret
            salt_vault_secret_id: Pangea only allows hashing to be done using a salt value to prevent brute-force attacks.
        """

    @overload
    def create_service_config(
        self,
        name: str,
        *,
        version: Literal["2.0.0"] | None = None,
        enabled_rules: Sequence[str] | None = None,
        enforce_enabled_rules: bool | None = None,
        redactions: Mapping[str, Redaction] | None = None,
        vault_service_config_id: str | None = None,
        salt_vault_secret_id: str | None = None,
        fpe_vault_secret_id: str | None = None,
        rules: Mapping[str, RuleV2] | None = None,
        rulesets: Mapping[str, RulesetV2] | None = None,
        supported_languages: Sequence[Literal["en"]] | None = None,
    ) -> PangeaResponse[ServiceConfigResult]:
        """
        Create a v2.0.0 service config.

        OperationId: redact_post_v1beta_config_create

        Args:
            enforce_enabled_rules: Always run service config enabled rules across all redact calls regardless of flags?
            vault_service_config_id: Service config used to create the secret
            salt_vault_secret_id: Pangea only allows hashing to be done using a salt value to prevent brute-force attacks.
            fpe_vault_secret_id: The ID of the key used by FF3 Encryption algorithms for FPE.
        """

    def create_service_config(
        self,
        name: str,
        *,
        version: Literal["1.0.0", "2.0.0"] | None = None,
        enabled_rules: Sequence[str] | None = None,
        enforce_enabled_rules: bool | None = None,
        fpe_vault_secret_id: str | None = None,
        redactions: Mapping[str, Redaction] | None = None,
        rules: Mapping[str, RuleV1 | RuleV2] | None = None,
        rulesets: Mapping[str, RulesetV1 | RulesetV2] | None = None,
        salt_vault_secret_id: str | None = None,
        supported_languages: Sequence[Literal["en"]] | None = None,
        vault_service_config_id: str | None = None,
    ) -> PangeaResponse[ServiceConfigResult]:
        """
        Create a service config.

        OperationId: redact_post_v1beta_config_create

        Args:
            enforce_enabled_rules: Always run service config enabled rules across all redact calls regardless of flags?
            fpe_vault_secret_id: The ID of the key used by FF3 Encryption algorithms for FPE.
            salt_vault_secret_id: Pangea only allows hashing to be done using a salt value to prevent brute-force attacks.
            vault_service_config_id: Service config used to create the secret
        """

        response = self.request.post(
            "v1beta/config/create",
            PangeaResponseResult,
            data={
                "name": name,
                "version": version,
                "enabled_rules": enabled_rules,
                "enforce_enabled_rules": enforce_enabled_rules,
                "fpe_vault_secret_id": fpe_vault_secret_id,
                "redactions": redactions,
                "rules": rules,
                "rulesets": rulesets,
                "salt_vault_secret_id": salt_vault_secret_id,
                "supported_languages": supported_languages,
                "vault_service_config_id": vault_service_config_id,
            },
        )
        response.result = TypeAdapter(ServiceConfigResult).validate_python(response.json["result"])
        return cast(PangeaResponse[ServiceConfigResult], response)

    @overload
    def update_service_config(
        self,
        config_id: str,
        *,
        version: Literal["1.0.0"],
        name: str,
        updated_at: str,
        enabled_rules: Sequence[str] | None = None,
        redactions: Mapping[str, Redaction] | None = None,
        vault_service_config_id: str | None = None,
        salt_vault_secret_id: str | None = None,
        rules: Mapping[str, RuleV1] | None = None,
        rulesets: Mapping[str, RulesetV1] | None = None,
        supported_languages: Sequence[Literal["en"]] | None = None,
    ) -> PangeaResponse[ServiceConfigResult]:
        """
        Update a v1.0.0 service config.

        OperationId: redact_post_v1beta_config_update

        Args:
            vault_service_config_id: Service config used to create the secret
            salt_vault_secret_id: Pangea only allows hashing to be done using a salt value to prevent brute-force attacks.
        """

    @overload
    def update_service_config(
        self,
        config_id: str,
        *,
        version: Literal["2.0.0"] | None = None,
        name: str,
        updated_at: str,
        enabled_rules: Sequence[str] | None = None,
        enforce_enabled_rules: bool | None = None,
        redactions: Mapping[str, Redaction] | None = None,
        vault_service_config_id: str | None = None,
        salt_vault_secret_id: str | None = None,
        fpe_vault_secret_id: str | None = None,
        rules: Mapping[str, RuleV2] | None = None,
        rulesets: Mapping[str, RulesetV2] | None = None,
        supported_languages: Sequence[Literal["en"]] | None = None,
    ) -> PangeaResponse[ServiceConfigResult]:
        """
        Update a v2.0.0 service config.

        OperationId: redact_post_v1beta_config_update

        Args:
            enforce_enabled_rules: Always run service config enabled rules across all redact calls regardless of flags?
            vault_service_config_id: Service config used to create the secret
            salt_vault_secret_id: Pangea only allows hashing to be done using a salt value to prevent brute-force attacks.
            fpe_vault_secret_id: The ID of the key used by FF3 Encryption algorithms for FPE.
        """

    def update_service_config(
        self,
        config_id: str,
        *,
        version: Literal["1.0.0", "2.0.0"] | None = None,
        name: str,
        updated_at: str,
        enabled_rules: Sequence[str] | None = None,
        enforce_enabled_rules: bool | None = None,
        fpe_vault_secret_id: str | None = None,
        redactions: Mapping[str, Redaction] | None = None,
        rules: Mapping[str, RuleV1 | RuleV2] | None = None,
        rulesets: Mapping[str, RulesetV1 | RulesetV2] | None = None,
        salt_vault_secret_id: str | None = None,
        supported_languages: Sequence[Literal["en"]] | None = None,
        vault_service_config_id: str | None = None,
    ) -> PangeaResponse[ServiceConfigResult]:
        """
        Update a service config.

        OperationId: redact_post_v1beta_config_update

        Args:
            enforce_enabled_rules: Always run service config enabled rules across all redact calls regardless of flags?
            fpe_vault_secret_id: The ID of the key used by FF3 Encryption algorithms for FPE.
            salt_vault_secret_id: Pangea only allows hashing to be done using a salt value to prevent brute-force attacks.
            vault_service_config_id: Service config used to create the secret
        """

        response = self.request.post(
            "v1beta/config/update",
            PangeaResponseResult,
            data={
                "id": config_id,
                "updated_at": updated_at,
                "name": name,
                "version": version,
                "enabled_rules": enabled_rules,
                "enforce_enabled_rules": enforce_enabled_rules,
                "fpe_vault_secret_id": fpe_vault_secret_id,
                "redactions": redactions,
                "rules": rules,
                "rulesets": rulesets,
                "salt_vault_secret_id": salt_vault_secret_id,
                "supported_languages": supported_languages,
                "vault_service_config_id": vault_service_config_id,
            },
        )
        response.result = TypeAdapter(ServiceConfigResult).validate_python(response.json["result"])
        return cast(PangeaResponse[ServiceConfigResult], response)

    def delete_service_config(
        self,
        config_id: str,
    ) -> PangeaResponse[ServiceConfigResult]:
        """
        Delete a service config.

        OperationId: redact_post_v1beta_config_delete

        Args:
            config_id: An ID for a service config
        """

        response = self.request.post("v1beta/config/delete", PangeaResponseResult, data={"id": config_id})
        response.result = TypeAdapter(ServiceConfigResult).validate_python(response.json["result"])
        return cast(PangeaResponse[ServiceConfigResult], response)

    def list_service_configs(
        self,
        *,
        filter: ServiceConfigFilter | None = None,
        last: str | None = None,
        order: Literal["asc", "desc"] | None = None,
        order_by: Literal["id", "created_at", "updated_at"] | None = None,
        size: int | None = None,
    ) -> PangeaResponse[ServiceConfigListResult]:
        """
        List service configs.

        OperationId: redact_post_v1beta_config_list

        Args:
            last: Reflected value from a previous response to obtain the next page of results.
            order: Order results asc(ending) or desc(ending).
            order_by: Which field to order results by.
            size: Maximum results to include in the response.
        """

        return self.request.post(
            "v1beta/config/list",
            ServiceConfigListResult,
            data={"filter": filter, "last": last, "order": order, "order_by": order_by, "size": size},
        )
