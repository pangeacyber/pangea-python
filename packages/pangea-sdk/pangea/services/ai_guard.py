from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Annotated, Any, Generic, Literal, Optional, Union, overload

from pydantic import BaseModel, ConfigDict, Field, RootModel
from typing_extensions import TypeAlias, TypedDict, TypeVar

from pangea.config import PangeaConfig
from pangea.response import APIRequestModel, APIResponseModel, PangeaDateTime, PangeaResponse, PangeaResponseResult
from pangea.services.base import ServiceBase

# This is named "prompt injection" in the API spec even though it is also used
# for many other detectors.
PromptInjectionAction = Literal["report", "block"]

MaliciousEntityAction = Literal["report", "defang", "disabled", "block"]

# This is named "PII entity" in the API spec even though it is also used for the
# secrets detector.
PiiEntityAction = Literal["disabled", "report", "block", "mask", "partial_masking", "replacement", "hash", "fpe"]


class Message(APIRequestModel):
    role: str
    content: str


class CodeDetectionOverride(APIRequestModel):
    disabled: Optional[bool] = None
    action: Optional[Literal["report", "block"]] = None
    threshold: Optional[float] = None


class LanguageDetectionOverride(APIRequestModel):
    disabled: Optional[bool] = None
    action: Optional[Literal["", "report", "allow", "block"]] = ""
    languages: Optional[list[str]] = None
    threshold: Optional[float] = None


class TopicDetectionOverride(APIRequestModel):
    disabled: Optional[bool] = None
    action: Optional[Literal["", "report", "block"]] = ""
    topics: Optional[list[str]] = None
    threshold: Optional[float] = None


class PromptInjectionOverride(APIRequestModel):
    disabled: Optional[bool] = None
    action: Optional[PromptInjectionAction] = None


class SelfHarmOverride(APIRequestModel):
    disabled: Optional[bool] = None
    action: Optional[PromptInjectionAction] = None
    threshold: Optional[float] = None


class GibberishOverride(APIRequestModel):
    disabled: Optional[bool] = None
    action: Optional[PromptInjectionAction] = None


class RoleplayOverride(APIRequestModel):
    disabled: Optional[bool] = None
    action: Optional[PromptInjectionAction] = None


class SentimentOverride(APIRequestModel):
    disabled: Optional[bool] = None
    action: Optional[PromptInjectionAction] = None
    threshold: Optional[float] = None


class MaliciousEntityOverride(APIRequestModel):
    disabled: Optional[bool] = None
    ip_address: Optional[MaliciousEntityAction] = None
    url: Optional[MaliciousEntityAction] = None
    domain: Optional[MaliciousEntityAction] = None


class CompetitorsOverride(APIRequestModel):
    disabled: Optional[bool] = None
    action: Optional[PromptInjectionAction] = None


class PiiEntityOverride(APIRequestModel):
    disabled: Optional[bool] = None
    email_address: Optional[PiiEntityAction] = None
    nrp: Optional[PiiEntityAction] = None
    location: Optional[PiiEntityAction] = None
    person: Optional[PiiEntityAction] = None
    phone_number: Optional[PiiEntityAction] = None
    date_time: Optional[PiiEntityAction] = None
    ip_address: Optional[PiiEntityAction] = None
    url: Optional[PiiEntityAction] = None
    money: Optional[PiiEntityAction] = None
    credit_card: Optional[PiiEntityAction] = None
    crypto: Optional[PiiEntityAction] = None
    iban_code: Optional[PiiEntityAction] = None
    us_bank_number: Optional[PiiEntityAction] = None
    nif: Optional[PiiEntityAction] = None
    au_abn: Optional[PiiEntityAction] = None
    au_acn: Optional[PiiEntityAction] = None
    au_tfn: Optional[PiiEntityAction] = None
    medical_license: Optional[PiiEntityAction] = None
    uk_nhs: Optional[PiiEntityAction] = None
    au_medicare: Optional[PiiEntityAction] = None
    us_drivers_license: Optional[PiiEntityAction] = None
    us_itin: Optional[PiiEntityAction] = None
    us_passport: Optional[PiiEntityAction] = None
    us_ssn: Optional[PiiEntityAction] = None


class SecretsDetectionOverride(APIRequestModel):
    disabled: Optional[bool] = None
    slack_token: Optional[PiiEntityAction] = None
    rsa_private_key: Optional[PiiEntityAction] = None
    ssh_dsa_private_key: Optional[PiiEntityAction] = None
    ssh_ec_private_key: Optional[PiiEntityAction] = None
    pgp_private_key_block: Optional[PiiEntityAction] = None
    amazon_aws_access_key_id: Optional[PiiEntityAction] = None
    amazon_aws_secret_access_key: Optional[PiiEntityAction] = None
    amazon_mws_auth_token: Optional[PiiEntityAction] = None
    facebook_access_token: Optional[PiiEntityAction] = None
    github_access_token: Optional[PiiEntityAction] = None
    jwt_token: Optional[PiiEntityAction] = None
    google_api_key: Optional[PiiEntityAction] = None
    google_cloud_platform_api_key: Optional[PiiEntityAction] = None
    google_drive_api_key: Optional[PiiEntityAction] = None
    google_cloud_platform_service_account: Optional[PiiEntityAction] = None
    google_gmail_api_key: Optional[PiiEntityAction] = None
    youtube_api_key: Optional[PiiEntityAction] = None
    mailchimp_api_key: Optional[PiiEntityAction] = None
    mailgun_api_key: Optional[PiiEntityAction] = None
    basic_auth: Optional[PiiEntityAction] = None
    picatic_api_key: Optional[PiiEntityAction] = None
    slack_webhook: Optional[PiiEntityAction] = None
    stripe_api_key: Optional[PiiEntityAction] = None
    stripe_restricted_api_key: Optional[PiiEntityAction] = None
    square_access_token: Optional[PiiEntityAction] = None
    square_oauth_secret: Optional[PiiEntityAction] = None
    twilio_api_key: Optional[PiiEntityAction] = None
    pangea_token: Optional[PiiEntityAction] = None


class Overrides(APIRequestModel):
    """Overrides flags."""

    ignore_recipe: Optional[bool] = None
    """Bypass existing Recipe content and create an on-the-fly Recipe."""

    code_detection: Optional[CodeDetectionOverride] = None
    competitors: Optional[CompetitorsOverride] = None
    gibberish: Optional[GibberishOverride] = None
    language_detection: Optional[LanguageDetectionOverride] = None
    malicious_entity: Optional[MaliciousEntityOverride] = None
    pii_entity: Optional[PiiEntityOverride] = None
    prompt_injection: Optional[PromptInjectionOverride] = None
    roleplay: Optional[RoleplayOverride] = None
    secrets_detection: Optional[SecretsDetectionOverride] = None
    selfharm: Optional[SelfHarmOverride] = None
    sentiment: Optional[SentimentOverride] = None
    topic: Optional[TopicDetectionOverride] = None


class LogFields(APIRequestModel):
    """Additional fields to include in activity log"""

    citations: Optional[str] = None
    """Origin or source application of the event"""

    extra_info: Optional[str] = None
    """Stores supplementary details related to the event"""

    model: Optional[str] = None
    """Model used to perform the event"""

    source: Optional[str] = None
    """IP address of user or app or agent"""

    tools: Optional[str] = None
    """Tools used to perform the event"""


class AnalyzerResponse(APIResponseModel):
    analyzer: str
    confidence: float


class PromptInjectionResult(APIResponseModel):
    action: str
    """The action taken by this Detector"""

    analyzer_responses: list[AnalyzerResponse]
    """Triggered prompt injection analyzers."""


class PiiEntity(APIResponseModel):
    type: str
    value: str
    action: str
    """The action taken on this Entity"""
    start_pos: Optional[int] = None


class PiiEntityResult(APIResponseModel):
    entities: list[PiiEntity]
    """Detected redaction rules."""


class MaliciousEntity(APIResponseModel):
    type: str
    value: str
    action: Optional[str] = None
    start_pos: Optional[int] = None
    raw: Optional[dict[str, object]] = None


class MaliciousEntityResult(APIResponseModel):
    entities: list[MaliciousEntity]
    """Detected harmful items."""


class CustomEntity(APIResponseModel):
    type: str
    value: str
    action: str
    """The action taken on this Entity"""
    start_pos: Optional[int] = None
    raw: Optional[dict[str, object]] = None


class CustomEntityResult(APIResponseModel):
    entities: list[CustomEntity]
    """Detected redaction rules."""


class SecretsEntity(APIResponseModel):
    type: str
    value: str
    action: str
    """The action taken on this Entity"""
    start_pos: Optional[int] = None
    redacted_value: Optional[str] = None


class SecretsEntityResult(APIResponseModel):
    entities: list[SecretsEntity]
    """Detected redaction rules."""


class LanguageDetectionResult(APIResponseModel):
    action: Optional[str] = None
    """The action taken by this Detector"""

    language: Optional[str] = None


class Topic(APIResponseModel):
    topic: str
    confidence: float


class TopicDetectionResult(APIResponseModel):
    action: Optional[str] = None
    """The action taken by this Detector"""

    topics: Optional[list[Topic]] = None
    """List of topics detected"""


class CodeDetectionResult(APIResponseModel):
    language: str
    action: str
    """The action taken by this Detector"""


_T = TypeVar("_T")


class TextGuardDetector(APIResponseModel, Generic[_T]):
    detected: Optional[bool] = None
    data: Optional[_T] = None


class TextGuardDetectors(APIResponseModel):
    code_detection: Optional[TextGuardDetector[CodeDetectionResult]] = None
    competitors: Optional[TextGuardDetector[object]] = None
    custom_entity: Optional[TextGuardDetector[object]] = None
    gibberish: Optional[TextGuardDetector[object]] = None
    hardening: Optional[TextGuardDetector[object]] = None
    language_detection: Optional[TextGuardDetector[LanguageDetectionResult]] = None
    malicious_entity: Optional[TextGuardDetector[MaliciousEntityResult]] = None
    pii_entity: Optional[TextGuardDetector[PiiEntityResult]] = None
    profanity_and_toxicity: Optional[TextGuardDetector[object]] = None
    prompt_injection: Optional[TextGuardDetector[PromptInjectionResult]] = None
    secrets_detection: Optional[TextGuardDetector[SecretsEntityResult]] = None
    selfharm: Optional[TextGuardDetector[object]] = None
    sentiment: Optional[TextGuardDetector[object]] = None
    topic: Optional[TextGuardDetector[TopicDetectionResult]] = None


class TextGuardResult(PangeaResponseResult):
    detectors: TextGuardDetectors
    """Result of the recipe analyzing and input prompt."""

    access_rules: Optional[object] = None
    """Result of the recipe evaluating configured rules"""

    blocked: Optional[bool] = None
    """Whether or not the prompt triggered a block detection."""

    fpe_context: Optional[str] = None
    """
    If an FPE redaction method returned results, this will be the context passed to
    unredact.
    """

    prompt_messages: Optional[object] = None
    """Updated structured prompt, if applicable."""

    prompt_text: Optional[str] = None
    """Updated prompt text, if applicable."""

    recipe: Optional[str] = None
    """The Recipe that was used."""

    transformed: Optional[bool] = None
    """Whether or not the original input was transformed."""


class GuardDetectors(APIResponseModel):
    code: Optional[object] = None
    competitors: Optional[object] = None
    confidential_and_pii_entity: Optional[object] = None
    custom_entity: Optional[object] = None
    language: Optional[object] = None
    malicious_entity: Optional[object] = None
    malicious_prompt: Optional[object] = None
    prompt_hardening: Optional[object] = None
    secret_and_key_entity: Optional[object] = None
    topic: Optional[object] = None


class GuardResult(PangeaResponseResult):
    detectors: GuardDetectors
    """Result of the recipe analyzing and input prompt."""

    access_rules: Optional[object] = None
    """Result of the recipe evaluating configured rules"""

    blocked: Optional[bool] = None
    """Whether or not the prompt triggered a block detection."""

    fpe_context: Optional[str] = None
    """
    If an FPE redaction method returned results, this will be the context passed
    to unredact.
    """

    input_token_count: Optional[float] = None
    """Number of tokens counted in the input"""

    output: Optional[object] = None
    """Updated structured prompt."""

    output_token_count: Optional[float] = None
    """Number of tokens counted in the output"""

    recipe: Optional[str] = None
    """The Recipe that was used."""

    transformed: Optional[bool] = None
    """Whether or not the original input was transformed."""


class Areas(BaseModel):
    model_config = ConfigDict(extra="forbid")

    text_guard: bool


class AuditDataActivityConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool
    audit_service_config_id: str
    areas: Areas


class PromptGuard(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: Optional[bool] = None
    config_id: Optional[str] = None
    confidence_threshold: Optional[float] = None


class IpIntel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: Optional[bool] = None
    config_id: Optional[str] = None
    reputation_provider: Optional[str] = None
    risk_threshold: Optional[float] = None


class UserIntel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: Optional[bool] = None
    config_id: Optional[str] = None
    breach_provider: Optional[str] = None


class UrlIntel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: Optional[bool] = None
    config_id: Optional[str] = None
    reputation_provider: Optional[str] = None
    risk_threshold: Optional[float] = None


class DomainIntel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: Optional[bool] = None
    config_id: Optional[str] = None
    reputation_provider: Optional[str] = None
    risk_threshold: Optional[float] = None


class FileScan(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: Optional[bool] = None
    config_id: Optional[str] = None
    scan_provider: Optional[str] = None
    risk_threshold: Optional[float] = None


class Redact(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: Optional[bool] = None
    config_id: Optional[str] = None


class Vault(BaseModel):
    model_config = ConfigDict(extra="forbid")

    config_id: Optional[str] = None


class Lingua(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: Optional[bool] = None


class Code(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: Optional[bool] = None


class ConnectionsConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    prompt_guard: Optional[PromptGuard] = None
    ip_intel: Optional[IpIntel] = None
    user_intel: Optional[UserIntel] = None
    url_intel: Optional[UrlIntel] = None
    domain_intel: Optional[DomainIntel] = None
    file_scan: Optional[FileScan] = None
    redact: Optional[Redact] = None
    vault: Optional[Vault] = None
    lingua: Optional[Lingua] = None
    code: Optional[Code] = None


class PartialMasking(BaseModel):
    masking_type: Optional[Literal["unmask", "mask"]] = "unmask"
    unmasked_from_left: Annotated[Optional[int], Field(ge=0)] = None
    unmasked_from_right: Annotated[Optional[int], Field(ge=0)] = None
    masked_from_left: Annotated[Optional[int], Field(ge=0)] = None
    masked_from_right: Annotated[Optional[int], Field(ge=0)] = None
    chars_to_ignore: Optional[list[CharsToIgnoreItem]] = None
    masking_char: Annotated[Optional[str], Field(max_length=1, min_length=1)] = "*"


class RuleRedactionConfig1(APIResponseModel):
    redaction_type: Literal[
        "mask",
        "partial_masking",
        "replacement",
        "hash",
        "detect_only",
        "fpe",
        "mask",
        "detect_only",
    ]
    """Redaction method to apply for this rule"""
    redaction_value: Optional[str] = None
    partial_masking: Optional[PartialMasking] = None
    hash: Optional[Hash] = None
    fpe_alphabet: Optional[
        Literal[
            "numeric",
            "alphalower",
            "alphaupper",
            "alpha",
            "alphanumericlower",
            "alphanumericupper",
            "alphanumeric",
        ]
    ] = None


class PartialMasking1(BaseModel):
    masking_type: Optional[Literal["unmask", "mask"]] = "unmask"
    unmasked_from_left: Annotated[Optional[int], Field(ge=0)] = None
    unmasked_from_right: Annotated[Optional[int], Field(ge=0)] = None
    masked_from_left: Annotated[Optional[int], Field(ge=0)] = None
    masked_from_right: Annotated[Optional[int], Field(ge=0)] = None
    chars_to_ignore: Optional[list[CharsToIgnoreItem]] = None
    masking_char: Annotated[Optional[str], Field(max_length=1, min_length=1)] = "*"


class RuleRedactionConfig2(BaseModel):
    model_config = ConfigDict(extra="forbid")

    redaction_type: Literal["replacement"]
    redaction_value: str
    partial_masking: Optional[PartialMasking1] = None
    hash: Optional[Hash] = None
    fpe_alphabet: Optional[
        Literal[
            "numeric",
            "alphalower",
            "alphaupper",
            "alpha",
            "alphanumericlower",
            "alphanumericupper",
            "alphanumeric",
        ]
    ] = None


class PartialMasking2(BaseModel):
    masking_type: Optional[Literal["unmask", "mask"]] = "unmask"
    unmasked_from_left: Annotated[Optional[int], Field(ge=0)] = None
    unmasked_from_right: Annotated[Optional[int], Field(ge=0)] = None
    masked_from_left: Annotated[Optional[int], Field(ge=0)] = None
    masked_from_right: Annotated[Optional[int], Field(ge=0)] = None
    chars_to_ignore: Optional[list[CharsToIgnoreItem]] = None
    masking_char: Annotated[Optional[str], Field(max_length=1, min_length=1)] = "*"


class RuleRedactionConfig3(BaseModel):
    model_config = ConfigDict(extra="forbid")

    redaction_type: Literal["partial_masking"]
    redaction_value: str
    partial_masking: PartialMasking2
    hash: Optional[Hash] = None
    fpe_alphabet: Optional[
        Literal[
            "numeric",
            "alphalower",
            "alphaupper",
            "alpha",
            "alphanumericlower",
            "alphanumericupper",
            "alphanumeric",
        ]
    ] = None


class PartialMasking3(BaseModel):
    masking_type: Optional[Literal["unmask", "mask"]] = "unmask"
    unmasked_from_left: Annotated[Optional[int], Field(ge=0)] = None
    unmasked_from_right: Annotated[Optional[int], Field(ge=0)] = None
    masked_from_left: Annotated[Optional[int], Field(ge=0)] = None
    masked_from_right: Annotated[Optional[int], Field(ge=0)] = None
    chars_to_ignore: Optional[list[CharsToIgnoreItem]] = None
    masking_char: Annotated[Optional[str], Field(max_length=1, min_length=1)] = "*"


class RuleRedactionConfig4(BaseModel):
    model_config = ConfigDict(extra="forbid")

    redaction_type: Literal["hash"]
    redaction_value: str
    partial_masking: PartialMasking3
    hash: Optional[Hash] = None
    fpe_alphabet: Optional[
        Literal[
            "numeric",
            "alphalower",
            "alphaupper",
            "alpha",
            "alphanumericlower",
            "alphanumericupper",
            "alphanumeric",
        ]
    ] = None


class CharsToIgnoreItem(RootModel[str]):
    root: Annotated[str, Field(max_length=1, min_length=1)]


class PartialMasking4(BaseModel):
    masking_type: Optional[Literal["unmask", "mask"]] = "unmask"
    unmasked_from_left: Annotated[Optional[int], Field(ge=0)] = None
    unmasked_from_right: Annotated[Optional[int], Field(ge=0)] = None
    masked_from_left: Annotated[Optional[int], Field(ge=0)] = None
    masked_from_right: Annotated[Optional[int], Field(ge=0)] = None
    chars_to_ignore: Optional[list[CharsToIgnoreItem]] = None
    masking_char: Annotated[Optional[str], Field(max_length=1, min_length=1)] = "*"


class Hash(BaseModel):
    hash_type: Literal["md5", "sha256"]
    """The type of hashing algorithm"""


class RuleRedactionConfig5(BaseModel):
    model_config = ConfigDict(extra="forbid")

    redaction_type: Literal["fpe"]
    redaction_value: str
    partial_masking: PartialMasking4
    hash: Optional[Hash] = None
    fpe_alphabet: Optional[
        Literal[
            "numeric",
            "alphalower",
            "alphaupper",
            "alpha",
            "alphanumericlower",
            "alphanumericupper",
            "alphanumeric",
        ]
    ] = None


class Rule(APIResponseModel):
    redact_rule_id: str
    """
    Identifier of the redaction rule to apply. This should match a rule defined
    in the [Redact service](https://pangea.cloud/docs/redact/using-redact/using-redact).
    """
    redaction: Union[
        RuleRedactionConfig1,
        RuleRedactionConfig2,
        RuleRedactionConfig3,
        RuleRedactionConfig4,
        RuleRedactionConfig5,
    ]
    """
    Configuration for the redaction method applied to detected values.

    Each rule supports one redaction type, such as masking, replacement,
    hashing, Format-Preserving Encryption (FPE), or detection-only mode.
    Additional parameters may be required depending on the selected redaction
    type.

    For more details, see the [AI Guard Recipe Actions](https://pangea.cloud/docs/ai-guard/recipes#actions)
    documentation.
    """
    block: Optional[bool] = None
    """
    If `true`, indicates that further processing should be stopped when this
    rule is triggered
    """
    disabled: Optional[bool] = None
    """
    If `true`, disables this specific rule even if the detector is enabled
    """
    reputation_check: Optional[bool] = None
    """
    If `true`, performs a reputation check using the configured intel provider.
    Applies to the Malicious Entity detector when using IP, URL, or Domain Intel
    services.
    """
    transform_if_malicious: Optional[bool] = None
    """
    If `true`, applies redaction or transformation when the detected value is
    determined to be malicious by intel analysis
    """


class Settings(BaseModel):
    rules: Optional[list[Rule]] = None


class DetectorSetting(BaseModel):
    model_config = ConfigDict(extra="forbid")

    detector_name: str
    state: Literal["disabled", "enabled"]
    settings: Settings


class RedactConnectorSettings(BaseModel):
    fpe_tweak_vault_secret_id: Optional[str] = None


class ConnectorSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    redact: Optional[RedactConnectorSettings] = None


class AccessRuleSettings(APIResponseModel):
    """
    Configuration for an individual access rule used in an AI Guard recipe. Each
    rule defines its matching logic and the action to apply when the logic
    evaluates to true.
    """

    rule_key: Annotated[str, Field(pattern="^([a-zA-Z0-9_][a-zA-Z0-9/|_]*)$")]
    """
    Unique identifier for this rule. Should be user-readable and consistent
    across recipe updates.
    """
    name: str
    """Display label for the rule shown in user interfaces."""
    state: Literal["block", "report"]
    """
    Action to apply if the rule matches. Use 'block' to stop further processing
    or 'report' to simply log the match.
    """


class RecipeConfig(APIResponseModel):
    name: str
    """Human-readable name of the recipe"""
    description: str
    """Detailed description of the recipe's purpose or use case"""
    version: Optional[str] = "v1"
    """Optional version identifier for the recipe. Can be used to track changes."""
    detectors: Optional[list[DetectorSetting]] = None
    """Setting for Detectors"""
    access_rules: Optional[list[AccessRuleSettings]] = None
    """Configuration for access rules used in an AI Guard recipe."""
    connector_settings: Optional[ConnectorSettings] = None


class ServiceConfig(PangeaResponseResult):
    id: Optional[str] = None
    """ID of an AI Guard service configuration"""
    name: Optional[str] = None
    """Human-readable name of the AI Guard service configuration"""
    audit_data_activity: Optional[AuditDataActivityConfig] = None
    connections: Optional[ConnectionsConfig] = None
    recipes: Optional[dict[str, RecipeConfig]] = None


class ServiceConfigFilter(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: Optional[str] = None
    """
    Only records where id equals this value.
    """
    id__contains: Optional[list[str]] = None
    """
    Only records where id includes each substring.
    """
    id__in: Optional[list[str]] = None
    """
    Only records where id equals one of the provided substrings.
    """
    created_at: Optional[PangeaDateTime] = None
    """
    Only records where created_at equals this value.
    """
    created_at__gt: Optional[PangeaDateTime] = None
    """
    Only records where created_at is greater than this value.
    """
    created_at__gte: Optional[PangeaDateTime] = None
    """
    Only records where created_at is greater than or equal to this value.
    """
    created_at__lt: Optional[PangeaDateTime] = None
    """
    Only records where created_at is less than this value.
    """
    created_at__lte: Optional[PangeaDateTime] = None
    """
    Only records where created_at is less than or equal to this value.
    """
    updated_at: Optional[PangeaDateTime] = None
    """
    Only records where updated_at equals this value.
    """
    updated_at__gt: Optional[PangeaDateTime] = None
    """
    Only records where updated_at is greater than this value.
    """
    updated_at__gte: Optional[PangeaDateTime] = None
    """
    Only records where updated_at is greater than or equal to this value.
    """
    updated_at__lt: Optional[PangeaDateTime] = None
    """
    Only records where updated_at is less than this value.
    """
    updated_at__lte: Optional[PangeaDateTime] = None
    """
    Only records where updated_at is less than or equal to this value.
    """


class ServiceConfigsPage(PangeaResponseResult):
    count: Optional[int] = None
    """The total number of service configs matched by the list request."""
    last: Optional[str] = None
    """
    Used to fetch the next page of the current listing when provided in a
    repeated request's last parameter.
    """
    items: Optional[list[ServiceConfig]] = None


class ExtraInfoTyped(TypedDict, total=False):
    """(AIDR) Logging schema."""

    app_name: str
    """Name of source application."""

    app_group: str
    """The group of source application."""

    app_version: str
    """Version of the source application."""

    actor_name: str
    """Name of subject actor."""

    actor_group: str
    """The group of subject actor."""

    source_region: str
    """Geographic region or data center."""

    data_sensitivity: str
    """Sensitivity level of data involved"""

    customer_tier: str
    """Tier of the user or organization"""

    use_case: str
    """Business-specific use case"""


ExtraInfo: TypeAlias = Union[ExtraInfoTyped, dict[str, object]]


class AIGuard(ServiceBase):
    """AI Guard service client.

    Provides methods to interact with Pangea's AI Guard service.

    Examples:
        from pangea.services import AIGuard

        ai_guard = AIGuard(token="pangea_token")
    """

    service_name = "ai-guard"

    def __init__(
        self, token: str, config: PangeaConfig | None = None, logger_name: str = "pangea", config_id: str | None = None
    ) -> None:
        """
        AI Guard service client.

        Initializes a new AI Guard client.

        Args:
            token: Pangea API token.
            config: Pangea service configuration.
            logger_name: Logger name.
            config_id: Configuration ID.

        Examples:
            from pangea.services import AIGuard

            ai_guard = AIGuard(token="pangea_token")
        """

        super().__init__(token, config, logger_name, config_id)

    @overload
    def guard_text(
        self,
        text: str,
        *,
        debug: bool | None = None,
        log_fields: LogFields | None = None,
        overrides: Overrides | None = None,
        recipe: str | None = None,
    ) -> PangeaResponse[TextGuardResult]:
        """
        Guard LLM input and output text

        Detect, remove, or block malicious content and intent in LLM inputs and
        outputs to prevent model manipulation and data leakage.

        OperationId: ai_guard_post_v1_text_guard

        Args:
            text: Text to be scanned by AI Guard for PII, sensitive data,
                malicious content, and other data types defined by the
                configuration. Supports processing up to 20 KiB of text.
            debug: Setting this value to true will provide a detailed analysis
                of the text data
            log_field: Additional fields to include in activity log
            overrides: Overrides flags. Note: This parameter has no effect when
                the request is made by AIDR
            recipe: Recipe key of a configuration of data types and settings
                defined in the Pangea User Console. It specifies the rules that
                are to be applied to the text, such as defang malicious URLs.

        Examples:
            response = ai_guard.guard_text("text")
        """

    @overload
    def guard_text(
        self,
        *,
        messages: Sequence[Message],
        recipe: str | None = None,
        debug: bool | None = None,
        overrides: Overrides | None = None,
        log_fields: LogFields | None = None,
    ) -> PangeaResponse[TextGuardResult]:
        """
        Guard LLM input and output text

        Detect, remove, or block malicious content and intent in LLM inputs and
        outputs to prevent model manipulation and data leakage.

        OperationId: ai_guard_post_v1_text_guard

        Args:
            messages: Structured messages data to be scanned by AI Guard for
                PII, sensitive data, malicious content, and other data types
                defined by the configuration. Supports processing up to 20 KiB
                of JSON text using Pangea message format.
            debug: Setting this value to true will provide a detailed analysis
                of the text data
            log_field: Additional fields to include in activity log
            overrides: Overrides flags. Note: This parameter has no effect when
                the request is made by AIDR
            recipe: Recipe key of a configuration of data types and settings
                defined in the Pangea User Console. It specifies the rules that
                are to be applied to the text, such as defang malicious URLs.

        Examples:
            response = ai_guard.guard_text(messages=[Message(role="user", content="hello world")])
        """

    def guard_text(
        self,
        text: str | None = None,
        *,
        messages: Sequence[Message] | None = None,
        debug: bool | None = None,
        log_fields: LogFields | None = None,
        overrides: Overrides | None = None,
        recipe: str | None = None,
    ) -> PangeaResponse[TextGuardResult]:
        """
        Guard LLM input and output text

        Detect, remove, or block malicious content and intent in LLM inputs and
        outputs to prevent model manipulation and data leakage.

        OperationId: ai_guard_post_v1_text_guard

        Args:
            text: Text to be scanned by AI Guard for PII, sensitive data,
                malicious content, and other data types defined by the
                configuration. Supports processing up to 10KB of text.
            messages: Structured messages data to be scanned by AI Guard for
                PII, sensitive data, malicious content, and other data types
                defined by the configuration. Supports processing up to 10KB of
                JSON text
            debug: Setting this value to true will provide a detailed analysis
                of the text data
            log_field: Additional fields to include in activity log
            overrides: Overrides flags. Note: This parameter has no effect when
                the request is made by AIDR
            recipe: Recipe key of a configuration of data types and settings
                defined in the Pangea User Console. It specifies the rules that
                are to be applied to the text, such as defang malicious URLs.

        Examples:
            response = ai_guard.guard_text("text")
        """

        if text is not None and messages is not None:
            raise ValueError("Exactly one of `text` or `messages` must be given")

        return self.request.post(
            "v1/text/guard",
            TextGuardResult,
            data={
                "text": text,
                "messages": messages,
                "recipe": recipe,
                "debug": debug,
                "overrides": overrides,
                "log_fields": log_fields,
            },
        )

    def guard(
        self,
        input: Mapping[str, Any],
        *,
        recipe: str | None = None,
        debug: bool | None = None,
        overrides: Overrides | None = None,
        app_id: str | None = None,
        actor_id: str | None = None,
        llm_provider: str | None = None,
        model: str | None = None,
        model_version: str | None = None,
        request_token_count: int | None = None,
        response_token_count: int | None = None,
        source_ip: str | None = None,
        source_location: str | None = None,
        tenant_id: str | None = None,
        event_type: Literal["input", "output"] | None = None,
        sensor_instance_id: str | None = None,
        extra_info: ExtraInfo | None = None,
        count_tokens: bool | None = None,
    ) -> PangeaResponse[GuardResult]:
        """
        Guard LLM input and output

        Analyze and redact content to avoid manipulation of the model, addition
        of malicious content, and other undesirable data transfers.

        OperationId: ai_guard_post_v1beta_guard

        Args:
            input: 'messages' (required) contains Prompt content and role array
                in JSON format. The `content` is the multimodal text or image
                input that will be analyzed. Additional properties such as
                'tools' may be provided for analysis.
            recipe: Recipe key of a configuration of data types and settings defined in the Pangea User Console. It specifies the rules that are to be applied to the text, such as defang malicious URLs.
            debug: Setting this value to true will provide a detailed analysis of the text data
            app_name: Name of source application.
            llm_provider: Underlying LLM.  Example: 'OpenAI'.
            model: Model used to perform the event. Example: 'gpt'.
            model_version: Model version used to perform the event. Example: '3.5'.
            request_token_count: Number of tokens in the request.
            response_token_count: Number of tokens in the response.
            source_ip: IP address of user or app or agent.
            source_location: Location of user or app or agent.
            tenant_id: For gateway-like integrations with multi-tenant support.
            event_type: (AIDR) Event Type.
            sensor_instance_id: (AIDR) sensor instance id.
            extra_info: (AIDR) Logging schema.
            count_tokens: Provide input and output token count.
        """
        return self.request.post(
            "v1beta/guard",
            GuardResult,
            data={
                "input": input,
                "recipe": recipe,
                "debug": debug,
                "overrides": overrides,
                "app_id": app_id,
                "actor_id": actor_id,
                "llm_provider": llm_provider,
                "model": model,
                "model_version": model_version,
                "request_token_count": request_token_count,
                "response_token_count": response_token_count,
                "source_ip": source_ip,
                "source_location": source_location,
                "tenant_id": tenant_id,
                "event_type": event_type,
                "sensor_instance_id": sensor_instance_id,
                "extra_info": extra_info,
                "count_tokens": count_tokens,
            },
        )

    def get_service_config(self, id: str) -> PangeaResponse[ServiceConfig]:
        """
        OperationId: ai_guard_post_v1beta_config
        """
        return self.request.post("v1beta/config", data={"id": id}, result_class=ServiceConfig)

    def create_service_config(
        self,
        name: str,
        *,
        id: str | None = None,
        audit_data_activity: AuditDataActivityConfig | None = None,
        connections: ConnectionsConfig | None = None,
        recipes: Mapping[str, RecipeConfig] | None = None,
    ) -> PangeaResponse[ServiceConfig]:
        """
        OperationId: ai_guard_post_v1beta_config_create
        """
        return self.request.post(
            "v1beta/config/create",
            data={
                "name": name,
                "id": id,
                "audit_data_activity": audit_data_activity,
                "connections": connections,
                "recipes": recipes,
            },
            result_class=ServiceConfig,
        )

    def update_service_config(
        self,
        id: str,
        name: str,
        *,
        audit_data_activity: AuditDataActivityConfig | None = None,
        connections: ConnectionsConfig | None = None,
        recipes: Mapping[str, RecipeConfig] | None = None,
    ) -> PangeaResponse[ServiceConfig]:
        """
        OperationId: ai_guard_post_v1beta_config_update
        """
        return self.request.post(
            "v1beta/config/update",
            data={
                "id": id,
                "name": name,
                "audit_data_activity": audit_data_activity,
                "connections": connections,
                "recipes": recipes,
            },
            result_class=ServiceConfig,
        )

    def delete_service_config(self, id: str) -> PangeaResponse[ServiceConfig]:
        """
        OperationId: ai_guard_post_v1beta_config_delete
        """
        return self.request.post("v1beta/config/delete", data={"id": id}, result_class=ServiceConfig)

    def list_service_configs(
        self,
        *,
        filter: ServiceConfigFilter | None = None,
        last: str | None = None,
        order: Literal["asc", "desc"] | None = None,
        order_by: Literal["id", "created_at", "updated_at"] | None = None,
        size: int | None = None,
    ) -> PangeaResponse[ServiceConfigsPage]:
        """
        OperationId: ai_guard_post_v1beta_config_list
        """
        return self.request.post(
            "v1beta/config/list",
            data={"filter": filter, "last": last, "order": order, "order_by": order_by, "size": size},
            result_class=ServiceConfigsPage,
        )
