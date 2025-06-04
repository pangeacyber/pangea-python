from __future__ import annotations

from collections.abc import Sequence
from typing import Generic, Literal, Optional, overload

from pydantic import BaseModel, ConfigDict
from typing_extensions import TypeVar

from pangea.config import PangeaConfig
from pangea.response import APIRequestModel, APIResponseModel, PangeaResponse, PangeaResponseResult
from pangea.services.base import ServiceBase

# This is named "prompt injection" in the API spec even though it is also used
# for many other detectors.
PromptInjectionAction = Literal["report", "block"]

MaliciousEntityAction = Literal["report", "defang", "disabled", "block"]

# This is named "PII entity" in the API spec even though it is also used for the
# secrets detector.
PiiEntityAction = Literal["disabled", "report", "block", "mask", "partial_masking", "replacement", "hash", "fpe"]


class Message(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: str
    content: str


class CodeDetectionOverride(APIRequestModel):
    disabled: Optional[bool] = None
    action: Optional[Literal["report", "block"]] = None


class LanguageDetectionOverride(APIRequestModel):
    disabled: Optional[bool] = None
    allow: Optional[list[str]] = None
    block: Optional[list[str]] = None
    report: Optional[list[str]] = None


class TopicDetectionOverride(APIRequestModel):
    disabled: Optional[bool] = None
    block: Optional[list[str]] = None


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
    topic_detection: Optional[TopicDetectionOverride] = None


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
    language: str
    action: str
    """The action taken by this Detector"""


class TopicDetectionResult(APIResponseModel):
    action: str
    """The action taken by this Detector"""


class CodeDetectionResult(APIResponseModel):
    language: str
    action: str
    """The action taken by this Detector"""


_T = TypeVar("_T")


class TextGuardDetector(APIResponseModel, Generic[_T]):
    detected: Optional[bool] = None
    data: Optional[_T] = None


class TextGuardDetectors(APIResponseModel):
    prompt_injection: Optional[TextGuardDetector[PromptInjectionResult]] = None
    pii_entity: Optional[TextGuardDetector[PiiEntityResult]] = None
    malicious_entity: Optional[TextGuardDetector[MaliciousEntityResult]] = None
    custom_entity: Optional[TextGuardDetector[object]] = None
    secrets_detection: Optional[TextGuardDetector[SecretsEntityResult]] = None
    profanity_and_toxicity: Optional[TextGuardDetector[object]] = None
    language_detection: Optional[TextGuardDetector[LanguageDetectionResult]] = None
    topic_detection: Optional[TextGuardDetector[TopicDetectionResult]] = None
    code_detection: Optional[TextGuardDetector[CodeDetectionResult]] = None


class TextGuardResult(PangeaResponseResult):
    detectors: TextGuardDetectors
    """Result of the recipe analyzing and input prompt."""

    prompt_text: Optional[str] = None
    """Updated prompt text, if applicable."""

    prompt_messages: Optional[object] = None
    """Updated structured prompt, if applicable."""

    blocked: bool
    """Whether or not the prompt triggered a block detection."""

    recipe: str
    """The Recipe that was used."""

    fpe_context: Optional[str] = None
    """
    If an FPE redaction method returned results, this will be the context passed
    to unredact.
    """


class AIGuard(ServiceBase):
    """AI Guard service client.

    Provides methods to interact with Pangea's AI Guard service.

    Examples:
        from pangea import PangeaConfig
        from pangea.services import AIGuard

        config = PangeaConfig(domain="aws.us.pangea.cloud")
        ai_guard = AIGuard(token="pangea_token", config=config)
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
            from pangea import PangeaConfig
            from pangea.services import AIGuard

            config = PangeaConfig(domain="aws.us.pangea.cloud")
            ai_guard = AIGuard(token="pangea_token", config=config)
        """

        super().__init__(token, config, logger_name, config_id)

    @overload
    def guard_text(
        self,
        text: str,
        *,
        recipe: str | None = None,
        debug: bool | None = None,
        overrides: Overrides | None = None,
        log_fields: LogFields | None = None,
    ) -> PangeaResponse[TextGuardResult]:
        """
        Text Guard for scanning LLM inputs and outputs

        Analyze and redact text to avoid manipulation of the model, addition of
        malicious content, and other undesirable data transfers.

        OperationId: ai_guard_post_v1_text_guard

        Args:
            text: Text to be scanned by AI Guard for PII, sensitive data,
                malicious content, and other data types defined by the
                configuration. Supports processing up to 10KB of text.
            recipe: Recipe key of a configuration of data types and settings
                defined in the Pangea User Console. It specifies the rules that
                are to be applied to the text, such as defang malicious URLs.
            debug: Setting this value to true will provide a detailed analysis
                of the text data
            log_field: Additional fields to include in activity log

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
        Text Guard for scanning LLM inputs and outputs

        Analyze and redact text to avoid manipulation of the model, addition of
        malicious content, and other undesirable data transfers.

        OperationId: ai_guard_post_v1_text_guard

        Args:
            messages: Structured messages data to be scanned by AI Guard for
                PII, sensitive data, malicious content, and other data types
                defined by the configuration. Supports processing up to 10KB of
                JSON text
            recipe: Recipe key of a configuration of data types and settings
                defined in the Pangea User Console. It specifies the rules that
                are to be applied to the text, such as defang malicious URLs.
            debug: Setting this value to true will provide a detailed analysis
                of the text data
            log_field: Additional fields to include in activity log

        Examples:
            response = ai_guard.guard_text(messages=[Message(role="user", content="hello world")])
        """

    def guard_text(
        self,
        text: str | None = None,
        *,
        messages: Sequence[Message] | None = None,
        recipe: str | None = None,
        debug: bool | None = None,
        overrides: Overrides | None = None,
        log_fields: LogFields | None = None,
    ) -> PangeaResponse[TextGuardResult]:
        """
        Text Guard for scanning LLM inputs and outputs

        Analyze and redact text to avoid manipulation of the model, addition of
        malicious content, and other undesirable data transfers.

        OperationId: ai_guard_post_v1_text_guard

        Args:
            text: Text to be scanned by AI Guard for PII, sensitive data,
                malicious content, and other data types defined by the
                configuration. Supports processing up to 10KB of text.
            messages: Structured messages data to be scanned by AI Guard for
                PII, sensitive data, malicious content, and other data types
                defined by the configuration. Supports processing up to 10KB of
                JSON text
            recipe: Recipe key of a configuration of data types and settings
                defined in the Pangea User Console. It specifies the rules that
                are to be applied to the text, such as defang malicious URLs.
            debug: Setting this value to true will provide a detailed analysis
                of the text data
            log_field: Additional fields to include in activity log

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
