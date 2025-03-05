from __future__ import annotations

from typing import Any, Dict, Generic, List, Optional, TypeVar, overload

from pangea.config import PangeaConfig
from pangea.response import APIRequestModel, APIResponseModel, PangeaResponse, PangeaResponseResult
from pangea.services.base import ServiceBase


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
    analyzer_responses: List[AnalyzerResponse]
    """Triggered prompt injection analyzers."""


class PiiEntity(APIResponseModel):
    type: str
    value: str
    action: str
    start_pos: Optional[int] = None


class PiiEntityResult(APIResponseModel):
    entities: List[PiiEntity]


class MaliciousEntity(APIResponseModel):
    type: str
    value: str
    action: str
    start_pos: Optional[int] = None
    raw: Optional[Dict[str, Any]] = None


class MaliciousEntityResult(APIResponseModel):
    entities: List[MaliciousEntity]


class SecretsEntity(APIResponseModel):
    type: str
    value: str
    action: str
    start_pos: Optional[int] = None
    redacted_value: Optional[str] = None


class SecretsEntityResult(APIResponseModel):
    entities: List[SecretsEntity]


class LanguageDetectionResult(APIResponseModel):
    language: str
    action: str


class CodeDetectionResult(APIResponseModel):
    language: str
    action: str


_T = TypeVar("_T")


class TextGuardDetector(APIResponseModel, Generic[_T]):
    detected: bool
    data: Optional[_T] = None


class TextGuardDetectors(APIResponseModel):
    prompt_injection: Optional[TextGuardDetector[PromptInjectionResult]] = None
    pii_entity: Optional[TextGuardDetector[PiiEntityResult]] = None
    malicious_entity: Optional[TextGuardDetector[MaliciousEntityResult]] = None
    secrets_detection: Optional[TextGuardDetector[SecretsEntityResult]] = None
    profanity_and_toxicity: Optional[TextGuardDetector[Any]] = None
    custom_entity: Optional[TextGuardDetector[Any]] = None
    language_detection: Optional[TextGuardDetector[LanguageDetectionResult]] = None
    code_detection: Optional[TextGuardDetector[CodeDetectionResult]] = None


class TextGuardResult(PangeaResponseResult, Generic[_T]):
    detectors: TextGuardDetectors
    """Result of the recipe analyzing and input prompt."""

    prompt_text: Optional[str] = None
    """Updated prompt text, if applicable."""

    prompt_messages: Optional[_T] = None
    """Updated structured prompt, if applicable."""

    blocked: bool


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
        log_fields: LogFields | None = None,
    ) -> PangeaResponse[TextGuardResult[None]]:
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
        messages: _T,
        recipe: str | None = None,
        debug: bool | None = None,
        log_fields: LogFields | None = None,
    ) -> PangeaResponse[TextGuardResult[_T]]:
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
            response = ai_guard.guard_text(messages=[{"role": "user", "content": "hello world"}])
        """

    def guard_text(  # type: ignore[misc]
        self,
        text: str | None = None,
        *,
        messages: _T | None = None,
        recipe: str | None = None,
        debug: bool | None = None,
        log_fields: LogFields | None = None,
    ) -> PangeaResponse[TextGuardResult[None]]:
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
                "log_fields": log_fields,
            },
        )
