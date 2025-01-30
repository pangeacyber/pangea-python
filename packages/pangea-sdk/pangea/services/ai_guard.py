from __future__ import annotations

from typing import Any, Dict, Generic, List, Literal, Optional, TypeVar, overload

from pangea.config import PangeaConfig
from pangea.response import APIResponseModel, PangeaResponse, PangeaResponseResult
from pangea.services.base import ServiceBase

_DetectorAction = Literal["detected", "redacted", "defanged", "reported", "blocked"]


class AnalyzerResponse(APIResponseModel):
    analyzer: str
    confidence: float


class PromptInjectionResult(APIResponseModel):
    action: _DetectorAction
    analyzer_responses: List[AnalyzerResponse]
    """Triggered prompt injection analyzers."""


class PiiEntity(APIResponseModel):
    type: str
    value: str
    action: _DetectorAction
    start_pos: Optional[int] = None


class PiiEntityResult(APIResponseModel):
    entities: List[PiiEntity]


class MaliciousEntity(APIResponseModel):
    type: str
    value: str
    action: _DetectorAction
    start_pos: Optional[int] = None
    raw: Optional[Dict[str, Any]] = None


class MaliciousEntityResult(APIResponseModel):
    entities: List[MaliciousEntity]


class SecretsEntity(APIResponseModel):
    type: str
    value: str
    action: _DetectorAction
    start_pos: Optional[int] = None
    redacted_value: Optional[str] = None


class SecretsEntityResult(APIResponseModel):
    entities: List[SecretsEntity]


class LanguageDetectionResult(APIResponseModel):
    language: str
    action: _DetectorAction


class CodeDetectionResult(APIResponseModel):
    language: str
    action: _DetectorAction


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
        text_or_messages: str,
        *,
        recipe: str = "pangea_prompt_guard",
        debug: bool = False,
    ) -> PangeaResponse[TextGuardResult[None]]:
        """
        Text Guard for scanning LLM inputs and outputs (Beta)

        Analyze and redact text to avoid manipulation of the model, addition of
        malicious content, and other undesirable data transfers.

        How to install a [Beta release](https://pangea.cloud/docs/sdk/python/#beta-releases).

        OperationId: ai_guard_post_v1beta_text_guard

        Args:
            text: Text to be scanned by AI Guard for PII, sensitive data,
                malicious content, and other data types defined by the
                configuration. Supports processing up to 10KB of text.
            recipe: Recipe key of a configuration of data types and settings
                defined in the Pangea User Console. It specifies the rules that
                are to be applied to the text, such as defang malicious URLs.
            debug: Setting this value to true will provide a detailed analysis
                of the text data

        Examples:
            response = ai_guard.guard_text("text")
        """

    @overload
    def guard_text(
        self,
        text_or_messages: _T,
        *,
        recipe: str = "pangea_prompt_guard",
        debug: bool = False,
    ) -> PangeaResponse[TextGuardResult[_T]]:
        """
        Text Guard for scanning LLM inputs and outputs (Beta)

        Analyze and redact text to avoid manipulation of the model, addition of
        malicious content, and other undesirable data transfers.

        How to install a [Beta release](https://pangea.cloud/docs/sdk/python/#beta-releases).

        OperationId: ai_guard_post_v1beta_text_guard

        Args:
            text_or_messages: Structured data to be scanned by AI Guard for PII,
                sensitive data, malicious content, and other data types defined
                by the configuration. Supports processing up to 10KB of text.
            recipe: Recipe key of a configuration of data types and settings
                defined in the Pangea User Console. It specifies the rules that
                are to be applied to the text, such as defang malicious URLs.
            debug: Setting this value to true will provide a detailed analysis
                of the text data

        Examples:
            response = ai_guard.guard_text([
                {"role": "user", "content": "hello world"}
            ])
        """

    def guard_text(
        self,
        text_or_messages: str | _T,
        *,
        recipe: str = "pangea_prompt_guard",
        debug: bool = False,
    ) -> PangeaResponse[TextGuardResult[_T]]:
        """
        Text Guard for scanning LLM inputs and outputs (Beta)

        Analyze and redact text to avoid manipulation of the model, addition of
        malicious content, and other undesirable data transfers.

        How to install a [Beta release](https://pangea.cloud/docs/sdk/python/#beta-releases).

        OperationId: ai_guard_post_v1beta_text_guard

        Args:
            text_or_messages: Text or structured data to be scanned by AI Guard
                for PII, sensitive data, malicious content, and other data types
                defined by the configuration. Supports processing up to 10KB of text.
            recipe: Recipe key of a configuration of data types and settings
                defined in the Pangea User Console. It specifies the rules that
                are to be applied to the text, such as defang malicious URLs.
            debug: Setting this value to true will provide a detailed analysis
                of the text data
        """

        return self.request.post(
            "v1beta/text/guard",
            TextGuardResult,
            data={
                "text" if isinstance(text_or_messages, str) else "messages": text_or_messages,
                "recipe": recipe,
                "debug": debug,
            },
        )
