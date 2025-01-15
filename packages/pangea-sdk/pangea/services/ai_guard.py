from __future__ import annotations

from typing import Any, Dict, Generic, List, Optional, TypeVar

from pangea.config import PangeaConfig
from pangea.response import APIResponseModel, PangeaResponse, PangeaResponseResult
from pangea.services.base import ServiceBase


class AnalyzerResponse(APIResponseModel):
    analyzer: str
    confidence: float


class PromptInjectionResult(APIResponseModel):
    analyzer_responses: List[AnalyzerResponse]
    """Triggered prompt injection analyzers."""


class PiiEntity(APIResponseModel):
    type: str
    value: str
    redacted: bool
    start_pos: Optional[int] = None


class PiiEntityResult(APIResponseModel):
    entities: List[PiiEntity]


class MaliciousEntity(APIResponseModel):
    type: str
    value: str
    redacted: Optional[bool] = None
    start_pos: Optional[int] = None
    raw: Optional[Dict[str, Any]] = None


class MaliciousEntityResult(APIResponseModel):
    entities: List[MaliciousEntity]


T = TypeVar("T")


class TextGuardDetector(APIResponseModel, Generic[T]):
    detected: bool
    data: Optional[T] = None


class TextGuardDetectors(APIResponseModel):
    prompt_injection: Optional[TextGuardDetector[PromptInjectionResult]] = None
    pii_entity: Optional[TextGuardDetector[PiiEntityResult]] = None
    malicious_entity: Optional[TextGuardDetector[MaliciousEntityResult]] = None


class TextGuardResult(PangeaResponseResult):
    detectors: TextGuardDetectors
    prompt: str


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

    def guard_text(
        self,
        text: str,
        *,
        recipe: str = "pangea_prompt_guard",
        debug: bool = False,
    ) -> PangeaResponse[TextGuardResult]:
        """
        Text guard (Beta)

        Guard text.

        How to install a [Beta release](https://pangea.cloud/docs/sdk/python/#beta-releases).

        OperationId: ai_guard_post_v1beta_text_guard

        Args:
            text: Text.
            recipe: Recipe.
            debug: Debug.

        Examples:
            response = ai_guard.guard_text("text")
        """

        return self.request.post(
            "v1beta/text/guard", TextGuardResult, data={"text": text, "recipe": recipe, "debug": debug}
        )
