from __future__ import annotations

from typing import TYPE_CHECKING, Literal, Optional

from pangea.config import PangeaConfig
from pangea.response import APIRequestModel, APIResponseModel, PangeaResponse, PangeaResponseResult
from pangea.services.base import ServiceBase

if TYPE_CHECKING:
    from collections.abc import Iterable


class Message(APIRequestModel):
    role: str
    content: str


class Classification(APIResponseModel):
    category: str
    """Classification category"""

    label: str
    """Classification label"""

    confidence: float
    """Confidence score for the classification"""


class GuardResult(PangeaResponseResult):
    detected: bool
    """Boolean response for if the prompt was considered malicious or not"""

    type: Optional[Literal["direct", "indirect"]] = None
    """Type of analysis, either direct or indirect"""

    analyzer: Optional[str] = None
    """Prompt Analyzers for identifying and rejecting properties of prompts"""

    confidence: int
    """Percent of confidence in the detection result, ranging from 0 to 100"""

    info: Optional[str] = None
    """Extra information about the detection result"""

    classifications: list[Classification]
    """List of classification results with labels and confidence scores"""


class PromptGuard(ServiceBase):
    """Prompt Guard service client.

    Provides methods to interact with Pangea's Prompt Guard service.

    Examples:
        from pangea import PangeaConfig
        from pangea.services import PromptGuard

        config = PangeaConfig(domain="aws.us.pangea.cloud")
        prompt_guard = PromptGuard(token="pangea_token", config=config)
    """

    service_name = "prompt-guard"

    def __init__(
        self, token: str, config: PangeaConfig | None = None, logger_name: str = "pangea", config_id: str | None = None
    ) -> None:
        """
        Prompt Guard service client.

        Initializes a new Prompt Guard client.

        Args:
            token: Pangea API token.
            config: Pangea service configuration.
            logger_name: Logger name.
            config_id: Configuration ID.

        Examples:
            from pangea import PangeaConfig
            from pangea.services import PromptGuard

            config = PangeaConfig(domain="aws.us.pangea.cloud")
            prompt_guard = PromptGuard(token="pangea_token", config=config)
        """

        super().__init__(token, config, logger_name, config_id)

    def guard(
        self, messages: Iterable[Message], *, analyzers: Iterable[str] | None = None
    ) -> PangeaResponse[GuardResult]:
        """
        Guard (Beta)

        Guard messages.

        How to install a [Beta release](https://pangea.cloud/docs/sdk/python/#beta-releases).

        OperationId: prompt_guard_post_v1beta_guard

        Args:
            messages: Prompt content and role array.
            analyzers: Specific analyzers to be used in the call.

        Examples:
            from pangea.services.prompt_guard import Message

            response = prompt_guard.guard([Message(role="user", content="hello world")])
        """

        return self.request.post("v1beta/guard", GuardResult, data={"messages": messages, "analyzers": analyzers})
