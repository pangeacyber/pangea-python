from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from pangea.config import PangeaConfig
from pangea.response import APIRequestModel, PangeaResponse, PangeaResponseResult
from pangea.services.base import ServiceBase

if TYPE_CHECKING:
    from collections.abc import Iterable


class Message(APIRequestModel):
    role: str
    content: str


class GuardResult(PangeaResponseResult):
    detected: bool
    type: Optional[str] = None
    detector: Optional[str] = None
    confidence: int


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

    def guard(self, messages: Iterable[Message]) -> PangeaResponse[GuardResult]:
        """
        Guard (Beta)

        Guard messages.

        How to install a [Beta release](https://pangea.cloud/docs/sdk/python/#beta-releases).

        OperationId: prompt_guard_post_v1beta_guard

        Args:
            messages: Messages.

        Examples:
            from pangea.services.prompt_guard import Message

            response = prompt_guard.guard([Message(role="user", content="hello world")])
        """

        return self.request.post("v1beta/guard", GuardResult, data={"messages": messages})
