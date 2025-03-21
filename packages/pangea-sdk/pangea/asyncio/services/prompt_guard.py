from __future__ import annotations

from typing import TYPE_CHECKING

from pangea.asyncio.services.base import ServiceBaseAsync
from pangea.config import PangeaConfig
from pangea.services.prompt_guard import GuardResult, Message

if TYPE_CHECKING:
    from collections.abc import Iterable

    from pangea.response import PangeaResponse


class PromptGuardAsync(ServiceBaseAsync):
    """Prompt Guard service client.

    Provides methods to interact with Pangea's Prompt Guard service.

    Examples:
        from pangea import PangeaConfig
        from pangea.asyncio.services import PromptGuardAsync

        config = PangeaConfig(domain="aws.us.pangea.cloud")
        prompt_guard = PromptGuardAsync(token="pangea_token", config=config)
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
            from pangea.asyncio.services import PromptGuardAsync

            config = PangeaConfig(domain="aws.us.pangea.cloud")
            prompt_guard = PromptGuardAsync(token="pangea_token", config=config)
        """

        super().__init__(token, config, logger_name, config_id)

    async def guard(
        self,
        messages: Iterable[Message],
        *,
        analyzers: Iterable[str] | None = None,
        classify: bool | None = None,
    ) -> PangeaResponse[GuardResult]:
        """
        Guard

        Guard messages.

        OperationId: prompt_guard_post_v1_guard

        Args:
            messages: Prompt content and role array in JSON format. The
              `content` is the text that will be analyzed for redaction.
            analyzers: Specific analyzers to be used in the call
            classify: Boolean to enable classification of the content

        Examples:
            from pangea.asyncio.services.prompt_guard import Message

            response = await prompt_guard.guard([Message(role="user", content="hello world")])
        """

        return await self.request.post(
            "v1/guard",
            GuardResult,
            data={"messages": messages, "analyzers": analyzers, "classify": classify},
        )
