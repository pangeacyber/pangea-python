from __future__ import annotations

from typing import TYPE_CHECKING

from pangea.asyncio.services.base import ServiceBaseAsync
from pangea.services.prompt_guard import GuardResult, Message

if TYPE_CHECKING:
    from collections.abc import Iterable

    from pangea.response import PangeaResponse


class PromptGuard(ServiceBaseAsync):
    """Prompt Guard service client.

    Provides methods to interact with Pangea's Prompt Guard service.
    """

    service_name = "prompt-guard"

    async def guard(self, messages: Iterable[Message]) -> PangeaResponse[GuardResult]:
        """
        Guard (Beta)

        Guard messages.

        How to install a [Beta release](https://pangea.cloud/docs/sdk/python/#beta-releases).

        OperationId: prompt_guard_post_v1beta_guard

        Args:
            messages: Messages..

        Examples:
            response = await prompt_guard.guard([Message(role="user", content="hello world")])
        """

        return await self.request.post("v1beta/guard", GuardResult, data={"messages": messages})
