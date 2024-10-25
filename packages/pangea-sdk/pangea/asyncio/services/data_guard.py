from __future__ import annotations

from pangea.asyncio.services.base import ServiceBaseAsync
from pangea.response import PangeaResponse, PangeaResponseResult
from pangea.services.data_guard import TextGuardResult


class DataGuard(ServiceBaseAsync):
    """Data Guard service client.

    Provides methods to interact with Pangea's Data Guard service.
    """

    service_name = "data-guard"

    async def guard_text(
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

        OperationId: data_guard_post_v1beta_text_guard

        Args:
            text: Text.
            recipe: Recipe.
            debug: Debug.

        Examples:
            response = await data_guard.guard_text("text")
        """

        return await self.request.post(
            "v1beta/text/guard", TextGuardResult, data={"text": text, "recipe": recipe, "debug": debug}
        )
