from __future__ import annotations

from pangea.asyncio.services.base import ServiceBaseAsync
from pangea.config import PangeaConfig
from pangea.response import PangeaResponse
from pangea.services.data_guard import TextGuardResult


class DataGuard(ServiceBaseAsync):
    """Data Guard service client.

    Provides methods to interact with Pangea's Data Guard service.

    Examples:
        from pangea import PangeaConfig
        from pangea.asyncio.services.data_guard import DataGuard

        config = PangeaConfig(domain="aws.us.pangea.cloud")
        data_guard = DataGuard(token="pangea_token", config=config)
    """

    service_name = "data-guard"

    def __init__(
        self, token: str, config: PangeaConfig | None = None, logger_name: str = "pangea", config_id: str | None = None
    ) -> None:
        """
        Data Guard service client.

        Initializes a new Data Guard client.

        Args:
            token: Pangea API token.
            config: Pangea service configuration.
            logger_name: Logger name.
            config_id: Configuration ID.

        Examples:
            from pangea import PangeaConfig
            from pangea.asyncio.services.data_guard import DataGuard

            config = PangeaConfig(domain="aws.us.pangea.cloud")
            data_guard = DataGuard(token="pangea_token", config=config)
        """

        super().__init__(token, config, logger_name, config_id)

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
