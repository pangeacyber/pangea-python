from __future__ import annotations

from typing import overload

from typing_extensions import TypeVar

from pangea.asyncio.services.base import ServiceBaseAsync
from pangea.config import PangeaConfig
from pangea.response import PangeaResponse
from pangea.services.ai_guard import TextGuardResult

_T = TypeVar("_T")


class AIGuardAsync(ServiceBaseAsync):
    """AI Guard service client.

    Provides methods to interact with Pangea's AI Guard service.

    Examples:
        from pangea import PangeaConfig
        from pangea.asyncio.services import AIGuardAsync

        config = PangeaConfig(domain="aws.us.pangea.cloud")
        ai_guard = AIGuardAsync(token="pangea_token", config=config)
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
            from pangea.asyncio.services import AIGuardAsync

            config = PangeaConfig(domain="aws.us.pangea.cloud")
            ai_guard = AIGuardAsync(token="pangea_token", config=config)
        """

        super().__init__(token, config, logger_name, config_id)

    @overload
    async def guard_text(
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
            response = await ai_guard.guard_text("text")
        """

    @overload
    async def guard_text(
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
            response = await ai_guard.guard_text([
                {"role": "user", "content": "hello world"}
            ])
        """

    async def guard_text(
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

        return await self.request.post(
            "v1beta/text/guard",
            TextGuardResult,
            data={
                "text" if isinstance(text_or_messages, str) else "messages": text_or_messages,
                "recipe": recipe,
                "debug": debug,
            },
        )
