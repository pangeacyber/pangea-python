from __future__ import annotations

from collections.abc import Sequence
from typing import overload

from pangea.asyncio.services.base import ServiceBaseAsync
from pangea.config import PangeaConfig
from pangea.response import PangeaResponse
from pangea.services.ai_guard import LogFields, Message, Overrides, TextGuardResult


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
        text: str,
        *,
        recipe: str | None = None,
        debug: bool | None = None,
        overrides: Overrides | None = None,
        log_fields: LogFields | None = None,
    ) -> PangeaResponse[TextGuardResult]:
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
            response = await ai_guard.guard_text("text")
        """

    @overload
    async def guard_text(
        self,
        *,
        messages: Sequence[Message],
        recipe: str | None = None,
        debug: bool | None = None,
        overrides: Overrides | None = None,
        log_fields: LogFields | None = None,
    ) -> PangeaResponse[TextGuardResult]:
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
            response = await ai_guard.guard_text(messages=[Message(role="user", content="hello world")])
        """

    async def guard_text(
        self,
        text: str | None = None,
        *,
        messages: Sequence[Message] | None = None,
        recipe: str | None = None,
        debug: bool | None = None,
        overrides: Overrides | None = None,
        log_fields: LogFields | None = None,
    ) -> PangeaResponse[TextGuardResult]:
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
            response = await ai_guard.guard_text("text")
        """

        if text is not None and messages is not None:
            raise ValueError("Exactly one of `text` or `messages` must be given")

        return await self.request.post(
            "v1/text/guard",
            TextGuardResult,
            data={
                "text": text,
                "messages": messages,
                "recipe": recipe,
                "debug": debug,
                "overrides": overrides,
                "log_fields": log_fields,
            },
        )
