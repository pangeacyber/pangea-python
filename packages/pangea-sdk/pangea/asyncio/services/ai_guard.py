from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import overload

from typing_extensions import Any, Literal

from pangea.asyncio.services.base import ServiceBaseAsync
from pangea.config import PangeaConfig
from pangea.response import PangeaResponse
from pangea.services.ai_guard import (
    ExtraInfo,
    GuardResult,
    LogFields,
    McpToolsMessage,
    Message,
    Overrides,
    Overrides2,
    TextGuardResult,
    get_relevant_content,
    patch_messages,
)


class AIGuardAsync(ServiceBaseAsync):
    """AI Guard service client.

    Provides methods to interact with Pangea's AI Guard service.

    Examples:
        from pangea.asyncio.services import AIGuardAsync

        ai_guard = AIGuardAsync(token="pangea_token")
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
            from pangea.asyncio.services import AIGuardAsync

            ai_guard = AIGuardAsync(token="pangea_token")
        """

        super().__init__(token, config, logger_name, config_id)

    @overload
    async def guard_text(
        self,
        text: str,
        *,
        debug: bool | None = None,
        log_fields: LogFields | None = None,
        overrides: Overrides | None = None,
        recipe: str | None = None,
    ) -> PangeaResponse[TextGuardResult]:
        """
        Guard LLM input and output text

        Detect, remove, or block malicious content and intent in LLM inputs and
        outputs to prevent model manipulation and data leakage.

        OperationId: ai_guard_post_v1_text_guard

        Args:
            text: Text to be scanned by AI Guard for PII, sensitive data,
                malicious content, and other data types defined by the
                configuration. Supports processing up to 20 KiB of text.
            debug: Setting this value to true will provide a detailed analysis
                of the text data
            log_field: Additional fields to include in activity log
            overrides: Overrides flags. Note: This parameter has no effect when
                the request is made by AIDR
            recipe: Recipe key of a configuration of data types and settings
                defined in the Pangea User Console. It specifies the rules that
                are to be applied to the text, such as defang malicious URLs.

        Examples:
            response = await ai_guard.guard_text("text")
        """

    @overload
    async def guard_text(
        self,
        *,
        messages: Sequence[Message | McpToolsMessage],
        recipe: str | None = None,
        debug: bool | None = None,
        overrides: Overrides | None = None,
        log_fields: LogFields | None = None,
        only_relevant_content: bool = False,
    ) -> PangeaResponse[TextGuardResult]:
        """
        Guard LLM input and output text

        Detect, remove, or block malicious content and intent in LLM inputs and
        outputs to prevent model manipulation and data leakage.

        OperationId: ai_guard_post_v1_text_guard

        Args:
            messages: Structured messages data to be scanned by AI Guard for
                PII, sensitive data, malicious content, and other data types
                defined by the configuration. Supports processing up to 20 KiB
                of JSON text using Pangea message format.
            debug: Setting this value to true will provide a detailed analysis
                of the text data
            log_field: Additional fields to include in activity log
            overrides: Overrides flags. Note: This parameter has no effect when
                the request is made by AIDR
            recipe: Recipe key of a configuration of data types and settings
                defined in the Pangea User Console. It specifies the rules that
                are to be applied to the text, such as defang malicious URLs.
            only_relevant_content: Whether or not to only send relevant content
                to AI Guard.

        Examples:
            response = await ai_guard.guard_text(messages=[Message(role="user", content="hello world")])
        """

    async def guard_text(
        self,
        text: str | None = None,
        *,
        messages: Sequence[Message | McpToolsMessage] | None = None,
        recipe: str | None = None,
        debug: bool | None = None,
        overrides: Overrides | None = None,
        log_fields: LogFields | None = None,
        only_relevant_content: bool = False,
    ) -> PangeaResponse[TextGuardResult]:
        """
        Guard LLM input and output text

        Detect, remove, or block malicious content and intent in LLM inputs and
        outputs to prevent model manipulation and data leakage.

        OperationId: ai_guard_post_v1_text_guard

        Args:
            text: Text to be scanned by AI Guard for PII, sensitive data,
                malicious content, and other data types defined by the
                configuration. Supports processing up to 10KB of text.
            messages: Structured messages data to be scanned by AI Guard for
                PII, sensitive data, malicious content, and other data types
                defined by the configuration. Supports processing up to 10KB of
                JSON text
            debug: Setting this value to true will provide a detailed analysis
                of the text data
            log_field: Additional fields to include in activity log
            overrides: Overrides flags. Note: This parameter has no effect when
                the request is made by AIDR
            recipe: Recipe key of a configuration of data types and settings
                defined in the Pangea User Console. It specifies the rules that
                are to be applied to the text, such as defang malicious URLs.
            only_relevant_content: Whether or not to only send relevant content
                to AI Guard.

        Examples:
            response = await ai_guard.guard_text("text")
        """

        if text is not None and messages is not None:
            raise ValueError("Exactly one of `text` or `messages` must be given")

        if only_relevant_content and messages is not None:
            original_messages = messages
            messages, original_indices = get_relevant_content(messages)

        response = await self.request.post(
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

        if only_relevant_content and response.result and response.result.prompt_messages:
            response.result.prompt_messages = patch_messages(
                original_messages, original_indices, response.result.prompt_messages
            )  # type: ignore[assignment]

        return response

    async def guard(
        self,
        input: Mapping[str, Any],
        *,
        recipe: str | None = None,
        debug: bool | None = None,
        overrides: Overrides2 | None = None,
        app_id: str | None = None,
        actor_id: str | None = None,
        llm_provider: str | None = None,
        model: str | None = None,
        model_version: str | None = None,
        request_token_count: int | None = None,
        response_token_count: int | None = None,
        source_ip: str | None = None,
        source_location: str | None = None,
        tenant_id: str | None = None,
        event_type: Literal["input", "output", "tool_input", "tool_output", "tool_listing"] | None = None,
        collector_instance_id: str | None = None,
        extra_info: ExtraInfo | None = None,
        count_tokens: bool | None = None,
    ) -> PangeaResponse[GuardResult]:
        """
        Guard LLM input and output

        Analyze and redact content to avoid manipulation of the model, addition
        of malicious content, and other undesirable data transfers.

        OperationId: ai_guard_post_v1_guard

        Args:
            input: 'messages' (required) contains Prompt content and role array
                in JSON format. The `content` is the multimodal text or image
                input that will be analyzed. Additional properties such as
                'tools' may be provided for analysis.
            recipe: Recipe key of a configuration of data types and settings defined in the Pangea User Console. It specifies the rules that are to be applied to the text, such as defang malicious URLs.
            debug: Setting this value to true will provide a detailed analysis of the text data
            app_name: Name of source application.
            llm_provider: Underlying LLM.  Example: 'OpenAI'.
            model: Model used to perform the event. Example: 'gpt'.
            model_version: Model version used to perform the event. Example: '3.5'.
            request_token_count: Number of tokens in the request.
            response_token_count: Number of tokens in the response.
            source_ip: IP address of user or app or agent.
            source_location: Location of user or app or agent.
            tenant_id: For gateway-like integrations with multi-tenant support.
            event_type: (AIDR) Event Type.
            collector_instance_id: (AIDR) collector instance id.
            extra_info: (AIDR) Logging schema.
            count_tokens: Provide input and output token count.
        """
        return await self.request.post(
            "v1/guard",
            GuardResult,
            data={
                "input": input,
                "recipe": recipe,
                "debug": debug,
                "overrides": overrides,
                "app_id": app_id,
                "actor_id": actor_id,
                "llm_provider": llm_provider,
                "model": model,
                "model_version": model_version,
                "request_token_count": request_token_count,
                "response_token_count": response_token_count,
                "source_ip": source_ip,
                "source_location": source_location,
                "tenant_id": tenant_id,
                "event_type": event_type,
                "collector_instance_id": collector_instance_id,
                "extra_info": extra_info,
                "count_tokens": count_tokens,
            },
        )
