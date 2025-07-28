from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, overload

from typing_extensions import Literal, TypeVar

from pangea.asyncio.services.base import ServiceBaseAsync
from pangea.config import PangeaConfig
from pangea.response import PangeaResponse
from pangea.services.ai_guard import (
    AuditDataActivityConfig,
    ConnectionsConfig,
    ExtraInfo,
    GuardResult,
    LogFields,
    Message,
    Overrides,
    RecipeConfig,
    ServiceConfig,
    ServiceConfigFilter,
    ServiceConfigsPage,
    TextGuardResult,
)

_T = TypeVar("_T")


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
        messages: Sequence[Message],
        recipe: str | None = None,
        debug: bool | None = None,
        overrides: Overrides | None = None,
        log_fields: LogFields | None = None,
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

    async def guard(
        self,
        input: Mapping[str, Any],
        *,
        recipe: str | None = None,
        debug: bool | None = None,
        overrides: Overrides | None = None,
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
        event_type: Literal["input", "output"] | None = None,
        sensor_instance_id: str | None = None,
        extra_info: ExtraInfo | None = None,
        count_tokens: bool | None = None,
    ) -> PangeaResponse[GuardResult]:
        """
        Guard LLM input and output

        Analyze and redact content to avoid manipulation of the model, addition
        of malicious content, and other undesirable data transfers.

        OperationId: ai_guard_post_v1beta_guard

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
            sensor_instance_id: (AIDR) sensor instance id.
            extra_info: (AIDR) Logging schema.
            count_tokens: Provide input and output token count.
        """
        return await self.request.post(
            "v1beta/guard",
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
                "sensor_instance_id": sensor_instance_id,
                "extra_info": extra_info,
                "count_tokens": count_tokens,
            },
        )

    async def get_service_config(self, id: str) -> PangeaResponse[ServiceConfig]:
        """
        OperationId: ai_guard_post_v1beta_config
        """
        return await self.request.post("v1beta/config", data={"id": id}, result_class=ServiceConfig)

    async def create_service_config(
        self,
        name: str,
        *,
        id: str | None = None,
        audit_data_activity: AuditDataActivityConfig | None = None,
        connections: ConnectionsConfig | None = None,
        recipes: Mapping[str, RecipeConfig] | None = None,
    ) -> PangeaResponse[ServiceConfig]:
        """
        OperationId: ai_guard_post_v1beta_config_create
        """
        return await self.request.post(
            "v1beta/config/create",
            data={
                "name": name,
                "id": id,
                "audit_data_activity": audit_data_activity,
                "connections": connections,
                "recipes": recipes,
            },
            result_class=ServiceConfig,
        )

    async def update_service_config(
        self,
        id: str,
        name: str,
        *,
        audit_data_activity: AuditDataActivityConfig | None = None,
        connections: ConnectionsConfig | None = None,
        recipes: Mapping[str, RecipeConfig] | None = None,
    ) -> PangeaResponse[ServiceConfig]:
        """
        OperationId: ai_guard_post_v1beta_config_update
        """
        return await self.request.post(
            "v1beta/config/update",
            data={
                "id": id,
                "name": name,
                "audit_data_activity": audit_data_activity,
                "connections": connections,
                "recipes": recipes,
            },
            result_class=ServiceConfig,
        )

    async def delete_service_config(self, id: str) -> PangeaResponse[ServiceConfig]:
        """
        OperationId: ai_guard_post_v1beta_config_delete
        """
        return await self.request.post("v1beta/config/delete", data={"id": id}, result_class=ServiceConfig)

    async def list_service_configs(
        self,
        *,
        filter: ServiceConfigFilter | None = None,
        last: str | None = None,
        order: Literal["asc", "desc"] | None = None,
        order_by: Literal["id", "created_at", "updated_at"] | None = None,
        size: int | None = None,
    ) -> PangeaResponse[ServiceConfigsPage]:
        """
        OperationId: ai_guard_post_v1beta_config_list
        """
        return await self.request.post(
            "v1beta/config/list",
            data={"filter": filter, "last": last, "order": order, "order_by": order_by, "size": size},
            result_class=ServiceConfigsPage,
        )
