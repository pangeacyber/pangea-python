from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Literal

from pangea.asyncio.services.base import ServiceBaseAsync
from pangea.config import PangeaConfig
from pangea.response import PangeaResponseResult
from pangea.services.prompt_guard import (
    AuditDataActivityConfig,
    GuardResult,
    Message,
    ServiceConfigFilter,
    ServiceConfigsPage,
)

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

    async def get_service_config(
        self,
        *,
        id: str | None = None,
        version: str | None = None,
        analyzers: Mapping[str, bool] | None = None,
        malicious_detection_threshold: float | None = None,
        benign_detection_threshold: float | None = None,
        audit_data_activity: AuditDataActivityConfig | None = None,
    ) -> PangeaResponse[PangeaResponseResult]:
        """
        OperationId: prompt_guard_post_v1beta_config
        """
        return await self.request.post(
            "v1beta/config",
            data={
                "id": id,
                "version": version,
                "analyzers": analyzers,
                "malicious_detection_threshold": malicious_detection_threshold,
                "benign_detection_threshold": benign_detection_threshold,
                "audit_data_activity": audit_data_activity,
            },
            result_class=PangeaResponseResult,
        )

    async def create_service_config(
        self,
        *,
        id: str | None = None,
        version: str | None = None,
        analyzers: Mapping[str, bool] | None = None,
        malicious_detection_threshold: float | None = None,
        benign_detection_threshold: float | None = None,
        audit_data_activity: AuditDataActivityConfig | None = None,
    ) -> PangeaResponse[PangeaResponseResult]:
        """
        OperationId: prompt_guard_post_v1beta_config_create
        """
        return await self.request.post(
            "v1beta/config/create",
            data={
                "id": id,
                "version": version,
                "analyzers": analyzers,
                "malicious_detection_threshold": malicious_detection_threshold,
                "benign_detection_threshold": benign_detection_threshold,
                "audit_data_activity": audit_data_activity,
            },
            result_class=PangeaResponseResult,
        )

    async def update_service_config(
        self,
        *,
        id: str | None = None,
        version: str | None = None,
        analyzers: Mapping[str, bool] | None = None,
        malicious_detection_threshold: float | None = None,
        benign_detection_threshold: float | None = None,
        audit_data_activity: AuditDataActivityConfig | None = None,
    ) -> PangeaResponse[PangeaResponseResult]:
        """
        OperationId: prompt_guard_post_v1beta_config_update
        """
        return await self.request.post(
            "v1beta/config/update",
            data={
                "id": id,
                "version": version,
                "analyzers": analyzers,
                "malicious_detection_threshold": malicious_detection_threshold,
                "benign_detection_threshold": benign_detection_threshold,
                "audit_data_activity": audit_data_activity,
            },
            result_class=PangeaResponseResult,
        )

    async def delete_service_config(self, id: str) -> PangeaResponse[PangeaResponseResult]:
        """
        OperationId: prompt_guard_post_v1beta_config_delete
        """
        return await self.request.post("v1beta/config/delete", data={"id": id}, result_class=PangeaResponseResult)

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
        OperationId: prompt_guard_post_v1beta_config_list
        """
        return await self.request.post(
            "v1beta/config/list",
            data={"filter": filter, "last": last, "order": order, "order_by": order_by, "size": size},
            result_class=ServiceConfigsPage,
        )
