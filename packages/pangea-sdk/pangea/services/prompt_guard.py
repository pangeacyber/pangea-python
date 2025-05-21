from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Annotated, Literal, Optional

from pydantic import BaseModel, Field

from pangea.config import PangeaConfig
from pangea.response import APIRequestModel, APIResponseModel, PangeaDateTime, PangeaResponse, PangeaResponseResult
from pangea.services.base import ServiceBase

if TYPE_CHECKING:
    from collections.abc import Iterable


class Message(APIRequestModel):
    role: str
    content: str


class Classification(APIResponseModel):
    category: str
    """Classification category"""

    detected: bool
    """Classification detection result"""

    confidence: float
    """Confidence score for the classification"""


class GuardResult(PangeaResponseResult):
    detected: bool
    """Boolean response for if the prompt was considered malicious or not"""

    type: Optional[Literal["direct", "indirect", ""]] = None
    """Type of analysis, either direct or indirect"""

    analyzer: Optional[str] = None
    """Prompt Analyzers for identifying and rejecting properties of prompts"""

    confidence: float
    """Percent of confidence in the detection result, ranging from 0 to 1"""

    info: Optional[str] = None
    """Extra information about the detection result"""

    classifications: list[Classification]
    """List of classification results with labels and confidence scores"""


class Areas(BaseModel):
    malicious_prompt: Optional[bool] = None
    benign_prompt: Optional[bool] = None


class AuditDataActivityConfig(BaseModel):
    enabled: bool
    audit_service_config_id: str
    areas: Areas


class ServiceConfig(BaseModel):
    id: Optional[str] = None
    version: Optional[str] = None
    analyzers: Optional[dict[str, bool]] = None
    malicious_detection_threshold: Annotated[Optional[float], Field(ge=0.0, le=1.0)] = None
    benign_detection_threshold: Annotated[Optional[float], Field(ge=0.0, le=1.0)] = None
    audit_data_activity: Optional[AuditDataActivityConfig] = None


class ServiceConfigFilter(BaseModel):
    id: Optional[str] = None
    """
    Only records where id equals this value.
    """
    id__contains: Optional[list[str]] = None
    """
    Only records where id includes each substring.
    """
    id__in: Optional[list[str]] = None
    """
    Only records where id equals one of the provided substrings.
    """
    created_at: Optional[PangeaDateTime] = None
    """
    Only records where created_at equals this value.
    """
    created_at__gt: Optional[PangeaDateTime] = None
    """
    Only records where created_at is greater than this value.
    """
    created_at__gte: Optional[PangeaDateTime] = None
    """
    Only records where created_at is greater than or equal to this value.
    """
    created_at__lt: Optional[PangeaDateTime] = None
    """
    Only records where created_at is less than this value.
    """
    created_at__lte: Optional[PangeaDateTime] = None
    """
    Only records where created_at is less than or equal to this value.
    """
    updated_at: Optional[PangeaDateTime] = None
    """
    Only records where updated_at equals this value.
    """
    updated_at__gt: Optional[PangeaDateTime] = None
    """
    Only records where updated_at is greater than this value.
    """
    updated_at__gte: Optional[PangeaDateTime] = None
    """
    Only records where updated_at is greater than or equal to this value.
    """
    updated_at__lt: Optional[PangeaDateTime] = None
    """
    Only records where updated_at is less than this value.
    """
    updated_at__lte: Optional[PangeaDateTime] = None
    """
    Only records where updated_at is less than or equal to this value.
    """


class ServiceConfigsPage(PangeaResponseResult):
    count: Optional[int] = None
    """The total number of service configs matched by the list request."""
    last: Optional[str] = None
    """
    Used to fetch the next page of the current listing when provided in a
    repeated request's last parameter.
    """
    items: Optional[list[ServiceConfig]] = None


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

    def guard(
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
            from pangea.services.prompt_guard import Message

            response = prompt_guard.guard([Message(role="user", content="hello world")])
        """

        return self.request.post(
            "v1/guard",
            GuardResult,
            data={"messages": messages, "analyzers": analyzers, "classify": classify},
        )

    def get_service_config(
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
        return self.request.post(
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

    def create_service_config(
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
        return self.request.post(
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

    def update_service_config(
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
        return self.request.post(
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

    def delete_service_config(self, id: str) -> PangeaResponse[PangeaResponseResult]:
        """
        OperationId: prompt_guard_post_v1beta_config_delete
        """
        return self.request.post("v1beta/config/delete", data={"id": id}, result_class=PangeaResponseResult)

    def list_service_configs(
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
        return self.request.post(
            "v1beta/config/list",
            data={"filter": filter, "last": last, "order": order, "order_by": order_by, "size": size},
            result_class=ServiceConfigsPage,
        )
