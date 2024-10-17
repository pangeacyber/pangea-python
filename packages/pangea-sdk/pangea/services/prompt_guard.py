from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from pangea.response import APIRequestModel, PangeaResponse, PangeaResponseResult
from pangea.services.base import ServiceBase

if TYPE_CHECKING:
    from collections.abc import Iterable


class Message(APIRequestModel):
    role: str
    content: str


class GuardResult(PangeaResponseResult):
    prompt_injection_detected: bool
    prompt_injection_type: Optional[str] = None
    prompt_injection_detector: Optional[str] = None


class PromptGuard(ServiceBase):
    """Prompt Guard service client.

    Provides methods to interact with Pangea's Prompt Guard service.
    """

    service_name = "prompt-guard"

    def guard(self, messages: Iterable[Message]) -> PangeaResponse[GuardResult]:
        """
        Guard (Beta)

        Guard messages.

        How to install a [Beta release](https://pangea.cloud/docs/sdk/python/#beta-releases).

        OperationId: prompt_guard_post_v1_guard

        Args:
            messages: Messages.

        Examples:
            response = prompt_guard.guard([Message(role="user", content="hello world")])
        """

        return self.request.post("v1/guard", GuardResult, data={"messages": messages})
