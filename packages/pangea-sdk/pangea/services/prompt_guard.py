from __future__ import annotations

from collections.abc import Iterable
from typing import Optional

from pangea.response import APIRequestModel, PangeaResponse, PangeaResponseResult
from pangea.services.base import ServiceBase


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
        return self.request.post("v1/guard", GuardResult, data={"messages": messages})
