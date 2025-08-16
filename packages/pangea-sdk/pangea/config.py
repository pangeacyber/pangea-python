# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation
from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, model_validator

__all__ = ("PangeaConfig",)


class PangeaConfig(BaseModel):
    """Holds run time configuration information used by SDK components."""

    base_url_template: str = "https://{SERVICE_NAME}.aws.us.pangea.cloud"
    """
    Template for constructing the base URL for API requests. The placeholder
    `{SERVICE_NAME}` will be replaced with the service name slug. This is a
    more powerful version of `domain` that allows for setting more than just
    the host of the API server. Defaults to
    `https://{SERVICE_NAME}.aws.us.pangea.cloud`.
    """

    domain: str = "aws.us.pangea.cloud"
    """
    Base domain for API requests. This is a weaker version of `base_url_template`
    that only allows for setting the host of the API server. Use
    `base_url_template` for more control over the URL, such as setting
    service-specific paths. Defaults to `aws.us.pangea.cloud`.
    """

    request_retries: int = 3
    """
    Number of retries on the initial request
    """

    request_backoff: float = 0.5
    """
    A backoff factor to apply between request attempts.
    """

    request_timeout: int = 5
    """
    Unused.
    """

    poll_result_timeout: int = 30
    """
    Timeout used to poll results after 202 (in secs)
    """

    queued_retry_enabled: bool = True
    """
    Enable queued request retry support
    """

    custom_user_agent: Optional[str] = None
    """
    Extra user agent to be added to request user agent
    """

    @model_validator(mode="before")
    @classmethod
    def _domain_backwards_compat(cls, data: Any) -> Any:
        if isinstance(data, dict) and "base_url_template" not in data and "domain" in data:
            return {**data, "base_url_template": f"https://{{SERVICE_NAME}}.{data['domain']}"}
        return data
