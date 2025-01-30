# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation

from dataclasses import dataclass
from typing import Literal, Optional


@dataclass
class PangeaConfig:
    """Holds run time configuration information used by SDK components."""

    domain: str = "aws.us.pangea.cloud"
    """
    Used to set Pangea domain (and port if needed), it should not include service subdomain
    just for particular use cases when environment = "local", domain could be set to an url including:
    scheme (http:// or https://), subdomain, domain and port.
    """

    environment: Literal["production", "local"] = "production"
    """
    Pangea environment, used to construct service URLs.

    If set to "local", then `domain` must be the full host (i.e., hostname and
    port) for the Pangea service that this `PangeaConfig` will be used for.
    """

    config_id: Optional[str] = None
    """
    Only used for services that support multiconfig (e.g.: Audit service)

    @deprecated("config_id will be deprecated from PangeaConfig. Set it on service initialization instead")
    """

    insecure: bool = False
    """
    Set to true to use plain http
    """

    request_retries: int = 3
    """
    Number of retries on the initial request
    """

    request_backoff: float = 0.5
    """
    Backoff strategy passed to 'requests'
    """

    request_timeout: int = 5
    """
    Timeout used on initial request attempts
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
