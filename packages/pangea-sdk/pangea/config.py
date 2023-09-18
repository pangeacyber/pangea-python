# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation

from dataclasses import dataclass
from typing import Optional


@dataclass
class PangeaConfig:
    """Holds run time configuration information used by SDK components."""

    """
    Used to set pangea domain (and port if needed), it should not include service subdomain
    just for particular use cases when environment = "local", domain could be set to an url including:
    scheme (http:// or https://), subdomain, domain and port.

    """
    domain: str = "aws.us.pangea.cloud"

    """
    Used to generate service url.
    It should be only 'production' or 'local' in case of particular services that can run locally as Redact

    """
    environment: str = "production"

    """
    Only used for services that support multiconfig (e.g.: Audit service)

    @deprecated("config_id will be deprecated from PangeaConfig. Set it on service initialization instead")
    """
    config_id: Optional[str] = None

    """
    Set to true to use plain http

    """
    insecure: bool = False

    """
    Number of retries on the initial request

    """
    request_retries: int = 3

    """
    Backoff strategy passed to 'requests'

    """
    request_backoff: float = 0.5

    """
    Timeout used on initial request attempts

    """
    request_timeout: int = 5

    """
    Timeout used to poll results after 202 (in secs)

    """
    poll_result_timeout: int = 30

    """
    Enable queued request retry support
    """
    queued_retry_enabled: bool = True

    """
    Extra user agent to be added to request user agent

    """
    custom_user_agent: Optional[str] = None
