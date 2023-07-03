# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation

from dataclasses import dataclass
from typing import Optional


@dataclass
class PangeaConfig:
    """Holds run time configuration information used by SDK components."""

    domain: str = "aws.us.pangea.cloud"
    environment: str = "production"

    config_id: Optional[str] = None

    """
    Set to true to use plain http

    """
    insecure: bool = False

    """
    Number of retries on the initial request

    """
    request_retries: int = 3

    """'
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
