# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation

from dataclasses import dataclass


@dataclass
class PangeaConfig:
    """Holds run time configuration information used by SDK components."""

    domain: str = "aws.us.pangea.cloud"
    environment: str = "production"

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
    request_backoff: int = 1

    """
    Timeout used on initial request attempts
    """
    request_timeout: int = 5

    """
    Enable queued request retry support
    """
    queued_retry_enabled: bool = True

    """
    Number of queued request retry attempts, with exponential
    backoff (4 -> 1 + 4 + 9 + 16  = 30 seconds of sleep)

    """
    queued_retries: int = 4
