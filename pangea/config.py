# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation


class PangeaConfig(object):
    base_domain = "pangea.cloud"
    environment = "production"
    config_id = ""

    """
    Set to true to use plian http
    """
    insecure = False

    """
    Number of retries on the initial request
    """
    request_retries = 3

    """'
    Backoff strategy passed to 'requests'
    """
    request_backoff = 1

    """
    Timeout used on initial request attempts
    """
    request_timeout = 5

    """
    Enale asynchronous request support
    """
    async_enabled = True

    """
    Number of async retry attempts, with exponential
    backoff (4 -> 1 + 4 + 9 + 16  = 30 seconds of sleep)

    """
    async_retries = 4

    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)
