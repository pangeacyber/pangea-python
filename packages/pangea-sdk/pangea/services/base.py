# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation

import copy
import logging
from typing import Optional

from pangea.config import PangeaConfig
from pangea.request import PangeaRequest


class ServiceBase(object):
    service_name: str = "base"

    def __init__(self, token, config: Optional[PangeaConfig] = None, logger_name: str = "pangea"):
        if not token:
            raise Exception("No token provided")

        self.config = config if copy.deepcopy(config) else PangeaConfig()
        self.logger = logging.getLogger(logger_name)

        self.request = PangeaRequest(
            self.config,
            token,
            self.service_name,
            self.logger,
        )

        extra_headers = {}
        self.request.set_extra_headers(extra_headers)

    @property
    def token(self):
        return self.request.token

    @token.setter
    def token(self, value):
        self.request.token = value
