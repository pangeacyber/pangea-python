# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation

from pangea.request import PangeaRequest
from pangea.config import PangeaConfig


class ServiceBase(object):
    service_name = "base"
    version = "v1"
    service_config = None

    def __init__(self, token, config=None):
        if not token:
            raise Exception("No token provided")

        self.config = config if config else PangeaConfig()

        self.request = PangeaRequest(
            self.config,
            token,
            self.version,
            self.service_name,
        )

    @property
    def token(self):
        return self.request.token

    @token.setter
    def token(self, value):
        self.request.token = value
