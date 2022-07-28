# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation

from pangea.config import PangeaConfig
from pangea.request import PangeaRequest


class ServiceBase(object):
    service_name: str = "base"
    version: str = "v1"
    config_id_header: str = ""

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

        if self.config.config_id and self.config_id_header:
            self.request.set_extra_headers({self.config_id_header: self.config.config_id})

    @property
    def token(self):
        return self.request.token

    @token.setter
    def token(self, value):
        self.request.token = value
