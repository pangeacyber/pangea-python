# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation

from typing import Optional

from pangea import __version__
from pangea.config import PangeaConfig
from pangea.request import PangeaRequest


class ServiceBase(object):
    service_name: str = "base"
    version: str = "v1"

    def __init__(self, token, config: Optional[PangeaConfig] = None):
        if not token:
            raise Exception("No token provided")

        self.config = config if config else PangeaConfig()

        self.request = PangeaRequest(
            self.config,
            token,
            self.version,
            self.service_name,
        )

        extra_headers = {
            "User-Agent": f"Pangea Python ${__version__}",
        }

        self.request.set_extra_headers(extra_headers)

    @property
    def token(self):
        return self.request.token

    @token.setter
    def token(self, value):
        self.request.token = value
