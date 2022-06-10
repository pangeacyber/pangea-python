# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation
from pangea.response import PangeaResponse
from .base import ServiceBase


class Embargo(ServiceBase):
    service_name = "embargo"
    version = "v1"

    def check_ip(self, ip: str) -> PangeaResponse:
        return self.request.post("check", data={"ip": ip})

    def check_isocode(self, iso_code: str) -> PangeaResponse:
        return self.request.post("check", data={"iso_code": iso_code})
