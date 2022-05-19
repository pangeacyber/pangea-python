# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation

from .base import ServiceBase


class Locate(ServiceBase):
    service_name = "locate"
    version = "v1"

    def geolocate(self, ip: str):
        endpoint_name = "geolocate"

        data = {"ip": ip}

        response = self.request.post(endpoint_name, data=data)

        return response
